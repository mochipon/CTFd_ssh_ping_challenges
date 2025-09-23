from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Dict, Optional

from flask import request

from CTFd.exceptions.challenges import (
    ChallengeCreateException,
    ChallengeUpdateException,
)
from CTFd.models import Challenges, db
from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.challenges import (
    CHALLENGE_CLASSES,
    BaseChallenge,
    ChallengeResponse,
)
from CTFd.plugins.migrations import upgrade
from CTFd.utils.user import get_current_team, is_admin

try:
    from CTFd.plugins.CTFd_lab_pods import (
        get_team_pod_id as lab_get_pod_id,
        substitute_pod_tokens,
    )
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "ssh_ping_challenges requires the lab_pods plugin to be installed"
    ) from exc

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "The ssh_ping_challenges plugin requires the netmiko package: pip install netmiko"
    ) from exc

# Cisco IOS XE emits either "!!!!!"/".!!!!" progress indicators or a summary line.
PING_SUCCESS_PATTERN = re.compile(
    r"Success +rate +is +(\d+)\s*percent\s*\((\d+)/(\d+)\)",
    re.IGNORECASE,
)
PING_RTT_PATTERN = re.compile(
    r"min/avg/max\s*=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms",
    re.IGNORECASE,
)
DEFAULT_PING_COMMAND = "ping {target} repeat 1 timeout 2"
DEFAULT_TIMEOUT = 10

logger = logging.getLogger("plugins.ssh_ping_challenges")


@dataclass
class BastionConfig:
    host: str
    display_name: str
    username: str
    password: str
    enable_password: Optional[str]
    command: str


class SshPingChallengeModel(Challenges):
    __tablename__ = "ssh_ping_challenge"
    __mapper_args__ = {"polymorphic_identity": "ssh_ping"}

    id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"), primary_key=True
    )
    bastion_host_template = db.Column(db.Text, nullable=False, default="")
    bastion_username_template = db.Column(db.Text, nullable=False, default="")
    bastion_password_template = db.Column(db.Text, nullable=False, default="")
    bastion_enable_password_template = db.Column(db.Text, nullable=False, default="")
    bastion_display_name_template = db.Column(db.Text, nullable=False, default="")
    per_pod_bastion_overrides = db.Column(db.Text, nullable=False, default="")
    ping_command_template = db.Column(
        db.Text, nullable=False, default=DEFAULT_PING_COMMAND
    )
    ssh_timeout = db.Column(db.Integer, nullable=False, default=DEFAULT_TIMEOUT)

    @property
    def bastion_overrides(self) -> Dict[int, Dict[str, str]]:
        return _safe_load_overrides(self.per_pod_bastion_overrides)

    @property
    def pretty_bastion_overrides(self) -> str:
        mapping = self.bastion_overrides
        if not mapping:
            return ""
        serializable = {str(k): v for k, v in mapping.items()}
        return json.dumps(serializable, indent=2, sort_keys=True)

    @property
    def resolved_target(self) -> Optional[str]:
        return resolve_target_host(self)

    @property
    def resolved_bastion_name(self) -> Optional[str]:
        return resolve_bastion_display_name(self)


def resolve_target_host(challenge: Challenges) -> Optional[str]:
    pod_id = _resolve_pod_id()
    if pod_id is None:
        return None

    template = _get_pod_specific_template(challenge, pod_id)
    if not template:
        template = _get_target_template(challenge)
    if not template:
        return None
    return substitute_pod_tokens(template, pod_id)

def resolve_bastion_display_name(challenge: Challenges) -> Optional[str]:
    pod_id = _resolve_pod_id()
    if pod_id is None:
        return None

    overrides = challenge.bastion_overrides.get(pod_id, {})
    template = _normalize_field(
        overrides.get("display_name") or challenge.bastion_display_name_template
    )
    if not template:
        template = _normalize_field(challenge.bastion_host_template)
    if not template:
        return None
    return substitute_pod_tokens(template, pod_id)


def _resolve_pod_id() -> Optional[int]:
    team = get_current_team()
    pod_id = lab_get_pod_id(team) if team else None
    if pod_id is None and is_admin():
        override = request.args.get("pod_id")
        if override is None and request.form:
            override = request.form.get("pod_id")
        if override and str(override).isdigit():
            pod_id = int(override)
    return pod_id


def _get_default_flag(challenge: Challenges):
    for flag in challenge.flags:
        if flag.type == "static":
            return flag
    return None


def _get_target_template(challenge: Challenges) -> str:
    flag = _get_default_flag(challenge)
    if flag is None:
        return ""
    return (flag.content or "").strip()


def _get_pod_specific_template(challenge: Challenges, pod_id: int) -> Optional[str]:
    for flag in challenge.flags:
        print(f"!!! {flag.type} {flag.data} {flag.content}")
        if flag.type != "pod_specific":
            continue
        data = (flag.data or "").strip()
        if not data:
            continue
        try:
            expected = int(data)
        except ValueError:
            try:
                payload = json.loads(data)
                expected = int(payload.get("pod_id"))
            except (ValueError, TypeError, json.JSONDecodeError):
                continue
        if expected == pod_id:
            return (flag.content or "").strip()
    return None


def _safe_load_overrides(raw_text: Optional[str]) -> Dict[int, Dict[str, str]]:
    if not raw_text:
        return {}
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:  # pragma: no cover - admin error path
        logger.warning("Invalid JSON in per-pod bastion overrides: %s", exc)
        return {}
    if not isinstance(payload, dict):
        logger.warning("Per-pod bastion overrides must be a JSON object.")
        return {}

    mapping: Dict[int, Dict[str, str]] = {}
    for key, value in payload.items():
        try:
            pod_id = int(key)
        except (TypeError, ValueError):
            logger.warning("Ignoring override with non-integer key: %s", key)
            continue
        if not isinstance(value, dict):
            logger.warning("Ignoring override for pod %s: payload is not an object", key)
            continue
        sanitized: Dict[str, str] = {}
        for field in (
            "host",
            "username",
            "password",
            "enable_password",
            "command",
            "display_name",
        ):
            current = value.get(field)
            if current is None:
                continue
            if not isinstance(current, str):
                logger.warning(
                    "Ignoring non-string override for pod %s field %s", key, field
                )
                continue
            sanitized[field] = current
        mapping[pod_id] = sanitized
    return mapping


def _parse_bastion_overrides(
    raw_text: Optional[str], error_cls
) -> Dict[int, Dict[str, str]]:
    if not raw_text or not raw_text.strip():
        return {}
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise error_cls(
            f"Invalid JSON for per-pod bastion overrides: {exc.msg}"
        ) from exc
    if not isinstance(payload, dict):
        raise error_cls("Per-pod bastion overrides must be a JSON object.")

    mapping: Dict[int, Dict[str, str]] = {}
    for key, value in payload.items():
        try:
            pod_id = int(key)
        except (TypeError, ValueError):
            raise error_cls(f"Override key '{key}' is not a valid integer pod id.")
        if not isinstance(value, dict):
            raise error_cls(f"Override for pod {pod_id} must be a JSON object.")
        sanitized: Dict[str, str] = {}
        for field in (
            "host",
            "username",
            "password",
            "enable_password",
            "command",
            "display_name",
        ):
            current = value.get(field)
            if current is None:
                continue
            if not isinstance(current, str):
                raise error_cls(
                    f"Override field '{field}' for pod {pod_id} must be a string."
                )
            sanitized[field] = current
        mapping[pod_id] = sanitized
    return mapping


def _parse_timeout(value: Optional[str], error_cls) -> int:
    if value in (None, ""):
        return DEFAULT_TIMEOUT
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise error_cls("SSH timeout must be a positive integer.") from None
    if parsed <= 0:
        raise error_cls("SSH timeout must be a positive integer.")
    return parsed


def _normalize_field(text: Optional[str]) -> str:
    return (text or "").strip()


SUPPORTED_FLAG_TYPES = {"static", "pod_specific"}

def _clean_payload(
    data, error_cls, *, existing: Optional[SshPingChallengeModel] = None
):
    cleaned: Dict[str, object] = dict(data)

    raw_overrides = data.get("per_pod_bastion_overrides")
    if raw_overrides is None:
        cleaned["per_pod_bastion_overrides"] = (
            existing.per_pod_bastion_overrides if existing else ""
        )
    else:
        overrides = _parse_bastion_overrides(raw_overrides, error_cls)
        cleaned["per_pod_bastion_overrides"] = (
            json.dumps({str(k): v for k, v in sorted(overrides.items())}, sort_keys=True)
            if overrides
            else ""
        )

    timeout_raw = data.get("ssh_timeout")
    if timeout_raw is None:
        cleaned["ssh_timeout"] = (
            int(existing.ssh_timeout) if existing else DEFAULT_TIMEOUT
        )
    else:
        cleaned["ssh_timeout"] = _parse_timeout(timeout_raw, error_cls)

    def _resolved(field: str) -> str:
        value = data.get(field)
        if value is None:
            if existing is not None:
                return _normalize_field(getattr(existing, field))
            return ""
        return _normalize_field(value)

    for field in (
        "bastion_host_template",
        "bastion_username_template",
        "bastion_password_template",
        "bastion_enable_password_template",
        "bastion_display_name_template",
        "ping_command_template",
    ):
        cleaned[field] = _resolved(field)

    for field, label in (
        ("bastion_host_template", "Bastion host"),
        ("bastion_username_template", "Bastion username"),
        ("bastion_password_template", "Bastion password"),
    ):
        if not cleaned[field]:
            raise error_cls(f"{label} is required.")

    if not cleaned["ping_command_template"]:
        cleaned["ping_command_template"] = DEFAULT_PING_COMMAND

    return cleaned


def _apply_bastion_fields(
    challenge: SshPingChallengeModel, data: Dict[str, object]
) -> None:
    updated = False
    for field in (
        "bastion_host_template",
        "bastion_username_template",
        "bastion_password_template",
        "bastion_enable_password_template",
        "bastion_display_name_template",
        "per_pod_bastion_overrides",
        "ping_command_template",
        "ssh_timeout",
    ):
        if field in data:
            value = data[field]
            if getattr(challenge, field) != value:
                setattr(challenge, field, value)
                updated = True

    if updated:
        db.session.commit()


class SshPingChallengeType(BaseChallenge):
    id = "ssh_ping"
    name = "SSH Ping"
    templates = {
        "create": "/plugins/CTFd_ssh_ping_challenges/assets/create.html",
        "update": "/plugins/CTFd_ssh_ping_challenges/assets/update.html",
        "view": "/plugins/CTFd_ssh_ping_challenges/assets/view.html",
    }
    scripts = {
        "create": "/plugins/CTFd_ssh_ping_challenges/assets/create.js",
        "update": "/plugins/CTFd_ssh_ping_challenges/assets/update.js",
        "view": "/plugins/CTFd_ssh_ping_challenges/assets/view.js",
    }
    challenge_model = SshPingChallengeModel

    @classmethod
    def create(cls, request):
        data = request.form or request.get_json() or {}
        cleaned = _clean_payload(dict(data), ChallengeCreateException)

        class _Payload:
            form = cleaned

            @staticmethod
            def get_json():
                return cleaned

        challenge = super().create(_Payload)
        _apply_bastion_fields(challenge, cleaned)
        return challenge

    @classmethod
    def read(cls, challenge):
        data = super().read(challenge)
        data.update(
            {
                "bastion_host_template": challenge.bastion_host_template,
                "bastion_username_template": challenge.bastion_username_template,
                "bastion_password_template": challenge.bastion_password_template,
                "bastion_enable_password_template": challenge.bastion_enable_password_template,
                "bastion_display_name_template": challenge.bastion_display_name_template,
                "per_pod_bastion_overrides": challenge.pretty_bastion_overrides,
                "ping_command_template": challenge.ping_command_template,
                "ssh_timeout": challenge.ssh_timeout,
            }
        )
        return data

    @classmethod
    def update(cls, challenge, request):
        data = request.form or request.get_json() or {}
        cleaned = _clean_payload(
            dict(data), ChallengeUpdateException, existing=challenge
        )

        class _Payload:
            form = cleaned

            @staticmethod
            def get_json():
                return cleaned

        challenge = super().update(challenge, _Payload)
        _apply_bastion_fields(challenge, cleaned)
        return challenge

    @classmethod
    def attempt(cls, challenge, request):
        pod_id = _resolve_pod_id()
        if pod_id is None:
            message = "No pod is assigned to your team yet."
            if is_admin():
                message = "Pod ID is required. Use ?pod_id=<id> when previewing."
            return ChallengeResponse(status="incorrect", message=message)

        template = _get_pod_specific_template(challenge, pod_id)
        if not template:
            template = _get_target_template(challenge)
        target = substitute_pod_tokens(template, pod_id) if template else None
        if not target:
            message = "Target host is not configured for this challenge."
            if is_admin():
                message = "Static flag content must define the target host."
            return ChallengeResponse(status="incorrect", message=message)

        try:
            bastion_config = resolve_bastion_config(challenge, pod_id, target)
        except ValueError as exc:
            message = "Bastion configuration is incomplete for your pod."
            if is_admin():
                message = f"Pod {pod_id}: {exc}"
            return ChallengeResponse(status="incorrect", message=message)

        try:
            output = execute_ping(bastion_config, challenge.ssh_timeout)
        except NetmikoAuthenticationException:
            return ChallengeResponse(
                status="incorrect",
                message="Authentication to the bastion failed.",
            )
        except NetmikoTimeoutException:
            return ChallengeResponse(
                status="incorrect",
                message="Unable to reach the bastion host.",
            )
        except Exception as exc:  # pragma: no cover - defensive path
            logger.exception("Unexpected error executing SSH ping: pod=%s", pod_id)
            message = "Unexpected error while contacting the bastion."
            if is_admin():
                message = f"Unexpected error: {exc}"
            return ChallengeResponse(status="incorrect", message=message)

        success, latency, explanation = interpret_ping_output(output)
        if success:
            detail = f" ({latency} ms avg)" if latency is not None else ""
            return ChallengeResponse(
                status="correct",
                message=f"Host reachable from {bastion_config.display_name}{detail}",
            )
        return ChallengeResponse(status="incorrect", message=explanation)


def resolve_bastion_config(
    challenge: SshPingChallengeModel, pod_id: int, target: str
) -> BastionConfig:
    """Resolve the bastion login details and ping command for *pod_id*.

    The returned configuration is fully substituted (both pod tokens and the
    target placeholder have been expanded) and ready for consumption by
    Netmiko.
    """
    defaults = {
        "host": challenge.bastion_host_template,
        "username": challenge.bastion_username_template,
        "password": challenge.bastion_password_template,
        "enable_password": challenge.bastion_enable_password_template,
        "display_name": challenge.bastion_display_name_template,
        "command": challenge.ping_command_template or DEFAULT_PING_COMMAND,
    }
    overrides = challenge.bastion_overrides.get(pod_id, {})

    host = _normalize_field(overrides.get("host") or defaults.get("host"))
    username = _normalize_field(
        overrides.get("username") or defaults.get("username")
    )
    password = _normalize_field(
        overrides.get("password") or defaults.get("password")
    )
    enable = _normalize_field(
        overrides.get("enable_password") or defaults.get("enable_password")
    )

    host = substitute_pod_tokens(host, pod_id)
    username = substitute_pod_tokens(username, pod_id)
    password = substitute_pod_tokens(password, pod_id)
    enable = substitute_pod_tokens(enable, pod_id) if enable else ""

    display_name = _normalize_field(
        overrides.get("display_name") or defaults.get("display_name")
    )
    display_name = substitute_pod_tokens(display_name, pod_id) if display_name else ""

    if not host or not username or not password:
        logger.warning(
            "Incomplete bastion configuration for pod %s (host=%s username=%s)",
            pod_id,
            bool(host),
            bool(username),
        )
        raise ValueError(
            "Bastion host, username, and password must all be provided."
        )

    command_template = (
        overrides.get("command")
        or defaults.get("command")
        or DEFAULT_PING_COMMAND
    )
    command_template = substitute_pod_tokens(command_template, pod_id)
    try:
        command = command_template.format(target=target)
    except KeyError as exc:
        logger.error("Ping command template uses unknown placeholder %s", exc)
        raise ValueError(f"Ping command template uses unknown placeholder {exc}.")

    return BastionConfig(
        host=host,
        display_name=display_name or host,
        username=username,
        password=password,
        enable_password=enable or None,
        command=command,
    )


def execute_ping(config: BastionConfig, timeout: int) -> str:
    """Execute the configured ping command via Netmiko."""

    device_params = {
        "device_type": "cisco_xe",
        "host": config.host,
        "username": config.username,
        "password": config.password,
        "fast_cli": False,
        "conn_timeout": timeout,
    }
    logger.debug(
        "Connecting to bastion %s as %s (timeout=%s)",
        config.host,
        config.username,
        timeout,
    )
    connection = ConnectHandler(**device_params)
    try:
        if config.enable_password:
            connection.secret = config.enable_password
            connection.enable()
        logger.debug("Executing ping command on %s: %s", config.host, config.command)
        output = connection.send_command(
            config.command,
            expect_string=r"[>#]",
            read_timeout=timeout,
            strip_prompt=False,
            strip_command=False,
        )
    finally:
        connection.disconnect()
    logger.debug("Ping output from %s:\n%s", config.host, output)
    return output


def interpret_ping_output(output: str) -> (bool, Optional[float], str):
    """Determine whether the ping succeeded and extract latency if present."""

    match = PING_SUCCESS_PATTERN.search(output)
    if match:
        percent = int(match.group(1))
        received = int(match.group(2))
        sent = int(match.group(3))
        if percent > 0 and received > 0:
            latency = None
            rtt = PING_RTT_PATTERN.search(output)
            if rtt:
                try:
                    latency = float(rtt.group(2))
                except ValueError:
                    latency = None
            return True, latency, "Host reachable"
        explanation = (
            f"Ping failed ({received}/{sent} replies)."
            if sent
            else "Ping failed (no packets sent)."
        )
        return False, None, explanation

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in lines:
        if set(line) <= {"!", "."} and "!" in line:
            return True, None, "Host reachable"

    if "Success rate is 100 percent" in output:
        return True, None, "Host reachable"

    if "% Unrecognized command" in output or "Invalid input" in output:
        return False, None, "Ping command was not accepted by the bastion."

    trimmed = output.strip() or "Ping failed"
    return False, None, trimmed.splitlines()[-1]


def load(app):
    """Register the SSH ping challenge type and expose static assets."""
    upgrade()
    CHALLENGE_CLASSES[SshPingChallengeType.id] = SshPingChallengeType
    register_plugin_assets_directory(
        app, base_path="/plugins/CTFd_ssh_ping_challenges/assets/"
    )
