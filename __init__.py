"""SSH Ping Challenges Plugin for CTFd.

This plugin enables CTFd to verify network reachability through Cisco IOS XE
bastions via SSH-based ping commands, supporting pod-specific configurations.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flask.wrappers import Request

from flask import has_request_context, request
from werkzeug.datastructures import MultiDict

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
from CTFd.utils.config.pages import build_markdown
from CTFd.utils.helpers import markup
from CTFd.utils.user import get_current_team, is_admin

try:
    from CTFd.plugins.CTFd_lab_pods import (
        get_team_pod_id,
        substitute_pod_tokens,
    )
except ImportError as exc:  # pragma: no cover
    error_msg = "ssh_ping_challenges requires the lab_pods plugin to be installed"
    raise RuntimeError(error_msg) from exc

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )
except ImportError as exc:  # pragma: no cover
    error_msg = "The ssh_ping_challenges plugin requires the netmiko package"
    raise RuntimeError(error_msg) from exc

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
    """SSH bastion configuration."""

    host: str
    display_name: str
    username: str
    password: str
    enable_password: str | None
    command: str


class SshPingChallengeModel(Challenges):
    """Database model for SSH Ping challenges."""

    __tablename__ = "ssh_ping_challenge"
    __mapper_args__ = {"polymorphic_identity": "ssh_ping"}

    id = db.Column(
        db.Integer,
        db.ForeignKey("challenges.id", ondelete="CASCADE"),
        primary_key=True,
    )
    bastion_host_template = db.Column(db.Text, nullable=False, default="")
    bastion_username_template = db.Column(db.Text, nullable=False, default="")
    bastion_password_template = db.Column(db.Text, nullable=False, default="")
    bastion_enable_password_template = db.Column(db.Text, nullable=False, default="")
    bastion_display_name_template = db.Column(db.Text, nullable=False, default="")
    ping_command_template = db.Column(db.Text, nullable=True)
    ssh_timeout = db.Column(db.Integer, nullable=True)

    @property
    def resolved_target(self) -> str | None:
        """Get resolved target host for current pod."""
        return resolve_target_host(self)

    @property
    def resolved_bastion_name(self) -> str | None:
        """Get resolved bastion name for current pod."""
        pod_id = _resolve_pod_id()
        target = self.resolved_target
        if pod_id is None or target is None:
            return None
        try:
            config = resolve_bastion_config(self, pod_id, target)
        except ValueError:
            return None
        else:
            return config.display_name

    @property
    def resolved_bastion_command(self) -> str | None:
        """Get resolved bastion command for current pod."""
        pod_id = _resolve_pod_id()
        target = self.resolved_target
        if pod_id is None or target is None:
            return None
        try:
            config = resolve_bastion_config(self, pod_id, target)
        except ValueError:
            return None
        else:
            return config.command

    @property
    def html(self) -> str:
        """Get HTML description with pod token substitution."""
        description = self.description or ""
        pod_id = _resolve_pod_id()
        if pod_id is not None:
            description = substitute_pod_tokens(description, pod_id)
        return markup(build_markdown(description))


def resolve_target_host(challenge: Challenges) -> str | None:
    """Resolve the target host for the current pod.

    Args:
        challenge: The challenge instance containing target templates.

    Returns:
        The resolved target hostname/IP, or None if unable to resolve.

    """
    pod_id = _resolve_pod_id()
    if pod_id is None:
        return None

    template = _get_pod_specific_template(challenge, pod_id)
    if not template:
        template = _get_target_template(challenge)
    if not template:
        return None
    return substitute_pod_tokens(template, pod_id)


def _resolve_pod_id() -> int | None:
    """Get the pod ID for the current team or admin override."""
    if not has_request_context():
        return None

    team = get_current_team()
    if team:
        return get_team_pod_id(team)

    # Admin override for previewing
    if is_admin():
        override = request.args.get("pod_id") or request.form.get("pod_id")
        if override and override.isdigit():
            return int(override)

    return None


def _get_default_flag(challenge: Challenges) -> object | None:
    """Get the first static flag from challenge."""
    for flag in challenge.flags:
        if flag.type == "static":
            return flag
    return None


def _get_target_template(challenge: Challenges) -> str:
    """Get target template from default flag."""
    flag = _get_default_flag(challenge)
    if flag is None:
        return ""
    return (flag.content or "").strip()


def _get_pod_specific_template(challenge: Challenges, pod_id: int) -> str | None:
    """Get pod-specific target template from flags.

    Args:
        challenge: The challenge instance to search.
        pod_id: The pod ID to match against.

    Returns:
        The target template for the specified pod, or None if not found.

    """
    for flag in challenge.flags:
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


class SshPingChallengeType(BaseChallenge):
    """SSH Ping challenge type for CTFd."""

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

    @staticmethod
    def _preprocess_empty_strings(request: Request) -> Request:
        """Remove empty strings from nullable fields before database operations."""
        nullable_fields = ["ssh_timeout", "ping_command_template"]

        if hasattr(request, "form") and request.form:
            new_form = MultiDict(request.form)
            for field in nullable_fields:
                if field in new_form and new_form[field] == "":
                    new_form[field] = None
            request.form = new_form
        elif request.is_json and request.json:
            json_data = request.get_json()
            for field in nullable_fields:
                if field in json_data and json_data[field] == "":
                    json_data[field] = None
            # Replace the cached JSON by setting a new attribute
            # This is a workaround for Flask's request object immutability
            request._cached_json = (json_data, True)
        return request

    @classmethod
    def create(cls, request: Request) -> SshPingChallengeModel:
        """Create a new SSH ping challenge."""
        data = request.form or request.get_json() or {}

        # Validate required fields
        required_fields = [
            "bastion_host_template",
            "bastion_username_template",
            "bastion_password_template",
        ]
        for field in required_fields:
            if not (data.get(field) or "").strip():
                field_name = field.replace("_", " ").title()
                error_msg = f"{field_name} is required."
                raise ChallengeCreateException(error_msg)

        # Validate ssh_timeout if provided
        if "ssh_timeout" in data and data["ssh_timeout"] not in (None, ""):
            try:
                timeout = int(data["ssh_timeout"])
                if timeout <= 0:
                    error_msg = "SSH timeout must be a positive integer."
                    raise ChallengeCreateException(error_msg)
            except (TypeError, ValueError):
                error_msg = "SSH timeout must be a positive integer."
                raise ChallengeCreateException(error_msg) from None

        # Remove empty strings from nullable fields before super() call
        if request.method == "POST":
            request = cls._preprocess_empty_strings(request)

        # Create challenge using parent class
        challenge = super().create(request)
        return challenge

    @classmethod
    def read(cls, challenge: SshPingChallengeModel) -> dict[str, Any]:
        """Read challenge data for API responses.

        Args:
            challenge: The challenge instance to serialize.

        Returns:
            Dictionary containing challenge data.

        """
        data = super().read(challenge)
        data.update(
            {
                "bastion_host_template": challenge.bastion_host_template,
                "bastion_username_template": challenge.bastion_username_template,
                "bastion_password_template": challenge.bastion_password_template,
                "bastion_enable_password_template": (
                    challenge.bastion_enable_password_template
                ),
                "bastion_display_name_template": (
                    challenge.bastion_display_name_template
                ),
                "ping_command_template": challenge.ping_command_template,
                "ssh_timeout": challenge.ssh_timeout,
            },
        )
        return data

    @classmethod
    def update(
        cls,
        challenge: SshPingChallengeModel,
        request: Request,
    ) -> SshPingChallengeModel:
        """Update an existing SSH ping challenge."""
        data = request.form or request.get_json() or {}

        # Validate ssh_timeout if provided
        if "ssh_timeout" in data and data["ssh_timeout"] not in (None, ""):
            try:
                timeout = int(data["ssh_timeout"])
                if timeout <= 0:
                    error_msg = "SSH timeout must be a positive integer."
                    raise ChallengeUpdateException(error_msg)
            except (TypeError, ValueError):
                error_msg = "SSH timeout must be a positive integer."
                raise ChallengeUpdateException(error_msg) from None

        # Remove empty strings from nullable fields before super() call
        request = cls._preprocess_empty_strings(request)

        # Update challenge using parent class
        challenge = super().update(challenge, request)
        return challenge

    @classmethod
    def attempt(cls, challenge: SshPingChallengeModel, _: object) -> ChallengeResponse:
        """Attempt to solve the SSH ping challenge."""
        pod_id = _resolve_pod_id()
        if pod_id is None:
            message = "No pod is assigned to your team yet."
            if is_admin():
                message = "Pod ID is required. Use ?pod_id=<id> when previewing."
            return ChallengeResponse(status="incorrect", message=message)

        # Get target host
        template = _get_pod_specific_template(challenge, pod_id)
        if not template:
            template = _get_target_template(challenge)
        target = substitute_pod_tokens(template, pod_id) if template else None

        if not target:
            message = "Target host is not configured for this challenge."
            if is_admin():
                message = "Static flag content must define the target host."
            return ChallengeResponse(status="incorrect", message=message)

        # Configure bastion
        try:
            bastion_config = resolve_bastion_config(challenge, pod_id, target)
        except ValueError as exc:
            message = "Bastion configuration is incomplete for your pod."
            if is_admin():
                message = f"Pod {pod_id}: {exc}"
            return ChallengeResponse(status="incorrect", message=message)

        # Execute ping
        timeout = challenge.ssh_timeout or DEFAULT_TIMEOUT
        try:
            output = execute_ping(bastion_config, timeout)
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
        except Exception as exc:
            logger.exception("Unexpected error executing SSH ping")
            message = "Unexpected error while contacting the bastion."
            if is_admin():
                message = f"Unexpected error: {exc}"
            return ChallengeResponse(status="incorrect", message=message)

        # Interpret results
        success, latency, explanation = interpret_ping_output(output)
        if success:
            detail = f" ({latency} ms avg)" if latency is not None else ""
            return ChallengeResponse(
                status="correct",
                message=f"Host reachable from {bastion_config.display_name}{detail}",
            )
        return ChallengeResponse(status="incorrect", message=explanation)


def resolve_bastion_config(
    challenge: SshPingChallengeModel,
    pod_id: int,
    target: str,
) -> BastionConfig:
    """Resolve the bastion login details and ping command for pod_id."""
    host = (challenge.bastion_host_template or "").strip()
    username = (challenge.bastion_username_template or "").strip()
    password = (challenge.bastion_password_template or "").strip()
    enable = (challenge.bastion_enable_password_template or "").strip()
    display_name = (challenge.bastion_display_name_template or "").strip()

    host = substitute_pod_tokens(host, pod_id)
    username = substitute_pod_tokens(username, pod_id)
    password = substitute_pod_tokens(password, pod_id)
    enable = substitute_pod_tokens(enable, pod_id) if enable else ""
    display_name = substitute_pod_tokens(display_name, pod_id) if display_name else ""

    if not host or not username or not password:
        logger.warning(
            "Incomplete bastion configuration for pod %s (host=%s username=%s)",
            pod_id,
            bool(host),
            bool(username),
        )
        error_msg = "Bastion host, username, and password must all be provided."
        raise ValueError(error_msg)

    command_template = challenge.ping_command_template or DEFAULT_PING_COMMAND
    command_template = substitute_pod_tokens(command_template, pod_id)
    try:
        command = command_template.format(target=target)
    except KeyError as exc:
        logger.exception("Ping command template uses unknown placeholder")
        error_msg = f"Ping command template uses unknown placeholder {exc}."
        raise ValueError(error_msg) from exc

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


def interpret_ping_output(output: str) -> tuple[bool, float | None, str]:
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


def load(app: object) -> None:
    """Register the SSH ping challenge type and expose static assets."""
    upgrade()
    CHALLENGE_CLASSES[SshPingChallengeType.id] = SshPingChallengeType
    register_plugin_assets_directory(
        app,
        base_path="/plugins/CTFd_ssh_ping_challenges/assets/",
    )

    # Add default values to template context
    app.jinja_env.globals["SSH_PING_DEFAULT_COMMAND"] = DEFAULT_PING_COMMAND
    app.jinja_env.globals["SSH_PING_DEFAULT_TIMEOUT"] = DEFAULT_TIMEOUT
