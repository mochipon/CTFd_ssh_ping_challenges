# SSH Ping Challenges Plugin

The SSH Ping challenge type allows CTFd to verify isolated lab environments even
when network reachability requires jumping through a Cisco IOS XE bastion. For
teams assigned to a pod (via the `CTFd_lab_pods` plugin) the challenge will:

1. Resolve the destination host using the challenge's static flag. The flag may
   include `:pod_id:` tokens for per-pod customization.
2. Build an SSH connection to the configured bastion (also supporting
   `:pod_id:` tokens and optional per-pod overrides defined as JSON).
3. Issue a non-interactive `ping` command from the bastion and parse the success
   rate reported by IOS XE.

If at least one response is received the attempt is marked correct and the
reported latency (when available) is echoed back to the competitor.

## Dependencies

- Python package: `netmiko` to manage SSH sessions to IOS XE devices.
- Plugins: [`CTFd_lab_pods`](https://github.com/mochipon/CTFd_lab_pods) (for pod resolution) and optionally
  [`CTFd_pod_specific_challenges`](https://github.com/mochipon/CTFd_pod_specific_challenges) for consistent flag management.
- Using the official CTFd Docker image? Clone this repository into the
  container's `plugins/` directory and rebuild the image—the build process will
  install `netmiko` and any other dependencies for you automatically.

## Installation

Clone this repo into your `CTFd/plugins/` directory then start/restart your CTFd instance.

```bash
git clone https://github.com/mochipon/CTFd_ssh_ping_challenges.git
```

## Notes

- Provide a static flag that defines the default target template
  (e.g. `192.0.2.:pod_id:.10`). You may also attach pod specific flags from the
  companion plugin—when present, the flag matching the team's pod id takes
  priority over the static template. If neither flag produces a target, the
  attempt is rejected with a helpful error.

- Authentication failures, timeouts, or command parsing errors are surfaced to
  competitors in a generic form, while administrators receive additional detail
  to assist with debugging.
- Bastion credentials (including passwords) are stored in plain text so that
  the worker container can establish SSH sessions. In the typical CTF or lab
  deployment model this is acceptable, but review your threat model before
  reusing the plugin elsewhere.
