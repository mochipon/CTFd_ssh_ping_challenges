# SSH Ping Challenges Plugin

A CTFd plugin that enables network reachability verification through Cisco IOS XE bastions using ping commands. This plugin is designed for lab environments where direct network access to target hosts is not available and requires jumping through network devices.

## Overview

The SSH Ping challenge type provides automated network connectivity testing by:

1. **Target Resolution**: Determines the destination host using the challenge's flag content, supporting `:pod_id:` tokens for per-team customization
2. **Bastion Connection**: Establishes SSH connections to configured Cisco IOS XE devices using team-specific credentials
3. **Ping Execution**: Executes non-interactive `ping` commands and parses IOS XE output for success indicators
4. **Result Reporting**: Provides detailed feedback including latency measurements when available

Challenges are marked as solved when the ping receives at least one response, with reported round-trip times displayed to competitors.

## Features

- **Pod-based Configuration**: Full support for per-pod bastion hosts, credentials, and commands
- **Flexible Authentication**: Supports both regular and privileged (enable) mode access
- **Template System**: Rich templating with `:pod_id:` substitution for scalable deployments
- **Internationalization**: Multi-language support (English, Japanese) with extensible translation system

## Dependencies

### Required Packages
- `netmiko` - SSH connection management for network devices

### Required Plugins
- [`CTFd_lab_pods`](https://github.com/mochipon/CTFd_lab_pods) - Pod assignment and token substitution
- [`CTFd_pod_specific_challenges`](https://github.com/mochipon/CTFd_pod_specific_challenges) *(optional)* - Enhanced flag management

### Installation

1. Clone this repository into your CTFd plugins directory:
```bash
cd /path/to/CTFd/CTFd/plugins
git clone https://github.com/mochipon/TFd_ssh_ping_challenges.git
```

2. Rebuild your docker image:
```bash
cd /path/to/CTFd/
docker compose build
```

3. Restart your CTFd instance to load the plugin

## Configuration

### Basic Setup

1. **Create Challenge**: Select "SSH Ping" as the challenge type
2. **Configure Bastion**: Set host, username, password, and optional enable password templates
3. **Set Target**: Define the target host in the static flag content (e.g., `192.0.2.:pod_id:.10`)
4. **Customize Command**: Optionally modify the ping command template

### Template Variables

Templates support `:pod_id:` substitution, which is replaced with each team's assigned pod number:

- `10.0.:pod_id:.254` → `10.0.5.254` (for pod 5)
- `team:pod_id:` → `team5` (for pod 5)
- `pod-:pod_id:-router` → `pod-5-router` (for pod 5)

### Advanced Configuration

#### Custom Ping Commands
The default command is `ping {target} repeat 1 timeout 2`. The `{target}` placeholder is automatically replaced with the resolved target host.

Examples:
- `ping {target} repeat 3 timeout 10` - More thorough testing
- `ping vrf MGMT {target} repeat 1` - VRF-specific routing
- `ping {target} source loopback0` - Source from specific interface

#### Timeout Settings
Configure SSH connection and command execution timeouts (default: 10 seconds) to match your network environment.

## Pod-Specific Flags

When using the `CTFd_pod_specific_challenges` plugin, you can define different targets for different pods:

1. **Static Flag**: Default target template (e.g., `192.0.2.:pod_id:.10`)
2. **Pod-Specific Flags**: Override targets for specific pods
   - Flag Type: `pod_specific`
   - Flag Data: Pod ID (e.g., `3`)
   - Flag Content: Target host (e.g., `203.0.113.50`)

Pod-specific flags take precedence over static flag templates.

## License

This project is licensed under the Apache License Version 2 License - see the [LICENSE](LICENSE) file for details.

## Compatibility

- **CTFd Version**: 3.0+
- **Python Version**: 3.11+
