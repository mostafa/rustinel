# Rustinel Documentation

Rustinel is a cross-platform endpoint detection and response agent for **Windows** and **Linux**. Windows builds collect telemetry from **ETW**. Linux builds load **eBPF** programs. Both paths feed a shared userspace pipeline that normalizes events, evaluates **Sigma**, **YARA**, and **IOC** detections, and writes **ECS 9.3.0 NDJSON** alerts.

## At A Glance

| Area | Summary |
| --- | --- |
| Sensors | Windows ETW and Linux eBPF |
| Detection | Sigma, YARA, IOC |
| Output | Operational logs plus ECS NDJSON alerts |
| Response | Optional process termination on matching alerts |
| Reloads | Hot reload for Sigma, YARA, and IOC files |
| Status | 1.0.0 official release with Windows and Linux support; Windows telemetry remains broader than Linux |

## Choose Your Path

### I want to run Rustinel

- [Getting Started](getting-started.md): first run, demo rules, validation steps
- [Configuration](configuration.md): config file layout, environment variables, production-safe paths
- [CLI Reference](cli.md): commands, flags, and platform-specific behavior

### I want to deploy or operate it

- [Operations and Upgrade Guide](operations.md): install layout, service behavior, upgrade workflows
- [Troubleshooting](troubleshooting.md): startup failures, missing alerts, reload issues, queue pressure
- [Output Format](output.md): log files, alert fields, and SIEM shipping
- [Active Response](active-response.md): dry-run, prevention mode, allowlists, safety checks
- [FAQ](faq.md): common operator and deployment questions

### I want to understand detections

- [Detection](detection.md): Sigma, YARA, IOC runtime behavior and current coverage
- [Architecture](architecture.md): data plane, control plane, handlers, caches, and workers

### I want to work on the codebase

- [Development](development.md): build and contributor workflow
- [Roadmap](roadmap.md): planned direction and remaining gaps

## Documentation Map

| Page | Best for | What it covers |
| --- | --- | --- |
| [Getting Started](getting-started.md) | First-time users | Build, run, validate alerts |
| [Configuration](configuration.md) | Operators | `config.toml`, `EDR__...`, allowlists, reloads |
| [CLI Reference](cli.md) | Operators | `run`, `service`, `--log-level`, Linux eBPF override |
| [Operations and Upgrade Guide](operations.md) | Operators | Install layout, Windows service lifecycle, Linux supervisor patterns |
| [Troubleshooting](troubleshooting.md) | Operators | Startup failures, no-alert situations, reload issues, and queue backpressure |
| [Detection](detection.md) | Detection engineers | Sigma logsource support, YARA flow, IOC matching behavior |
| [Output Format](output.md) | SIEM / DFIR users | Operational log shape, ECS NDJSON alerts, key fields |
| [Active Response](active-response.md) | Operators | Severity thresholds, allowlists, dry-run and prevention behavior |
| [FAQ](faq.md) | Operators and evaluators | Practical answers for deployment, paths, alerts, and platform gaps |
| [Architecture](architecture.md) | Engineers | Sensors, router, normalizer, detector store, workers |
| [Development](development.md) | Contributors | Local dev workflow and repo expectations |
| [Roadmap](roadmap.md) | Maintainers | Planned capabilities and future scope |

## Platform Snapshot

| Platform | Sensor | Current telemetry surface | Runtime model |
| --- | --- | --- | --- |
| Windows | ETW | Process, image load, network, file, registry, DNS, PowerShell, WMI, service, task | Foreground console run or built-in Windows service commands |
| Linux | eBPF | Process, network, file, DNS | Foreground binary under root or your supervisor of choice |

## What Rustinel Actually Does

1. Collects raw events from ETW or eBPF.
2. Normalizes those events into a shared Sysmon-style model.
3. Evaluates Sigma and inline IOC indicators on normalized events.
4. Queues YARA scans and IOC hashing from process-start events.
5. Writes detections as ECS NDJSON alerts.
6. Optionally applies active response based on severity and allowlists.

## Recommended Reading Order

### For Operators

1. [Getting Started](getting-started.md)
2. [Configuration](configuration.md)
3. [Operations and Upgrade Guide](operations.md)
4. [Troubleshooting](troubleshooting.md)
5. [Output Format](output.md)
6. [Active Response](active-response.md)
7. [FAQ](faq.md)

### For Detection Engineers

1. [Detection](detection.md)
2. [Output Format](output.md)
3. [Architecture](architecture.md)

### For Contributors

1. [Architecture](architecture.md)
2. [Development](development.md)
3. [Roadmap](roadmap.md)

## Minimum Requirements

### Runtime

- Windows: Windows 10/11 or Server 2016+, Administrator privileges
- Linux: kernel 5.8+, BTF enabled, root or equivalent eBPF capabilities

### Build From Source

- Rust 1.92+
- Windows: Visual Studio Build Tools
- Linux: if `ebpf/rustinel-ebpf.o` is not already present, the first build also needs nightly Rust, `rust-src`, and `bpf-linker`

## Quick Validation

### Windows

```powershell
.\rustinel.exe run --console
whoami /all
```

### Linux

```bash
sudo ./rustinel run
whoami
```

In both cases, confirm that:

- `logs/rustinel.log.<date>` contains startup messages
- `logs/alerts.json.<date>` contains the alert from the bundled `whoami` Sigma rule

## Operational Notes

- Relative paths in `config.toml` resolve from the current working directory.
- Windows services often start in `C:\Windows\System32`, so production deployments should use absolute paths.
- Linux does not ship built-in service-management commands; use `systemd` or another supervisor for background execution.
- Trusted path allowlists are shared by default across active response, YARA exclusions, and IOC hash exclusions.
