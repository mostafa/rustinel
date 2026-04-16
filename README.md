# Rustinel
**Open-source endpoint detection for Windows and Linux**

<p align="center">
  <a href="https://karib0u.github.io/rustinel/"><img src="https://img.shields.io/badge/docs-available-brightgreen" alt="Docs"></a>
  <img src="https://img.shields.io/badge/platform-Windows%20ETW-blue?logo=windows" alt="Platform Windows ETW">
  <img src="https://img.shields.io/badge/platform-Linux%20eBPF-orange?logo=linux" alt="Platform Linux eBPF">
  <img src="https://img.shields.io/badge/language-Rust-orange?logo=rust" alt="Language Rust">
  <img src="https://img.shields.io/badge/license-Apache%202.0-green" alt="License">
  <img src="https://img.shields.io/badge/status-Official%20Release%201.0-success" alt="Status">
</p>

Rustinel gives blue teams a simple, transparent way to collect host telemetry and run rule-based detections across **Windows** and **Linux**.

It uses **ETW** on Windows and **eBPF** on Linux, normalizes events into a shared model, evaluates **Sigma**, **YARA**, and **IOC** detections, writes **ECS NDJSON** alerts, and can optionally terminate malicious processes.

Version **1.0.0** is the first official Rustinel release, with supported Windows ETW and Linux eBPF collectors.

<p align="center">
  <img src="docs/images/demo.gif" alt="Rustinel Demo" width="900">
</p>

## Why Rustinel

- Native telemetry sources: ETW on Windows, eBPF on Linux
- One shared detection pipeline across both platforms
- Sigma, YARA, and IOC matching in one agent
- Hot reload for rules and indicator files
- ECS NDJSON alerts that fit easily into SIEM pipelines
- Optional active response with dry-run and allowlists

## How It Works

1. Rustinel collects raw host telemetry from ETW or eBPF.
2. It normalizes that data into a shared event model.
3. It evaluates Sigma, YARA, and IOC detections.
4. It writes alerts to disk and can optionally apply response actions.

## Platform Support

| Platform | Sensor | Current coverage | Runtime model |
| --- | --- | --- | --- |
| Windows 10/11, Server 2016+ | ETW | Process, image load, network, file, registry, DNS, PowerShell, WMI, service, task | Foreground run or built-in Windows service commands |
| Linux 5.8+ with BTF | eBPF | Process, network, file, DNS | Foreground run under root or your supervisor of choice |

## Quick Start

Download the release package for your platform from [GitHub Releases](https://github.com/Karib0u/rustinel/releases) and extract it.

### Windows

Download `rustinel-<version>-x86_64-pc-windows-msvc.zip`, extract it, then run:

```powershell
cd .\rustinel-<version>-x86_64-pc-windows-msvc
.\rustinel.exe run --console
whoami /all
```

### Linux

Choose the archive that matches your architecture:

- `rustinel-<version>-x86_64-unknown-linux-musl.tar.gz`
- `rustinel-<version>-aarch64-unknown-linux-musl.tar.gz`

Then extract and run:

```bash
tar xzf rustinel-<version>-x86_64-unknown-linux-musl.tar.gz
cd rustinel-<version>-x86_64-unknown-linux-musl
sudo ./rustinel run
whoami
```

If startup fails with `tracefs not found`, mount the tracing filesystems and retry:

```bash
mount -t tracefs tracefs /sys/kernel/tracing
mount -t debugfs debugfs /sys/kernel/debug
```

The bundled Sigma demo rule should write an alert to `logs/alerts.json.<date>`.

## Compile From Source

If you prefer to build locally instead of using a published release, use `cargo build --release`.

### Windows

```powershell
cargo build --release
.\target\release\rustinel.exe run --console
```

### Linux

```bash
cargo build --release
sudo ./target/release/rustinel run
```

For full release setup, source-build prerequisites, and validation steps, see [Getting Started](https://karib0u.github.io/rustinel/getting-started/).

## Detection

- **Sigma** for behavioral detections on normalized events
- **YARA** for executable scanning on process-start events
- **IOC** for domains, IPs, path regexes, and file hashes

## Output

- Operational logs: `logs/rustinel.log.<date>`
- Alerts: `logs/alerts.json.<date>`
- Alert format: ECS 9.3.0 NDJSON

## Best For

- Lab deployments and evaluations
- Rule development and detection testing
- Blue teams that want transparent host telemetry and file-based alert output
- Cross-platform detection work without maintaining separate Windows and Linux pipelines

## Documentation

- [Documentation Home](https://karib0u.github.io/rustinel/)
- [Getting Started](https://karib0u.github.io/rustinel/getting-started/)
- [Configuration](https://karib0u.github.io/rustinel/configuration/)
- [Detection](https://karib0u.github.io/rustinel/detection/)
- [Architecture](https://karib0u.github.io/rustinel/architecture/)
- [Operations and Upgrade Guide](https://karib0u.github.io/rustinel/operations/)
- [Troubleshooting](https://karib0u.github.io/rustinel/troubleshooting/)
- [FAQ](https://karib0u.github.io/rustinel/faq/)

## Status

Rustinel **1.0.0** is the first official release. **Windows** and **Linux** are supported platforms. Windows telemetry coverage is still broader than Linux today, while Linux currently covers process, network, file, and DNS telemetry through eBPF.

## License

Apache 2.0. See `LICENSE`.
