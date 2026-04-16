# Roadmap

Rustinel is in active development. The items below reflect planned improvements across the sensor, detection, and operational layers.

## Sensor

### Linux

- **DNS domain name extraction** — `QueryName` is currently absent from Linux DNS events because BPF verifier complexity prevents in-kernel string parsing of DNS payloads. The plan is to move extraction to a userspace eBPF ring-buffer consumer or a `perf_event` uprobe on resolver libraries.
- **Expanded file telemetry** — cover `chmod`, `chown`, `truncate`, and `link` syscalls to close gaps in file-integrity coverage.
- **Container context** — enrich process events with cgroup, namespace, and container runtime metadata so rules can scope to specific workloads.

### Windows

- **ETW integrity checks** — detect ETW session tampering and provider blinding that could suppress telemetry.
- **Deep inspection via stack walking** — identify shellcode and "floating code" executing outside mapped image regions.

### Cross-Platform

- **Memory scanning** — extend YARA to scan live process memory regions on creation, not just the on-disk executable.
- **Periodic YARA sweeps** — scheduled background scans of running processes independent of creation events.

## Detection

- **Sigma aggregation conditions** — support `count`, `min`, `max`, `avg`, and `sum` aggregations for threshold and frequency-based rules.
- **Correlation engine** — multi-event rules that fire when a sequence or pattern of events occurs within a time window.
- **Threat intelligence enrichment** — inline lookup against external feeds at alert time.

## Operations

- **Resource governor** — CPU and memory budgets via Windows Job Objects and Linux cgroups to prevent the agent from affecting monitored workloads.
- **Watchdog sidecar** — lightweight companion process that restarts the agent if it crashes or becomes unresponsive.
- **Metrics endpoint** — expose operational counters (events processed, rules evaluated, alerts generated, queue depth) for Prometheus or a compatible scraper.
- **Remote rule delivery** — pull rule and IOC updates from a central server without manual file deployment.

## Hardening

- **Self-defense** — restrict access to the agent process and its rule files via Windows DACL restrictions and Linux seccomp/namespace isolation to reduce tampering surface.
- **eBPF program integrity** — verify that loaded eBPF objects match expected checksums at startup.
