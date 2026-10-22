# portscout

A multithreaded TCP port scanner in Java to understand how tools like nmap work: it maps open ports across a subnet, identifies services from their banners, and tells closed ports apart from firewalled ones.

> Only scan hosts you own or have written permission to scan. `scanme.nmap.org` allows light scanning for testing.

## Why

Every device on a network listens on numbered **ports**: 22 is usually SSH, 80 and 443 are websites, 3389 is Remote Desktop. A port scanner answers one question: *on this machine or subnet, which ports are open, and what is running behind them?*

- **Network engineering:** check a firewall really blocks what it should, find every device on a subnet, or see why a service can't be reached.
- **Security:** every open port is a possible way in, and a banner such as `SSH-2.0-OpenSSH_7.2` shows the exact version to check against known vulnerabilities. Scanning is the first step of most security assessments.
- **Operations:** find forgotten services, like an old FTP server nobody switched off.

nmap already does this well. portscout exists to show how it works underneath:

| Concept | Where it lives |
|---|---|
| TCP three-way handshake (SYN, SYN-ACK, RST) | `PortProbe`: open / closed / filtered |
| Subnetting and CIDR math | `TargetParser`: network and broadcast addresses |
| Service identification | `PortProbe.grabBanner` |
| Firewall behaviour (drop vs refuse) | FILTERED vs CLOSED |
| Concurrency in Java 21 | `Scanner`: virtual threads capped by a semaphore |
| Testing and documentation | JUnit tests, Javadoc, UML and flowchart below |

## Usage

```
gradlew run --args="127.0.0.1 -p 1-1024"
gradlew run --args="192.168.1.0/24 -p 22,80,443 --json"
```

| Option | Meaning | Default |
|---|---|---|
| `-p, --ports` | `22,80,443,8000-8100` | `1-1024` |
| `-t, --timeout` | connect timeout in ms | `500` |
| `-c, --concurrency` | probes running at once | `200` |
| `--json` | JSON output | off |
| `--all` | also list closed and filtered ports | off |

## How it works

- **TCP connect scan:** open = handshake completes, closed = RST, filtered = no reply before the timeout.
- **Banner grabbing:** read the greeting that SSH, FTP and SMTP send first; for silent services send an HTTP `HEAD` and read the status line.
- **Concurrency:** one virtual thread per probe, capped by a semaphore so the scan does not exhaust sockets.

## Design

### Program flow

The main thread parses the input and hands one task per host and port to a pool of virtual threads. Each task runs a TCP connect scan and, for open ports, grabs the banner.

![portscout program flow](docs/portscout-flow.png)

### UML class diagram

![portscout UML class diagram](docs/portscout-uml.png)

Both diagrams are drawn in draw.io: [portscout-flow.drawio](docs/portscout-flow.drawio) and [portscout-uml.drawio](docs/portscout-uml.drawio). Open them in draw.io or at app.diagrams.net to edit, then export to PNG with the same name.

## Benchmarks

TODO: time `127.0.0.1 -p 1-1024` at concurrency 1, 50 and 500, and compare against `nmap -sT`.

## Roadmap

- [ ] PortParser
- [ ] TargetParser (CIDR)
- [ ] PortProbe (connect scan + banners)
- [ ] Scanner (virtual threads + semaphore)
- [ ] Benchmarks vs nmap
- [ ] Stretch: UDP probes for DNS (53) and NTP (123)
- [ ] Stretch: map banners to known versions and flag outdated ones

## License

MIT, Copyright (c) 2026 AoceanP. See [LICENSE](LICENSE).
