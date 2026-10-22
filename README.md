# portscout

A multithreaded TCP port scanner in Java to understand how tools like nmap work: it maps open ports across a subnet, identifies services from their banners, and tells closed ports apart from firewalled ones.

> Only scan hosts you own or have written permission to scan. `scanme.nmap.org` allows light scanning for testing.

## Overview

### What

A command-line tool that takes an IPv4 address or subnet (e.g. `192.168.1.0/24`) and a list of ports, tries to connect to each one, and reports which ports are **open**, **closed** or **filtered**, plus the banner of the service behind each open port.

### Problem

Every device on a network listens on numbered **ports**: 22 is usually SSH, 80 and 443 are websites, 3389 is Remote Desktop. Network and security teams constantly need to know *which ports a machine exposes and what is running behind them*:

- **Network engineering:** does the firewall really block what it should? What is on this subnet? Why can't anyone reach this service?
- **Security:** every open port is a possible way in, and a banner such as `SSH-2.0-OpenSSH_7.2` shows the exact version to check against known vulnerabilities.
- **Operations:** find forgotten services, like an old FTP server nobody switched off.

Doing this by hand is slow and unclear:

1. **Slow:** checking ports one at a time means waiting out a full timeout for every port that does not answer. On a firewalled host, 1,024 ports at 500 ms each is over **8 minutes**.
2. **Unclear:** a failed connection alone does not say whether *nothing is listening* or *a firewall is hiding the port*, and those mean very different things.

### Solution

- **TCP connect scan** that reads the packet behaviour: a completed handshake is OPEN, a reset (RST) is CLOSED, silence until the timeout is FILTERED. That turns "it failed" into "nothing there" vs "a firewall is dropping it".
- **Banner grabbing** to identify the service: read the greeting that SSH, FTP and SMTP send, and send an HTTP `HEAD` to services that stay silent.
- **Java 21 virtual threads, capped by a semaphore,** so probes wait on the network in parallel: 1,024 ports at 200 at a time takes about 1,024 ÷ 200 × 0.5 s ≈ **3 seconds** in the worst case instead of 8 minutes, without exhausting sockets or flooding the target.
- **CIDR parsing** to scan a whole subnet in one command, with safety limits (nothing bigger than a /16, at most 1,000,000 probes).

### Why I built it

nmap already does this well. portscout exists to understand **how it works underneath**, the networking, security and Java skills these jobs are built on:

| Concept | Where it lives |
|---|---|
| TCP three-way handshake (SYN, SYN-ACK, RST) | `PortProbe`: open / closed / filtered |
| Subnetting and CIDR math | `TargetParser`: network and broadcast addresses |
| Service identification | `PortProbe.grabBanner` |
| Firewall behaviour (drop vs refuse) | FILTERED vs CLOSED |
| Concurrency in Java 21 | `Scanner`: virtual threads capped by a semaphore |
| Testing and documentation | 28 JUnit tests, Javadoc, UML and flowchart below |

## Setup

### 1. Install the requirements

- **JDK 21 or newer.** Check with `java -version`. If it is missing or older, install [Eclipse Temurin](https://adoptium.net/) and reopen your terminal.
- **Git**, to download the code.

You do **not** need to install Gradle: the included `gradlew` wrapper downloads the right version on first use.

### 2. Get the code

```
git clone https://github.com/AoceanP/portscout.git
cd portscout
```

### 3. Build and run the tests

| Windows (PowerShell or cmd) | macOS / Linux |
|---|---|
| `.\gradlew.bat build` | `./gradlew build` |

The first run downloads Gradle and takes a minute. It ends with `BUILD SUCCESSFUL` once every test passes.

### 4. Scan your own machine

| Windows | macOS / Linux |
|---|---|
| `.\gradlew.bat run --args="127.0.0.1"` | `./gradlew run --args="127.0.0.1"` |

### 5. Optional: install it as a command

| Windows | macOS / Linux |
|---|---|
| `.\gradlew.bat installDist` | `./gradlew installDist` |
| `build\install\portscout\bin\portscout.bat 127.0.0.1` | `build/install/portscout/bin/portscout 127.0.0.1` |

Add that `bin` folder to your `PATH` to run `portscout` from anywhere.

### Troubleshooting

- **`gradlew` is not recognized** (PowerShell): type `.\gradlew.bat`, with the `.\` in front.
- **`JAVA_HOME is not set`** or **`Unsupported class file major version`**: your Java is missing or older than 21; see step 1.
- **Every port shows FILTERED on a remote host:** a firewall is dropping the probes, or the timeout is too short for a slow link; try `-t 2000`.

## Usage

```
portscout <target> [options]
```

| Option | Meaning | Default |
|---|---|---|
| `target` | one IPv4 address, or a CIDR block up to /16, e.g. `192.168.1.0/24` | required |
| `-p, --ports` | ports and ranges, e.g. `22,80,443,8000-8100` | `1-1024` |
| `-t, --timeout` | connect and read timeout in ms | `500` |
| `-c, --concurrency` | probes running at once | `200` |
| `--json` | JSON output, including closed and filtered ports | off |
| `--all` | also list closed and filtered ports in the table | off |

Example, a scan of a Windows PC:

```
> portscout 127.0.0.1 -p 1-1024
HOST             PORT   STATE     MS     BANNER
127.0.0.1        135    OPEN      1009
127.0.0.1        445    OPEN      501
2 open of 1024 probed
scanned 1 host(s) x 1024 port(s) in 1053 ms
```

Ports 135 (RPC) and 445 (SMB file sharing) are open on every Windows PC; a home router keeps them hidden from the internet. Neither sends a banner, so the time shown includes waiting for one.

## How it works

- **TCP connect scan:** open = handshake completes, closed = RST, filtered = no reply before the timeout.
- **Banner grabbing:** read the greeting that SSH, FTP and SMTP send first; for silent services send an HTTP `HEAD` and read the status line. Only the first printable line is kept, because banners are untrusted remote data.
- **Concurrency:** a semaphore permit is taken before each virtual thread starts, so at most `-c` probes exist at once and the scan never exhausts sockets.
- **Safety limits:** blocks bigger than a /16 and scans over 1,000,000 probes are refused.

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

- [x] PortParser
- [x] TargetParser (CIDR)
- [x] PortProbe (connect scan + banners)
- [x] Scanner (virtual threads + semaphore)
- [ ] Benchmarks vs nmap
- [ ] Stretch: UDP probes for DNS (53) and NTP (123)
- [ ] Stretch: map banners to known versions and flag outdated ones

## License

MIT, Copyright (c) 2026 AoceanP. See [LICENSE](LICENSE).
