<h1 align="center">cyberm4fia-spoofer</h1>

<p align="center">
  <img src="https://img.shields.io/badge/mission-network%20redirection%20%26%20interception-red?style=for-the-badge" alt="mission">
</p>

<p align="center">
<pre align="center">
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗  ██╗███████╗██╗ █████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║  ██║██╔════╝██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║███████║█████╗  ██║███████║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║╚════██║██╔══╝  ██║██╔══██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║     ██║██║     ██║██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
</pre>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python" alt="python">
  <img src="https://img.shields.io/badge/modules-16-purple?style=flat-square" alt="modules">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows-lightgrey?style=flat-square" alt="platform">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="license">
  <img src="https://img.shields.io/github/last-commit/erkanrzgc/cyberm4fia-spoofer?style=flat-square" alt="last commit">
</p>

<p align="center">
  <b>cyberm4fia-spoofer</b> is a modular, cross-platform DNS &amp; ARP spoofing toolkit for red team operations and network security testing.
</p>

---

## Features

### DNS Spoofing
| Feature | Description |
|---|---|
| Race Mode | Cross-platform — sniffs DNS queries and injects fake responses before real servers reply. |
| Intercept Mode | Linux-only — hijacks DNS responses via `netfilterqueue` for guaranteed redirection. |
| Multi-Action | Redirect (custom IP), Block (NXDOMAIN), Forward (passthrough). |
| Record Types | A, AAAA, CNAME, MX, NS — full DNS record spoofing support. |
| Domain Matching | Exact, wildcard (`*.example.com`), and regex patterns. |

### ARP Spoofing
| Feature | Description |
|---|---|
| ARP Cache Poisoning | Continuous ARP reply injection at configurable intervals. |
| Bidirectional Spoof | Poison both victim→gateway and gateway→victim simultaneously. |
| Auto-Restore | Restores original ARP tables on exit to prevent network disruption. |
| Multi-Victim | Multiple victims per gateway in a single session. |
| MAC Resolution | Automatic MAC address resolution for gateway and victim hosts. |

### Platform & Infrastructure
| Feature | Description |
|---|---|
| Cross-Platform | Linux: scapy + iptables | Windows: scapy + Npcap + netsh. |
| Firewall Automation | Auto setup/cleanup of `iptables` (Linux) and Windows Firewall rules. |
| IP Forwarding | Automatic IPv4 forwarding enable/disable on session start/stop. |
| Pre-Flight Health Checks | 13 system checks before starting — dependencies, permissions, interfaces. |
| Network Discovery | ARP-based network scan with OUI vendor lookup via macvendors API. |

### UI & UX
| Feature | Description |
|---|---|
| Textual TUI Dashboard | Real-time session stats, live log feed, active targets panel. |
| Interactive Menu | Full terminal UI with keyboard shortcuts for all operations. |
| Rich CLI | Gradient ASCII banner, colored output, styled tables via `rich`. |
| Typer CLI | 13 subcommands with auto-generated `--help`, type-hinted interface. |

### Extensibility
| Feature | Description |
|---|---|
| Plugin System | Drop `.py` files into `plugins/` — subclass `BasePlugin`, auto-loaded at runtime. |
| Callbacks | Webhook (Discord/Slack) + shell command execution on DNS/ARP hits. |
| YAML Config | Pydantic v2-validated configuration with profile support. |
| Stats Export | JSON session statistics saved on exit. |
| Session Resume | Config-based session management, profile save/load. |

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Pre-flight health check
python spoof.py health

# Interactive TUI menu (launches automatically when no targets configured)
sudo python spoof.py

# DNS spoof with wildcard matching
sudo python spoof.py dns --domain "*.vulnweb.com" --spoof-ip 192.168.1.100

# ARP spoof with single victim
sudo python spoof.py arp --gateway 192.168.1.1 --victim 192.168.1.105

# Full MITM mode (DNS + ARP simultaneously)
sudo python spoof.py mitm \
  --domain "*example.com" --spoof-ip 10.0.0.5 \
  --gateway 192.168.1.1 --victim 192.168.1.105

# Network discovery
sudo python spoof.py discover

# View and manage targets
python spoof.py targets
python spoof.py add-target "blocked.org" --action block
python spoof.py add-arp 192.168.1.1 192.168.1.107
python spoof.py remove-target "blocked.org"
```

---

## CLI Commands

| Command | Description | Example |
|---|---|---|
| `spoof` | Start session or launch interactive menu | `sudo spoof` |
| `spoof init` | Create default config file | `spoof init --path custom.yaml` |
| `spoof health` | Run pre-flight system checks | `spoof health` |
| `spoof discover` | ARP scan for network devices | `sudo spoof discover -i eth0` |
| `spoof dns` | Start DNS spoofing only | `sudo spoof dns -d "*.target.com" -s 1.2.3.4` |
| `spoof arp` | Start ARP spoofing only | `sudo spoof arp -g 192.168.1.1 -t 192.168.1.105` |
| `spoof mitm` | Start DNS + ARP spoofing | `sudo spoof mitm -d "*" -s 10.0.0.5 -g 192.168.1.1 -t 192.168.1.105` |
| `spoof targets` | List configured targets | `spoof targets` |
| `spoof add-target` | Add DNS target rule | `spoof add-target "*.evil.com" --ip 5.6.7.8 --match wildcard` |
| `spoof add-arp` | Add ARP spoof target | `spoof add-arp 192.168.1.1 192.168.1.108` |
| `spoof remove-target` | Remove DNS target rule | `spoof remove-target "*.evil.com"` |
| `spoof menu` | Launch interactive TUI menu | `spoof menu` |
| `spoof version` | Show version and platform info | `spoof version` |

### Global Options

| Option | Short | Description |
|---|---|---|
| `--config` | `-c` | Path to YAML config file |
| `--mode` | `-m` | Attack mode: `dns`, `arp`, `mitm` |
| `--interface` | `-i` | Network interface to use |
| `--domain` | `-d` | Target domain to spoof |
| `--spoof-ip` | `-s` | IP address to redirect to |
| `--gateway` | `-g` | Gateway IP for ARP spoofing |
| `--victim` | `-t` | Victim IP for ARP spoofing |
| `--dns-mode` | | DNS spoof mode: `race`, `intercept` |
| `--log-level` | `-l` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `--banner` | `-b` | Show banner and exit |

---

## Configuration

The tool uses a Pydantic-validated YAML config file (`config/targets.yaml`):

```yaml
session:
  interface: null              # auto-detect if null
  log:
    level: INFO
    file: logs/spoof.log
    rotation: "10 MB"
    retention: "7 days"
  auto_firewall: true          # auto iptables/netsh management
  restore_on_exit: true        # restore ARP tables on stop
  save_stats: true

dns:
  enabled: true
  mode: race                   # race | intercept
  targets:
    - pattern: "*.vulnweb.com"
      match_type: wildcard     # exact | wildcard | regex
      action: redirect         # redirect | block | forward
      redirect_ip: "192.168.1.100"
      enabled: true

    - pattern: "blocked.org"
      match_type: exact
      action: block            # returns NXDOMAIN
      enabled: true

    - pattern: "^login\\..*\\.com$"
      match_type: regex
      action: redirect
      redirect_ip: "10.0.0.5"
      enabled: true

  ttl: 300

arp:
  enabled: true
  interval: 2.0               # seconds between ARP replies
  targets:
    - gateway: "192.168.1.1"
      victims:
        - ip: "192.168.1.105"
      enabled: true
```

---

## Plugin System

Create custom plugins by subclassing `BasePlugin` and dropping `.py` files into `plugins/`:

```python
from spoof.plugin_manager import BasePlugin

class DiscordNotifier(BasePlugin):
    name = "discord_notifier"
    version = "1.0.0"

    def on_dns_hit(self, domain, client_ip, spoof_ip, action):
        self._notify(f"DNS Hit: {domain} → {spoof_ip} from {client_ip}")

    def on_arp_spoof(self, gateway, victim, action):
        self._notify(f"ARP Spoof: gw={gateway} victim={victim}")

    def on_session_start(self):
        self._notify("Spoof session started")

    def on_session_stop(self):
        self._notify("Spoof session stopped")

    def _notify(self, msg):
        import httpx
        httpx.post("YOUR_WEBHOOK_URL", json={"content": msg})
```

Enable in config:
```yaml
session:
  plugin:
    enabled_plugins: ["discord_notifier"]
```

---

## DNS Spoof Modes

### Race Mode (Default — Cross-Platform)
Sniffs DNS query packets on the wire and injects a forged DNS response before the legitimate server can reply. Works on both Linux and Windows.

```
Client → [DNS Query: example.com] → LAN
                                        ↓
                              Spoofer detects query
                              Spoofer sends fake response (IP: 1.2.3.4)
                                        ↓
Client ← [DNS Answer: example.com = 1.2.3.4]
                                        ↓
                              Real DNS response arrives too late → discarded
```

### Intercept Mode (Linux Only)
Uses `netfilterqueue` to intercept DNS responses at the kernel level, modify them, and re-inject. Guaranteed redirection — no race condition.

```
Client → [DNS Query: example.com] → DNS Server
Client ← [DNS Answer: example.com = 8.8.8.8] ← DNS Server
                   ↓
         iptables NFQUEUE intercepts
         Spoofer modifies: 8.8.8.8 → 1.2.3.4
                   ↓
Client ← [DNS Answer: example.com = 1.2.3.4]
```

---

## Project Structure

```
cyberm4fia-spoofer/
├── spoof.py                       # Typer CLI entry point (13 subcommands)
├── spoof/                         # Main package
│   ├── __init__.py
│   ├── models.py                  # Pydantic v2 data models (15 models)
│   ├── config.py                  # YAML config + CLI merge + profile init
│   ├── logger.py                  # Loguru — colored output, rotation, retention
│   ├── banner.py                  # Rich gradient ASCII banner
│   ├── session.py                 # Session orchestrator (all engines)
│   ├── target_manager.py          # Domain matching engine (exact/wildcard/regex)
│   ├── health_check.py            # 13 pre-flight system checks
│   ├── discovery.py               # ARP network scanner + OUI vendor lookup
│   ├── callback.py                # Webhook + shell command callbacks
│   ├── plugin_manager.py          # Plugin system (BasePlugin)
│   ├── dashboard.py               # Textual real-time TUI dashboard
│   ├── menu.py                    # Textual interactive terminal menu
│   ├── core/
│   │   ├── __init__.py
│   │   ├── dns_spoofer.py         # DNS spoof engine (race + intercept)
│   │   ├── arp_spoofer.py         # ARP spoof engine (poison + restore)
│   │   ├── packet_sniffer.py      # Cross-platform packet sniffer wrapper
│   │   └── packet_injector.py     # Packet injection (DNS responses, ARP replies)
│   ├── platform/
│   │   ├── __init__.py
│   │   ├── base.py                # Abstract platform adapter
│   │   ├── linux.py               # Linux implementation (scapy + iptables)
│   │   └── windows.py             # Windows implementation (scapy + Npcap + netsh)
│   └── firewall/
│       ├── __init__.py
│       ├── base.py                # Abstract firewall adapter
│       ├── iptables.py            # iptables rule management
│       └── windows_fw.py          # Windows Firewall (netsh) management
├── config/
│   └── targets.yaml               # Default configuration
├── plugins/
│   └── discord_webhook_example.py # Example plugin
├── requirements.txt
├── LICENSE
└── README.md
```

---

## Requirements

| Dependency | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Runtime |
| scapy | 2.5.0+ | Packet crafting, sniffing, ARP operations |
| pydantic | 2.0+ | Config validation, data models |
| typer | 0.9+ | CLI framework with type hints |
| textual | 0.50+ | TUI dashboard and interactive menu |
| rich | 13.0+ | Terminal styling, tables, ASCII art |
| loguru | 0.7+ | Structured logging with rotation |
| httpx | 0.25+ | Webhook and API calls |
| psutil | 5.9+ | Process and system utilities |
| pyyaml | 6.0+ | YAML config parsing |

**Linux extras:** iptables (or nftables), libpcap, root access
**Windows extras:** [Npcap](https://npcap.com), Administrator access

Install all Python deps:
```bash
pip install -r requirements.txt
```

---

## Legal Disclaimer

> **This tool is for authorized security testing and educational purposes only.**
> Unauthorized interception or manipulation of network traffic is illegal.
> The developers assume no liability for misuse. Always obtain explicit written permission before testing.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
