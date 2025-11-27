# NetInfo-Extractor – README

A powerful, universal, and container-friendly Bash script that collects **comprehensive network interface information** from any Linux environment — physical machines, virtual machines, WSL, Docker/Podman containers, LXC, cloud instances, etc.

Works perfectly even when many common tools (`ifconfig`, `iwconfig`, `ethtool`, `brctl`, etc.) are missing.

![](https://img.shields.io/badge/version-2.1-brightgreen) ![](https://img.shields.io/badge/bash-%3E%3D4.0-blue) ![](https://img.shields.io/badge/root-not_required-orange)

## Features

- Detects **all** network interfaces (eth0, wlan0, ens*, enp*, wlp*, tun0, tap0, br-*, veth*, lo, etc.)
- Works in minimal environments (Alpine, Docker, distroless, etc.)
- Colorful interactive menu
- Smart fallbacks for missing tools
- Detailed per-interface report including:
  - Interface state, IP (v4/v6), MAC
  - Routing table & default gateway
  - Statistics (rx/tx packets, errors, etc.)
  - Active connections (ss or netstat)
  - ARP/neighbor table
  - Wireless info (signal, connected AP, etc.)
  - VPN/Tunnel stats
  - Ethernet link settings (ethtool)
  - Bridge information
  - Basic firewall rules (iptables or nft)
- Saves everything to a nicely formatted `.txt` file with timestamp
- No external dependencies beyond `iproute2` (which is present almost everywhere)

## Screenshot

![demo](https://i.ibb.co.com/9h0n0v0/netinfo-demo.png)

## Quick Start

```bash
# One-liner (recommended)
curl -sSL https://raw.githubusercontent.com/moteus/NetInfo-Extractor/main/net_info.sh | bash

# Or download and run manually
wget https://raw.githubusercontent.com/moteus/NetInfo-Extractor/main/net_info.sh
chmod +x net_info.sh
./net_info.sh
```

## Permanent Installation (optional)

```bash
git clone https://github.com/VulnEdge/NetInfo-Extractor
```

Then just run:

```bash
netinfo
```

## Output Example

```
netinfo_eth0_20251127_153022.txt
netinfo_wlan0_20251127_153145.txt
netinfo_tun0_20251127_153210.txt
```

Each file contains a complete, human-readable diagnostic report ideal for:
- Troubleshooting connectivity issues
- Auditing containers/VMs
- Sharing with support teams
- Documenting network configuration

## Requirements

- Linux (any distribution)
- `bash` ≥ 4.0
- `iproute2` package (`ip`, `ss`, etc.) – installed by default on 99% of systems

Optional tools (gracefully handled if missing):
- `iw`, `ethtool`, `bridge`, `brctl`, `iptables`, `nft`, `netstat`, `less`

## Tested Environments

| Environment           | Works? | Notes                          |
|-----------------------|--------|--------------------------------|
| Ubuntu / Debian       | Yes    | Perfect                        |
| Alpine Linux          | Yes    | Even in minimal containers     |
| CentOS / RHEL / Rocky | Yes    |                                |
| Arch Linux            | Yes    |                                |
| WSL1 & WSL2           | Yes    |                                |
| Docker / Podman       | Yes    | Works inside containers        |
| LXC / systemd-nspawn  | Yes    |                                |
| OpenWrt               | Yes    |                                |
| Kali / Parrot OS      | Yes    |                                |

## Contributing

Contributions are very welcome! Feel free to:
- Open issues
- Submit pull requests
- Suggest new features (JSON output, HTML export, etc.)

## Author & License

Created with ❤️ by the open-source community  
Maintained at: https://github.com/VulnEdge/NetInfo-Extractor

**License**: MIT – free to use, modify, and distribute.

---

**When in doubt about your network setup, just run `netinfo`.**  
You’ll get everything you need in under 10 seconds.
