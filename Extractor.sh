#!/usr/bin/env bash
# =============================================================================
# Universal Network Interface Information Collector - FIXED & ENHANCED
# Works on: Physical machines, VMs, WSL, Docker, LXC, etc.
# Run: bash net_info.sh
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Colored output functions
print_status()  { echo -e "${GREEN}[*] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error()   { echo -e "${RED}[!] $1${NC}"; }
print_info()    { echo -e "${BLUE}[i] $1${NC}"; }

# Global variables
declare -A interface_map
interface_count=0
INTERFACE=""
OUTPUT_FILE=""

# Detect interfaces using the most reliable method available
detect_interfaces() {
    print_status "Detecting network interfaces..."

    local interfaces=""

    # Method 1: ip link (best when available)
    if command -v ip >/dev/null; then
        interfaces=$(ip -o link show | awk -F': ' '{print $2}' | sort -u)
    fi

    # Method 2: /sys/class/net (works in containers)
    if [[ -z "$interfaces" ]] && [[ -d /sys/class/net ]]; then
        interfaces=$(ls /sys/class/net/ | sort)
    fi

    # Method 3: /proc/net/dev fallback
    if [[ -z "$interfaces" ]] && [[ -f /proc/net/dev ]]; then
        interfaces=$(awk '/:/{gsub(/:/,""); print $1}' /proc/net/dev | grep -v lo | sort)
        [[ -n "$interfaces" ]] && interfaces="lo $interfaces"
    fi

    [[ -z "$interfaces" ]] && print_error "No network interfaces found!" && return 1

    echo ""
    print_info "Available network interfaces:"
    echo "=================================="

    local counter=1
    for iface in $interfaces; do
        [[ -z "$iface" ]] && continue

        local state="UNKNOWN"
        state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
        [[ "$state" == "unknown" ]] && state=$(ip link show "$iface" 2>/dev/null | grep -o "state [A-Z]*" | awk '{print $2}' || echo "DOWN")

        local ip_addr="None"
        ip_addr=$(ip -4 addr show dev "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "None")

        local mac_addr="No MAC"
        mac_addr=$(cat "/sys/class/net/$iface/address" 2>/dev/null 2>/dev/null || ip link show "$iface" 2>/dev/null | grep -o "link/ether [0-9a-f:]*" | awk '{print $2}' || echo "No MAC")

        local type_desc="Other"
        if [[ "$iface" == "lo" ]]; then
            type_desc="Loopback"
        elif [[ -d "/sys/class/net/$iface/wireless" ]] || command -v iw >/dev/null && iw dev "$iface" info >/dev/null 2>&1; then
            type_desc="Wireless"
        elif [[ "$iface" =~ ^(tun|tap)[0-9]+$ ]]; then
            type_desc="VPN/Tunnel"
        elif [[ "$iface" =~ ^br[0-9a-f]*$ ]]; then
            type_desc="Bridge"
        elif [[ "$iface" =~ ^veth ]]; then
            type_desc="Virtual Ethernet"
        elif [[ -d "/sys/class/net/$iface/device" ]]; then
            type_desc="Ethernet"
        fi

        case "$type_desc" in
            "Wireless")     echo -e "  ${GREEN}$counter. $iface  [$type_desc]  State: $state  IP: $ip_addr  MAC: $mac_addr${NC}" ;;
            "Ethernet")     echo -e "  ${BLUE}$counter. $iface  [$type_desc]  State: $state  IP: $ip_addr  MAC: $mac_addr${NC}" ;;
            "VPN/Tunnel"|"Bridge"|"Virtual Ethernet") echo -e "  ${YELLOW}$counter. $iface  [$type_desc]  State: $state  IP: $ip_addr${NC}" ;;
            *)              echo "  $counter. $iface  [$type_desc]  State: $state  IP: $ip_addr  MAC: $mac_addr" ;;
        esac

        interface_map[$counter]="$iface"
        ((counter++))
    done

    interface_count=$((counter - 1))
    [[ $interface_count -eq 0 ]] && print_error "No interfaces to display!" && return 1
    echo ""
    return 0
}

select_interface() {
    while true; do
        read -p "$(echo -e "${BLUE}[?] Enter interface number (1-$interface_count): ${NC}")" choice
        if [[ -z "$choice" ]]; then
            print_error "Please enter a number"
            continue
        fi
        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            print_error "Invalid input - numbers only"
            continue
        fi
        if [[ -z "${interface_map[$choice]:-}" ]]; then
            print_error "Invalid selection. Choose 1 to $interface_count"
            continue
        fi
        INTERFACE="${interface_map[$choice]}"
        print_status "Selected interface: $INTERFACE"
        break
    done
}

get_interface_type() {
    local iface="$1"
    if [[ "$iface" == "lo" ]]; then echo "loopback"; return; fi
    if [[ -d "/sys/class/net/$iface/wireless" ]] || command -v iw >/dev/null && iw dev "$iface" info >/dev/null 2>&1; then
        echo "wireless"; return
    fi
    if [[ "$iface" =~ ^(tun|tap)[0-9]+$ ]]; then echo "vpn"; return; fi
    if [[ "$iface" =~ ^br[0-9a-f]*$ ]]; then echo "bridge"; return; fi
    if [[ "$iface" =~ ^veth ]]; then echo "virtual"; return; fi
    if [[ -d "/sys/class/net/$iface/device" ]]; then echo "ethernet"; return; fi
    echo "unknown"
}

collect_interface_info() {
    local output_file="$1"
    local iface="$INTERFACE"
    local type=$(get_interface_type "$iface")

    print_status "Collecting detailed information for $iface ($type)..."

    {
        echo "=== UNIVERSAL NETWORK INTERFACE REPORT ==="
        echo "Generated: $(date)"
        echo "Hostname: $(hostname 2>/dev/null || echo 'unknown')"
        echo "User: $(whoami)"
        echo "Interface: $iface"
        echo "Type: $type"
        echo ""

        echo "=== Basic Info ==="
        ip link show dev "$iface" 2>/dev/null || echo "ip link failed"
        echo ""

        echo "=== IP Configuration ==="
        ip -4 addr show dev "$iface" 2>/dev/null || echo "No IPv4"
        ip -6 addr show dev "$iface" 2>/dev/null | grep -v "scope link" || echo "No IPv6 (or only link-local)"
        echo ""

        echo "=== Routing ==="
        ip route show dev "$iface" 2>/dev/null || ip route show table all | grep "$iface" || echo "No specific routes"
        echo ""

        echo "=== Statistics ==="
        ip -s link show dev "$iface" 2>/dev/null || echo "No stats available"
        echo ""

        echo "=== Active Connections (all, filtered if possible) ==="
        if command -v ss >/dev/null; then
            ss -tunlp | grep -i "$iface" || ss -tunlp | head -20
        elif command -v netstat >/dev/null; then
            netstat -tunp 2>/dev/null | head -20
        else
            echo "Neither ss nor netstat available"
        fi
        echo ""

        echo "=== Neighbors / ARP ==="
        ip neighbor show dev "$iface" 2>/dev/null || echo "No neighbor info"
        echo ""

        echo "=== Interface-Specific Info ==="
        case "$type" in
            wireless)
                iw dev "$iface" info 2>/dev/null || echo "iw info failed"
                iw dev "$iface" link 2>/dev/null || echo "Not connected"
                iw dev "$iface" scan >/dev/null 2>&1 && echo "[Scan works - suppressed output]" || true
                ;;
            vpn)
                echo "RX/TX packets:"
                cat "/sys/class/net/$iface/statistics/rx_packets" 2>/dev/null || echo "N/A"
                cat "/sys/class/net/$iface/statistics/tx_packets" 2>/dev/null || echo "N/A"
                ;;
            ethernet)
                command -v ethtool >/dev/null && ethtool "$iface" | head -20 || echo "ethtool not available"
                ;;
            bridge)
                if command -v bridge >/dev/null; then
                    bridge link show dev "$iface" 2>/dev/null || echo "No bridge info"
                elif command -v brctl >/dev/null; then
                    brctl show 2>/dev/null | grep "$iface" || echo "No bridge info"
                fi
                ;;
        esac
        echo ""

        echo "=== System-Wide Info ==="
        echo "All IPs: $(hostname -I 2>/dev/null || echo 'unknown')"
        echo "Default gateway:"
        ip route get 8.8.8.8 2>/dev/null | grep via || echo "None detected"
        echo ""

        echo "=== Firewall (sample) ==="
        if command -v iptables >/dev/null; then
            iptables -L -n -v | head -10 2>/dev/null || echo "iptables not accessible"
        elif command -v nft >/dev/null; then
            nft list ruleset | head -10 2>/dev/null || echo "nft not accessible"
        else
            echo "No firewall tool found"
        fi

        echo ""
        echo "=== END OF REPORT ==="
        echo "Generated at: $(date)"
    } > "$output_file"
}

main() {
    clear
    echo -e "${GREEN}"
    echo "===================================================="
    echo "   Universal Network Interface Information Tool"
    echo "   Works everywhere: VMs, WSL, Docker, Servers"
    echo "===================================================="
    echo -e "${NC}"

    if ! command -v ip >/dev/null; then
        print_error "'ip' command not found. Install iproute2."
        exit 1
    fi

    if ! detect_interfaces; then
        print_error "Failed to detect interfaces. Exiting."
        exit 1
    fi

    select_interface

    OUTPUT_FILE="netinfo_${INTERFACE}_$(date +%Y%m%d_%H%M%S).txt"
    collect_interface_info "$OUTPUT_FILE"

    echo ""
    print_status "Collection complete!"
    echo -e "   ${BLUE}Output saved to: $OUTPUT_FILE${NC}"
    echo -e "   Lines: $(wc -l < "$OUTPUT_FILE")"
    echo -e "   Size : $(du -h "$OUTPUT_FILE" | cut -f1)"

    read -p "$(echo -e "${BLUE}[?] View file now? (y/N): ${NC}")" view
    if [[ "$view" =~ ^[Yy]$ ]]; then
        if command -v less >/dev/null; then
            less "$OUTPUT_FILE"
        else
            cat "$OUTPUT_FILE"
        fi
    fi

    print_status "All done! Report: $OUTPUT_FILE"
}

main "$@"