#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./audit.sh)"
  exit
fi

# Path to Windows tools
PWSH="/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
ARP_EXE="/mnt/c/Windows/System32/arp.exe"

# --- DYNAMIC DISCOVERY ---
V_GW=$(ip route | grep default | awk '{print $3}')
P_IP=$($PWSH -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { \$_.InterfaceAlias -match 'Wi-Fi|Ethernet' -and \$_.IPv4Address -notmatch '172.' }).IPAddress" 2>/dev/null | head -n 1 | tr -d '\r')
P_GW=$($PWSH -Command "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop | Select-Object -First 1)" 2>/dev/null | tr -d '\r')

show_menu() {

    echo "------------------------------------------"
    echo "      GHOST MANGO AUDITOR (STEALTH)       "
    echo "------------------------------------------"
    echo " Mode: PASSIVE/SYN STEALTH (-sS -T2)      "
    echo "------------------------------------------"
    echo "1) [DISCOVERY]      Find All Real Devices (Passive)"
    echo "2) [IDENTITY]       Scan Virtual Host via SYN Stealth"
    echo "3) [ROUTER]         Stealth Interrogate Router: $P_GW"
    echo "4) [TRUE ORIGIN]    Trace Network Origin"
    echo "5) [NINJA]          Listen for Hidden Traffic"
    echo "6) [DECOY]          Hide IP among other ips"
    echo "7) [SPOOF]          Temporarily Spoof Hardware"
    echo "8) [GHOST 100]      Permanently Spoof Hardware"
}

execute_action() {
    case $1 in
1)
            echo "[STEALTH] Initiating Passive Recon (45s)..."
            echo "Listening for ARP/DHCP broadcasts. 100% silent."
            echo "------------------------------------------"
            # -p: passive mode (no packets sent)
            # -r: subnet range
            sudo timeout 45s netdiscover -p -i eth0 -r $(echo $P_IP | cut -d. -f1-3).0/24

            echo -e "\n[+] Discovery complete. Checking local cache for quiet hosts..."
            $ARP_EXE -a | grep "$(echo $P_IP | cut -d. -f1-3)"            ;;
        2)
            echo "[STEALTH] Scanning Virtual Host via SYN Stealth..."
            # -sS (SYN Scan), -T2 (Polite timing)
            nmap -sS -sV -T2 -Pn "$V_GW"
            ;;
        3)
            echo "[STEALTH] Stealth Interrogating Router: $P_GW"
            # Using -f (fragment packets) to bypass simple firewalls
            nmap -sS -sV -f -T2 -Pn "$P_GW"
            # -D RND:10 generates 10 random decoy IP addresses
            # ME ensures your real IP is hidden somewhere in that list of 10

            ;;
        4)
            echo "[STEALTH] Tracing Origin via Public API..."
            # Using a different API to avoid repeated patterns
            curl -s "https://ipinfo.io/org" && echo " ($(curl -s https://ipinfo.io/city))"
            ;;
5)
            echo "--- ADVANCED SNIFFER ---"
            echo "1) Discovery (mDNS/SSDP/ARP)"
            echo "2) Web Traffic (HTTP/HTTPS)"
            echo "3) DNS Queries (Site Names)"
            echo "4) The Firehose (All Traffic)"
            read -p "Select Mode: " sniff_mode

            case $sniff_mode in
                1) FILTER="udp port 5353 or udp port 1900 or arp" ;;
                2) FILTER="tcp port 80 or tcp port 443" ;;
                3) FILTER="udp port 53" ;;
                4) FILTER="" ;;
            esac

            echo "Sniffing started. Press Ctrl+C to stop."
            sudo tcpdump -i eth0 -n -l $FILTER | awk '{
                cyan="\033[36m"; green="\033[32m"; yellow="\033[33m"; purple="\033[35m"; red="\033[1;31m"; reset="\033[0m";

                if ($0 ~ /\.443[: ]/) print red "[SECURE WEB]" reset " " $0;
                else if ($0 ~ /\.80[: ]/) print yellow "[HTTP]" reset " " $0;
                else if ($0 ~ /\.53[: ]/) print purple "[DNS QUERY]" reset " " $0;
                else if ($0 ~ /\.138[: ]/ || $0 ~ /\.1900[: ]/) print cyan "[DISCOVERY]" reset " " $0;
                else if ($0 ~ /ARP/) print green "[DEVICE]" reset " " $0;
                else print "[RAW] " $0;
            }'
            ;;
        6)  echo "--- TACTICAL GHOST SCAN (Decoy Swarm) ---"
            read -p "Number of decoys (default 10): " DECOY_COUNT
            DECOY_COUNT=${DECOY_COUNT:-10}

            echo "[GHOST] Swarming $P_GW with $DECOY_COUNT decoys..."
            # Removed -f (fragmentation) to avoid triggering IPS drops
            # Added --randomize-hosts to make the scan pattern non-linear
            sudo nmap -sS -sV -Pn -T4 -D RND:$DECOY_COUNT --randomize-hosts "$P_GW"

            ;;
        7)
            echo "--- HARDWARE GHOSTING ---"
            echo "Choose a Hardware Mask:"
            echo "1) Apple (iPhone/Mac)"
            echo "2) Samsung"
            echo "3) Google"
            read -p "Selection: " mac_choice

            case $mac_choice in
                1) MASK="Apple" ;;
                2) MASK="Samsung" ;;
                3) MASK="Google" ;;
                *) MASK="0" ;;
            esac

            echo "[GHOST] Scanning as $MASK device..."
            # --spoof-mac: Changes your hardware ID for this scan only
            sudo nmap -sS -Pn --spoof-mac $MASK "$P_GW"
            ;;
        8)
            echo "--- PERMANENT HARDWARE GHOSTING ---"
            echo "1) Mask as Apple (iPhone)"
            echo "2) Mask as Samsung"
            echo "3) Mask as Google"
            echo "4) RESET to Factory Hardware ID"
            read -p "Selection: " mac_choice

            case $mac_choice in
                1) NEW_MAC="00:1E:C2:$(printf '%02X:%02X:%02X' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))" ;; # Apple OUI
                2) NEW_MAC="00:12:47:$(printf '%02X:%02X:%02X' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))" ;; # Samsung OUI
                3) NEW_MAC="00:1A:11:$(printf '%02X:%02X:%02X' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))" ;; # Google OUI
                4)
                   echo "[REVERT] Restoring real Hardware ID..."
                   # WSL2 usually uses a 00:15:5D prefix; this reset triggers a refresh
                   ip link set dev eth0 down
                   # Attempting to fetch the 'permanent' address if possible, else use a default reset
                   ip link set dev eth0 address $(ethtool -P eth0 | awk '{print $3}' 2>/dev/null || echo "00:15:5d:a9:5a:03")
                   ip link set dev eth0 up
                   echo "Hardware ID Reset."
                   return
                   ;;
                *) return ;;
            esac

            echo "[GHOST] Changing eth0 MAC to $NEW_MAC..."
            sudo ip link set dev eth0 down
            sudo ip link set dev eth0 address $NEW_MAC
            sudo ip link set dev eth0 up
            echo "Interface eth0 is now GHOSTED as $(ip link show eth0 | grep link/ether | awk '{print $2}')"
            # Define a hostname that matches the brand
            case $mac_choice in
            1) NEW_HOST="iPhone-$(printf '%04d' $((RANDOM%10000)))" ;;
            2) NEW_HOST="Samsung-S24-Ultra" ;;
            3) NEW_HOST="Pixel-8-Pro" ;;
            4) NEW_HOST="Mango" ;;
            esac

            # Apply the hostname change instantly
            sudo hostname $NEW_HOST
            echo "[GHOST] Hostname changed to: $NEW_HOST"
            ;;
        9)
            echo "Ghosting out..."
            exit 0
            ;;
    esac
    read -p "Press enter to continue..."
}

while true; do
    show_menu
    read -p "Selection: " choice
    if [ "$choice" -eq 9 ]; then exit 0; fi
    execute_action "$choice"
done
