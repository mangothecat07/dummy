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

if [ ! -z "$P_IP" ]; then
    P_RANGE=$(echo $P_IP | cut -d. -f1-3).0/24
else
    P_RANGE="Unknown"
fi

show_menu() {

    echo "------------------------------------------"
    echo "    UNIVERSAL MANGO AUDITOR (WSL2)        "
    echo "------------------------------------------"
    echo " Current WiFi IP:  ${P_IP:-Disconnected}"
    echo " Current Gateway:  ${P_GW:-Unknown}"
    echo " Current Subnet:   $P_RANGE"
    echo "------------------------------------------"
    echo "1) [DISCOVERY] Find All Real Devices"
    echo "2) [IDENTITY]  Scan Virtual Host (Windows)"
    echo "3) [ORIGIN]    Deep Scan Current Router"
    echo "4) [TRUE ORIGIN] Trace Network Origin"
    echo "5) [NINJA]     Listen for Hidden Traffic"
    echo "6) [AGG DISC]  Hyper-Aggro Discovery"
    echo "7) [HYBRID DISC]    Smart Discovery"
    echo "8) [OS]    Scan OS Type"
    echo "9) Exit"
    echo "------------------------------------------"
}

execute_action() {
    case $1 in
1)
            echo "--- LOUD DISCOVERY ---"
            echo "[LOUD] Sending Multi-Protocol Probes (ICMP + TCP)..."
            # -sn: No port scan, -PE: Echo, -PP: Timestamp, -PS: TCP SYN on common ports
            nmap -sn -PE -PP -PS22,80,443 "$P_RANGE" | grep "Nmap scan report"
            echo -e "\n[+] Updated Windows ARP Neighbors:"
            $ARP_EXE -a | grep "$PREFIX"
# Extract the MAC for the identified Gateway
            RAW_MAC=$($ARP_EXE -a | grep "$P_GW " | awk '{print $2}' | head -n 1)

            if [ ! -z "$RAW_MAC" ] && [ "$RAW_MAC" != "N/A" ]; then
    # Clean the OUI for the API (handles the '-' to ':' conversion)
                CLEAN_OUI=$(echo $RAW_MAC | tr '-' ':' | cut -c1-8)

                echo -n "[VENDOR] Checking hardware manufacturer... "
                VENDOR=$(curl -s "https://api.macvendors.com/$CLEAN_OUI")

                # Handle randomized MACs or API errors
                if [[ "$VENDOR" == *"errors"* ]] || [[ -z "$VENDOR" ]]; then
                    echo -e "\033[33mRandomized/Private Hardware\033[0m"
                else
                    echo -e "\033[32m$VENDOR\033[0m"
                fi
            else
                echo "[!] Could not find MAC for $P_GW in Windows ARP cache."
            fi
;;

        2)
            echo "Scanning Windows Host via Virtual Bridge..."
            nmap -sV -T4 -O -Pn "$V_GW"
            ;;
        3)
            echo "Aggressive Scan on Router: $P_GW"
            nmap -A -Pn "$P_GW"
            # This fetches the Organization (ISP) associated with your public exit point
            curl -s "https://ipapi.co/org/" && echo " (Location: $(curl -s https://ipapi.co/city/))"
            echo "--- SEARCHING FOR ADMIN PORTAL ---"
            if [ -z "$P_GW" ]; then echo "No Gateway found."; else
                echo "[POKE] Checking $P_GW for Web Management Interfaces..."
                # Ports: 80 (HTTP), 443 (HTTPS), 8080/8443 (Common Alt), 7547 (TR-069 Management)
                sudo nmap -sV -O -p 80,443,8080,8443,7547 --open "$P_GW" | grep -E "PORT|STATE|SERVICE|VERSION"

                echo -e "\n[TIP] If you see port 80 or 443 open, try visiting http://$P_GW in your browser."
            fi
            ;;
        4)
            echo "--- TRACING NETWORK ORIGIN ---"
            if [ -z "$P_GW" ]; then echo "No Gateway found."; else
                echo "Master Gateway Found: $P_GW"
                sudo nmap -sV -O -Pn -T4 "$P_GW"
                # This fetches the Organization (ISP) associated with your public exit point
                curl -s "https://ipapi.co/org/" && echo " (Location: $(curl -s https://ipapi.co/city/))"
            fi
            ;;
        5)
             echo "Capturing DNS, Web, and Discovery traffic..."
    # Captures DNS (53), Web (80/443), and common discovery ports
            sudo tcpdump -i eth0 -n -l "port 53 or port 80 or port 443 or port 5353 or port 1900" | awk '{
            if ($0 ~ /\.53 /) print "\033[35m[DNS]\033[0m " $0;
            else if ($0 ~ /\.443/) print "\033[31m[HTTPS]\033[0m " $0;
            else if ($0 ~ /1900|5353/) print "\033[36m[DISCOVERY]\033[0m " $0;
            else print "[TRAFFIC] " $0;
            }'
            ;;
6)
            # --- RESUMPTION CHECK ---
            SKIP_DISCO="n"
            if [ -f /aggro_ips.txt ] && [ -s /aggro_ips.txt ]; then
                echo -e "\n\033[33m[?] Found previous discovery results:\033[0m"
                cat /aggro_ips.txt
                read -p "Skip Discovery and jump straight to Vuln Probe? (y/n): " SKIP_DISCO
            fi

            if [[ "$SKIP_DISCO" != "y" ]]; then
                echo "--- HYPER-AGGRO DISCOVERY & VULN PROBE ---"
                echo "Step 1: Rapid-fire Wake-up (Fast-Ping)..."
                # Use Nmap for native speed over PowerShell loops
                nmap -sn -PE -n --min-parallelism 100 "$P_RANGE" > /dev/null 2>&1

                echo "Step 2: Nmap ARP Ping Scan ($P_RANGE)..."
                nmap -sn -PR "$P_RANGE" | grep "Nmap scan report" | awk '{print $NF}' > /aggro_ips.txt
                cat /tmp/aggro_ips.txt
            fi

            echo -e "\nStep 3: Probing for Service Versions (DNS Chaos)..."
            while read -r ip; do
                # Added --host-timeout 1s to ensure the loop never hangs
                if nmap -p 53 --open -T4 --host-timeout 1s "$ip" | grep -q "open"; then
                    VERSION=$(dig @$ip version.bind CHAOS TXT +short | tr -d '"')
                    if [ ! -z "$VERSION" ]; then
                        echo -e "[!] $ip is running: \033[31m$VERSION\033[0m"
                        if [[ "$VERSION" == *"2.51"* ]]; then
                            echo -e "    \033[31m-> WARNING: Potential CVE-2017-14491 (Remote Code Execution)\033[0m"
                        fi
                    fi
                fi
            done < /tmp/aggro_ips.txt

            echo -e "\nStep 4: Confirmed Windows ARP Neighbors:"
            PREFIX=$(echo $P_IP | cut -d. -f1-3)
            $ARP_EXE -a | grep "$PREFIX" | grep "dynamic"
            ;;
7)
    echo "--- SMART HYBRID DISCOVERY ---"
    echo "[GHOST] Listening for heartbeats (10s)..."

    # We use tcpdump to capture ARP packets quietly in the background
    # This won't mess up your screen formatting
    sudo tcpdump -i eth0 -n arp > /tmp/arp_packets.txt 2>/dev/null &
    SNIFF_PID=$!

    sleep 2
    echo "[POKE] Sending Broadcast Wake-up..."
    ping -c 1 -b $(echo $P_IP | cut -d. -f1-3).255 > /dev/null 2>&1

    sleep 8
    sudo kill $SNIFF_PID 2>/dev/null

    echo -e "\n[+] Live Devices Detected (Passive Sniff):"
    # Extract unique IPs from the tcpdump log
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' /tmp/arp_packets.txt | sort -u

    echo -e "\n[+] Confirmed Neighbors (Windows Cache):"
    $ARP_EXE -a | grep "$(echo $P_IP | cut -d. -f1-3)"
    ;;
8)
    TARGETS="/scripts/aggro_ips.txt"
    if [ -s "$TARGETS" ]; then
        echo "[SMART] Targets found in $TARGETS. Scanning only live hosts..."
        SCAN_TARGET="-iL $TARGETS"
    else
        echo "[RANGE] No target list found. Scanning whole range: $P_RANGE"
        SCAN_TARGET="$P_RANGE"
    fi

    sudo nmap -sV --script banner -O --osscan-guess --source-port 53 $SCAN_TARGET | \
    grep -E "Nmap scan report|OS details|Device type|banner:"
;;
        9)
            echo "Audit Complete. Staying stealthy."
            exit 0
            ;;
        *)
            echo "Invalid selection."
            ;;
    esac
    read -p "Press enter to continue..."
}

while true; do
    show_menu
    read -p "Selection: " choice
    # Fixed the exit bug: Choice 6 now exits correctly
    if [ "$choice" -eq 9 ]; then exit 0; fi
    execute_action "$choice"
done
