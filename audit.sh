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
    echo "6) Exit"
    echo "------------------------------------------"
}

execute_action() {
    case $1 in
        1)
            echo "Step 1: Pinging via Windows to wake neighbors..."
            PREFIX=$(echo $P_IP | cut -d. -f1-3)
            $PWSH -Command "1..20 | ForEach-Object { Test-Connection \"$PREFIX.\$_\" -Count 1 -Quiet }" > /dev/null 2>&1
            echo "Step 2: Nmap ARP Ping Scan ($P_RANGE)..."
            nmap -sn -PR "$P_RANGE" | grep "Nmap scan report"
            echo -e "\nStep 3: Confirmed Windows ARP Neighbors:"
            $ARP_EXE -a | grep "$PREFIX" | grep "dynamic"
            ;;
        2)
            echo "Scanning Windows Host via Virtual Bridge..."
            nmap -sV -T4 -Pn "$V_GW"
            ;;
        3)
            echo "Aggressive Scan on Router: $P_GW"
            nmap -A -Pn "$P_GW"
            # This fetches the Organization (ISP) associated with your public exit point
            curl -s "https://ipapi.co/org/" && echo " (Location: $(curl -s https://ipapi.co/city/))"
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
            echo "Sniffing for mDNS/SSDP (Ctrl+C to stop)..."
            tcpdump -i eth0 -n "udp port 5353 or udp port 1900" -c 50
            ;;
        6)
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
    if [ "$choice" -eq 6 ]; then exit 0; fi
    execute_action "$choice"
done

