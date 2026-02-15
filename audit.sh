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

    # 1. Real-time Nmap Loop
    # -oG - outputs in "Grepable" format for easier line-by-line parsing
    nmap -sn -PE -PP -PS22,80,443 "$P_RANGE" -oG - | while read -r line; do
        if echo "$line" | grep -q "Host:"; then
            IP=$(echo "$line" | awk '{print $2}')
            # Extract hostname if it exists, otherwise just show IP
            HOST=$(echo "$line" | awk '{print $3}' | tr -d '()')
            if [ "$HOST" != "" ] && [ "$HOST" != "$IP" ]; then
                echo "[FOUND] $IP ($HOST)"
            else
                echo "[FOUND] $IP"
            fi
        fi
    done

    echo -e "\n[+] Updated Windows ARP Neighbors:"
    $ARP_EXE -a | grep "$PREFIX"

    # 2. Extract and Check Gateway Vendor
    # We use -A 1 to ensure we get the line following the Gateway IP if needed
    RAW_MAC=$($ARP_EXE -a | grep -w "$P_GW" | awk '{print $2}' | head -n 1)

    if [ -n "$RAW_MAC" ] && [ "$RAW_MAC" != "N/A" ]; then
        # Standardize MAC format (00-11-22-33-44-55 to 00:11:22:33:44:55)
        CLEAN_OUI=$(echo "$RAW_MAC" | tr '-' ':' | cut -c1-8)
        
        echo -n "[VENDOR] Checking hardware manufacturer for $P_GW ($RAW_MAC)... "
        
        # API Call with a small timeout to prevent hanging
        VENDOR=$(curl -s --max-time 3 "https://api.macvendors.com/$CLEAN_OUI")
        
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
    TARGET_FILE="/tmp/aggro_ips.txt"

    if [ -f "$TARGET_FILE" ] && [ -s "$TARGET_FILE" ]; then
        echo -e "\n\033[33m[?] Found previous discovery results:\033[0m"
        cat "$TARGET_FILE"
        read -p "Skip Discovery and jump straight to Vuln Probe? (y/n): " SKIP_DISCO
    fi

    if [[ "$SKIP_DISCO" != "y" ]]; then
        echo "--- HYPER-AGGRO DISCOVERY & VULN PROBE ---"
        echo "Step 1: Rapid-fire Wake-up (Fast-Ping)..."
        # High parallelism to wake up sleeping NICs
        nmap -sn -PE -n --min-parallelism 100 "$P_RANGE" > /dev/null 2>&1
        
        echo "Step 2: Nmap ARP Ping Scan ($P_RANGE)..."
        # Clear file and start streaming results live
        > "$TARGET_FILE"
        nmap -sn -PR "$P_RANGE" -oG - | while read -r line; do
            if echo "$line" | grep -q "Host:"; then
                IP=$(echo "$line" | awk '{print $2}')
                echo "[LIVE] Discovered: $IP"
                echo "$IP" >> "$TARGET_FILE"
            fi
        done
    fi
    
    echo -e "\nStep 3: Probing for Service Versions (DNS Chaos)..."
    
    
    while read -r ip; do
        # Immediate visual feedback for the user
        echo -n "[PROBE] Testing $ip... "
        
        # Check if port 53 is open before attempting the heavy dig command
        if nmap -p 53 --open -T4 --host-timeout 1s "$ip" | grep -q "open"; then
            echo -e "\033[32mPort 53 Open\033[0m"
            
            # Attempt DNS version disclosure
            VERSION=$(dig @$ip version.bind CHAOS TXT +short +time=1 | tr -d '"')
            
            if [ -n "$VERSION" ]; then
                echo -e "    \033[34m[!]\033[0m Version Found: \033[31m$VERSION\033[0m"
                if [[ "$VERSION" == *"2.51"* ]]; then
                    echo -e "    \033[41m CRITICAL \033[0m \033[31mPotential CVE-2017-14491 (Dnsmasq RCE)\033[0m"
                fi
            fi
        else
            echo "Skipped (DNS Closed)"
        fi
    done < "$TARGET_FILE"

    echo -e "\nStep 4: Confirmed Windows ARP Neighbors:"
    PREFIX=$(echo $P_IP | cut -d. -f1-3)
    $ARP_EXE -a | grep "$PREFIX" | grep "dynamic"
;;
7)
    echo "--- SMART HYBRID DISCOVERY (COMPLETE MAP) ---"
    
    # 1. The "Floodlight" Poke
    # We use a rapid Nmap 'Ping Sweep' from Linux while 
    # Windows is watching. This forces every device to ARP-reply.
    echo "[POKE] Broadcasting to all potential hosts..."
    # -sn (No port scan), -PR (ARP Ping - the most effective on WiFi)
    nmap -sn -PR --randomize-hosts "$P_RANGE" > /dev/null 2>&1
    
    # Also trigger the Windows broadcast for redundancy
    powershell.exe -Command "ping -n 2 -w 500 ${PREFIX}.255" > /dev/null 2>&1
    
    # 2. Wait 10 seconds for the ARP cache to populate
    for i in {10..1}; do
        echo -ne "[GHOST] Forcing network identification... ${i}s\r"
        sleep 1
    done
    echo -e "\n[GHOST] Extraction started..."

    # 3. Process the Table
    # We pull from the Windows ARP binary again, now that it's "warm"
# 3. Process the Table
    # Ensure PREFIX is set to your ACTUAL WiFi (e.g., 192.168.1)
    # We filter for 'dynamic' to ignore static virtual interfaces
    RAW_DATA=$($ARP_EXE -a | grep "$PREFIX" | grep "dynamic" | awk '{print $1, $2}')

    echo -e "\n[+] Full WiFi Device Map (Subnet: $PREFIX.x):"
    echo "------------------------------------------------------------"
    
    if [ -z "$RAW_DATA" ]; then
        echo "    [!] Error: No physical devices found on $PREFIX.x"
    else
        echo "$RAW_DATA" | while read -r ip mac; do
            CLEAN_MAC=$(echo $mac | tr '-' ':')
            OUI=$(echo ${CLEAN_MAC^^} | cut -c1-8) # Convert to uppercase for matching
            
            # 1. HARDCODED LOCAL CHECK (Instant & Reliable)
            if [[ "$OUI" == "00:15:5D" ]]; then
                VENDOR="Microsoft (WSL/Hyper-V)"
            elif [[ "$CLEAN_MAC" =~ ^(2|6|A|E|22|ce) ]]; then
                # Checking the second character for randomization
                VENDOR="Randomized (Privacy ON)"
            else
                # 2. EXTERNAL API FALLBACK
                VENDOR=$(curl -s --max-time 1 "https://api.macvendors.com/$OUI")
                [ -z "$VENDOR" ] || [[ "$VENDOR" == *"errors"* ]] && VENDOR="Unknown Vendor"
            fi

            printf "[FOUND] %-15s | %-17s | \033[32m%s\033[0m\n" "$ip" "$mac" "$VENDOR"
        done
    fi
;;
8) 
    echo "[SCANNING] Mapping active WiFi devices..."
    
    # 1. Quick Discovery to populate the list
    # We use -n to skip DNS resolution here for maximum speed
    LIVE_TARGETS=$(nmap -sn -n $P_RANGE | grep "Nmap scan report for" | awk '{print $NF}')

    if [ -n "$LIVE_TARGETS" ]; then
        COUNT=$(echo "$LIVE_TARGETS" | wc -l)
	echo "$LIVE_TARGETS"
        echo "[FOUND] $COUNT active devices. Starting Real-Time Deep OS Scan..."
        echo "------------------------------------------------------------"
        
        # 2. Individual OS Probing for immediate feedback
        for TARGET in $LIVE_TARGETS; do
        echo -e "\n[PROBING] Target: \033[1;34m$TARGET\033[0m"
    
    # 1. -F: Scan only top 100 ports (enough for OS fingerprinting)
    # 2. -O: Guess the OS/Hardware
    # 3. --script nbstat: Pulls the "Friendly Name" (Windows/NetBIOS)
    # 4. -T4: Aggressive timing for local networks
    
        # Add --script smb-os-discovery to specifically ask for the Windows version
sudo nmap -F -sV --version-light -O --osscan-guess --script nbstat,smb-os-discovery -T4 "$TARGET" | \
grep -E "Nmap scan report for|OS details|Device type|NetBIOS name|Service Info|OS:|Computer name" | \
sed 's/Nmap scan report for/   [NAME]:/' | \
sed 's/^/  /'
done
        
    else
        echo "[ERROR] No devices found on $P_RANGE. Check your WiFi connection."
    fi
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
