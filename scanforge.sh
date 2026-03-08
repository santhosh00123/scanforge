#!/bin/sh
# scanforge - Automated multi-host, multi-type nmap scanning with live progress.
#
# Usage:
#   ./scanforge.sh -H <TARGET(s)|hosts.txt> -t <TYPE(s)>
#   ./scanforge.sh -H 10.10.10.1 -t Port,Script,Vulns
#   ./scanforge.sh -H 10.10.10.1,10.10.10.2 -t All
#   ./scanforge.sh -H targets.txt -t Port,Script
#
# Scan types (comma-separate multiple):
#   Network  - Live host discovery across /24 subnet (~15s)
#   Port     - Top-1000 TCP port scan (~15s)
#   Script   - Service version + default scripts on open ports (~5m)
#   Full     - All 65535 TCP ports, then scripts on new ports (~5-10m)
#   UDP      - UDP port scan, requires sudo (~5m)
#   Vulns    - CVE scan (vulners.nse) + nmap vuln scripts (~5-15m)
#   Recon    - Recommends and optionally runs recon tools per service
#   All      - Runs all of the above in sequence (~20-30m)
#
# Optional flags:
#   -r / --remote        Run without local nmap (limited mode)
#   -d / --dns <IP>      Custom DNS server for nmap and resolution
#   -o / --output <DIR>  Override base output directory (default: beside script)
#   -s / --static-nmap   Path to a static nmap binary
#
# Output:
#   One folder per host is created next to the script (or under -o path).
#   All scan results for a single run are merged into one timestamped .txt file:
#     <HOST>/<HOST>_<Types>_<YYYYMMDD_HHMMSS>.txt
#
# Requirements:
#   nmap, standard POSIX sh utilities
#   vulners.nse for CVE scans: https://github.com/vulnersCom/nmap-vulners
#   sudo for UDP scans


RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'
origIFS="${IFS}"

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd -P)"
elapsedStart="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"
REMOTE=false

while [ $# -gt 0 ]; do
        key="$1"
        case "${key}" in
        -H | --host)
                HOST_INPUT="$2"
                shift; shift
                ;;
        -t | --type)
                TYPE_INPUT="$2"
                shift; shift
                ;;
        -d | --dns)
                DNS="$2"
                shift; shift
                ;;
        -o | --output)
                OUTPUTDIR_BASE="$2"
                shift; shift
                ;;
        -s | --static-nmap)
                NMAPPATH="$2"
                shift; shift
                ;;
        -r | --remote)
                REMOTE=true
                shift
                ;;
        *)
                POSITIONAL="${POSITIONAL} $1"
                shift
                ;;
        esac
done
set -- ${POSITIONAL}

if [ -z "${HOST_INPUT}" ]; then HOST_INPUT="$1"; fi
if [ -z "${TYPE_INPUT}" ]; then TYPE_INPUT="$2"; fi

TYPE_INPUT="$(echo "${TYPE_INPUT}" | sed 's/[Qq]uick/Port/g; s/[Bb]asic/Script/g')"

if [ -n "${DNS}" ]; then
        DNSSERVER="${DNS}"
        DNSSTRING="--dns-server=${DNSSERVER}"
else
        DNSSERVER="$(grep 'nameserver' /etc/resolv.conf | grep -v '#' | head -n 1 | awk '{print $NF}')"
        DNSSTRING="--system-dns"
fi

if [ -z "${NMAPPATH}" ] && type nmap >/dev/null 2>&1; then
        NMAPPATH="$(type nmap | awk '{print $NF}')"
elif [ -n "${NMAPPATH}" ]; then
        NMAPPATH="$(cd "$(dirname "${NMAPPATH}")" && pwd -P)/$(basename "${NMAPPATH}")"
        if [ ! -x "${NMAPPATH}" ]; then
                printf "%b\n" "${RED}File is not executable! Attempting chmod +x...${NC}"
                chmod +x "${NMAPPATH}" 2>/dev/null || (printf "%b\n\n" "${RED}Could not chmod. Running in Remote mode...${NC}" && REMOTE=true)
        elif [ "$("${NMAPPATH}" -h 2>/dev/null | head -c4)" != "Nmap" ]; then
                printf "%b\n\n" "${RED}Static binary does not appear to be Nmap! Running in Remote mode...${NC}"
                REMOTE=true
        fi
        printf "%b\n" "${GREEN}Using static nmap binary at ${NMAPPATH}${NC}"
else
        printf "%b\n\n" "${RED}Nmap is not installed and -s is not used. Running in Remote mode...${NC}"
        REMOTE=true
fi

# ---------------------------------------------------------------------------
# Helper: produce one-host-per-line from a comma list or a hosts file.
# ---------------------------------------------------------------------------
build_host_list() {
        if [ -f "$1" ] && [ -r "$1" ]; then
                grep -v '^\s*#' "$1" | grep -v '^\s*$'
        else
                echo "$1" | tr ',' '\n' | tr -d ' ' | grep -v '^$'
        fi
}

build_type_list() {
        echo "$1" | tr ',' '\n' | tr -d ' ' | grep -v '^$'
}

validate_type() {
        case "$1" in
        [Nn]etwork|[Pp]ort|[Ss]cript|[Ff]ull|[Uu][Dd][Pp]|[Vv]ulns|[Rr]econ|[Aa]ll) return 0 ;;
        *) return 1 ;;
        esac
}

validate_host() {
        expr "$1" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null ||
        expr "$1" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null
}

usage() {
        echo
        printf "%b" "${RED}Usage: $(basename "$0") -H/--host ${NC}<TARGET(s) or hosts.txt>${RED} -t/--type ${NC}<TYPE(s)>\n"
        printf "%b" "${YELLOW}Optional: [-r/--remote] [-d/--dns <DNS>] [-o/--output <DIR>] [-s/--static-nmap <PATH>]\n\n"
        printf "Scan Types (comma-separate multiple, e.g. Port,Script,Vulns):\n"
        printf "%b" "${YELLOW}  Network ${NC}: Shows all live hosts in the host network (~15 seconds)\n"
        printf "%b" "${YELLOW}  Port    ${NC}: Shows all open ports (~15 seconds)\n"
        printf "%b" "${YELLOW}  Script  ${NC}: Runs a script scan on found ports (~5 minutes)\n"
        printf "%b" "${YELLOW}  Full    ${NC}: Runs a full range port scan then script scan on new ports (~5-10 minutes)\n"
        printf "%b" "${YELLOW}  UDP     ${NC}: Runs a UDP scan - requires sudo (~5 minutes)\n"
        printf "%b" "${YELLOW}  Vulns   ${NC}: Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)\n"
        printf "%b" "${YELLOW}  Recon   ${NC}: Suggests recon commands then prompts to run them\n"
        printf "%b" "${YELLOW}  All     ${NC}: Runs all the scans (~20-30 minutes)\n"
        printf "%b\n" "${NC}"
        printf "Examples:\n"
        printf "  %s -H 10.10.10.1 -t Port,Script,Vulns\n" "$(basename "$0")"
        printf "  %s -H 10.10.10.1,10.10.10.2 -t Port,Script\n" "$(basename "$0")"
        printf "  %s -H targets.txt -t Full\n" "$(basename "$0")"
        printf "%b\n" "${NC}"
        exit 1
}

# printf-safe separator helpers — prevents "Illegal option --" when string starts with dashes.
print_sep_green()  { printf "%b\n" "${GREEN}$1${NC}"; }
print_sep_yellow() { printf "%b\n" "${YELLOW}$1${NC}"; }

# ---------------------------------------------------------------------------
# init_host_env — run once per host before any scans.
# Sets: kernel, urlIP, subnet, nmapType (-Pn or bare), pingable, ttl, osType
# ---------------------------------------------------------------------------
init_host_env() {
        kernel="$(uname -s)"

        if expr "${HOST}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
                urlIP="$(host -4 -W 1 "${HOST}" ${DNSSERVER} 2>/dev/null \
                        | grep "${HOST}" | head -n 1 | awk '{print $NF}')"
        else
                urlIP=""
        fi

        if expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
                subnet="$(echo "${HOST}" | cut -d '.' -f 1,2,3).0"
        fi

        if [ "${kernel}" = "Linux" ]; then TW="W"; else TW="t"; fi
        pingTest="$(ping -c 1 -"${TW}" 1 "${urlIP:-$HOST}" 2>/dev/null | grep ttl)"

        if [ -z "${pingTest}" ]; then
                nmapType="${NMAPPATH} -Pn"
                pingable=false
                ttl=""
        else
                nmapType="${NMAPPATH}"
                pingable=true
                if expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
                        ttl="$(echo "${pingTest}" | cut -d ' ' -f 6 | cut -d '=' -f 2)"
                else
                        ttl="$(echo "${pingTest}" | cut -d ' ' -f 7 | cut -d '=' -f 2)"
                fi
        fi

        if [ -n "${ttl}" ]; then
                osType="$(checkOS "${ttl}")"
        else
                osType=""
        fi
}

header() {
        echo
        if expr "${TYPE}" : '^\([Aa]ll\)$' >/dev/null; then
                printf "%b" "${YELLOW}Running all scans on ${NC}${HOST}"
        else
                printf "%b" "${YELLOW}Running a ${TYPE} scan on ${NC}${HOST}"
        fi

        if [ -n "${urlIP}" ]; then
                printf "%b\n\n" "${YELLOW} with IP ${NC}${urlIP}"
        else
                printf "\n"
        fi

        if $REMOTE; then
                printf "%b\n" "${YELLOW}Running in Remote mode! Some scans will be limited.${NC}"
        fi

        if ! $pingable; then
                printf "\n%b\n\n" "${YELLOW}No ping detected.. Will not use ping scans!${NC}"
        fi

        if [ -n "${osType}" ]; then
                printf "\n%b\n" "${GREEN}Host is likely running ${osType}${NC}"
        fi

        echo; echo
}

# ---------------------------------------------------------------------------
# assignPorts — re-read port lists from disk into commonPorts / allPorts / udpPorts.
# Called before every scan type so each function sees the latest discovered ports.
# ---------------------------------------------------------------------------
assignPorts() {
        commonPorts=""
        allPorts=""
        udpPorts=""

        if [ -f "${OUTDIR}/Port_$1.nmap" ]; then
                commonPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "${OUTDIR}/Port_$1.nmap" | sed 's/.$//')"
        fi

        if [ -f "${OUTDIR}/Full_$1.nmap" ]; then
                if [ -f "${OUTDIR}/Port_$1.nmap" ]; then
                        allPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "${OUTDIR}/Port_$1.nmap" "${OUTDIR}/Full_$1.nmap" | sed 's/.$//')"
                else
                        allPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "${OUTDIR}/Full_$1.nmap" | sed 's/.$//')"
                fi
        fi

        if [ -f "${OUTDIR}/UDP_$1.nmap" ]; then
                udpPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "${OUTDIR}/UDP_$1.nmap" | sed 's/.$//')"
                [ "${udpPorts}" = "Al" ] && udpPorts=""
        fi
}

# TTL-based OS guess: Linux≈64, Windows≈128, Cisco/OpenBSD≈255
checkOS() {
        case "$1" in
        25[456]) echo "OpenBSD/Cisco/Oracle" ;;
        12[78])  echo "Windows" ;;
        6[34])   echo "Linux" ;;
        *)       echo "Unknown OS!" ;;
        esac
}

cmpPorts() {
        extraPorts="$(echo ",${allPorts}," \
                | sed 's/,\('"$(echo "${commonPorts}" | sed 's/,/,\\|/g')"',\)\+/,/g; s/^,\|,$//g')"
}

progressBar() {
        [ -z "${2##*[!0-9]*}" ] && return 1
        [ "$(stty size 2>/dev/null | cut -d ' ' -f 2)" -le 120 ] && width=50 || width=100
        fill="$(printf "%-$((width == 100 ? $2 : ($2 / 2)))s" "#" | tr ' ' '#')"
        empty="$(printf "%-$((width - (width == 100 ? $2 : ($2 / 2))))s" " ")"
        printf "In progress: %s Scan (%s elapsed - %s remaining)   \n" "$1" "$3" "$4"
        printf "[%s>%s] %s%%%% done   \n" "${fill}" "${empty}" "$2"
        printf "\e[2A"
}

# ---------------------------------------------------------------------------
# nmapProgressBar — launch nmap in background, stream a live progress bar,
# then print a cleaned port table from the output file.
#
# Completion is detected via PID (kill -0), not by polling the output file,
# which avoids the stuck-at-99% race where the process exits before the OS
# flushes the final "Nmap done at" line.
# ---------------------------------------------------------------------------
nmapProgressBar() {
        refreshRate="${2:-1}"
        outputFile="$(echo "$1" | sed -e 's/.*-oN \(.*\).nmap.*/\1/').nmap"
        tmpOutputFile="${outputFile}.tmp"

        _nmapPid=""
        if [ ! -e "${outputFile}" ]; then
                eval "$1 --stats-every ${refreshRate}s" >"${tmpOutputFile}" 2>&1 &
                _nmapPid=$!
        fi

        while true; do
                if [ -n "${_nmapPid}" ]; then
                        if ! kill -0 "${_nmapPid}" 2>/dev/null; then
                                break
                        fi
                else
                        if [ -e "${outputFile}" ] && grep -q "Nmap done at" "${outputFile}"; then
                                break
                        fi
                fi
                if [ -e "${tmpOutputFile}" ] && grep -iq "quitting" "${tmpOutputFile}"; then
                        break
                fi
                scanType="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null \
                        | sed -ne '/elapsed/{s/.*undergoing \(.*\) Scan.*/\1/p}')"
                percent="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null \
                        | sed -ne '/% done/{s/.*About \(.*\)\..*% done.*/\1/p}')"
                elapsed="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null \
                        | sed -ne '/elapsed/{s/Stats: \(.*\) elapsed.*/\1/p}')"
                remaining="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null \
                        | sed -ne '/remaining/{s/.* (\(.*\) remaining.*/\1/p}')"
                progressBar "${scanType:-No}" "${percent:-0}" "${elapsed:-0:00:00}" "${remaining:-0:00:00}"
                sleep "${refreshRate}"
        done

        [ -n "${_nmapPid}" ] && wait "${_nmapPid}" 2>/dev/null

        printf "\033[0K\r\n\033[0K\r\n"

        if [ -e "${outputFile}" ]; then
                sed -n '/PORT.*STATE.*SERVICE/,/^# Nmap/H;${x;s/^\n\|\n[^\n]*\n# Nmap.*//gp}' "${outputFile}" \
                        | awk '!/^SF(:|-).*$/' | grep -v 'service unrecognized despite'
        else
                cat "${tmpOutputFile}"
        fi
        rm -f "${tmpOutputFile}"
}

networkScan() {
        print_sep_green "---------------------Starting Network Scan---------------------"
        echo

        origHOST="${HOST}"
        HOST="${urlIP:-$HOST}"
        if [ "${kernel}" = "Linux" ]; then TW="W"; else TW="t"; fi

        if ! $REMOTE; then
                nmapProgressBar "${nmapType} -T4 --max-retries 1 --max-scan-delay 20 -n -sn -oN ${OUTDIR}/Network_${HOST}.nmap ${subnet}/24"
                printf "%b\n\n" "${YELLOW}Found the following live hosts:${NC}"
                grep -v '#' "${OUTDIR}/Network_${HOST}.nmap" \
                        | grep "$(echo "${subnet}" | sed 's/..$//')" | awk '{print $5}'
        elif $pingable; then
                echo >"${OUTDIR}/Network_${HOST}.nmap"
                for ip in $(seq 0 254); do
                        (ping -c 1 -"${TW}" 1 "$(echo "${subnet}" | sed 's/..$//').$ip" 2>/dev/null \
                                | grep 'stat' -A1 | xargs | grep -v ', 0.*received' \
                                | awk '{print $2}' >>"${OUTDIR}/Network_${HOST}.nmap") &
                done
                wait
                sed -i '/^$/d' "${OUTDIR}/Network_${HOST}.nmap"
                sort -t . -k 3,3n -k 4,4n "${OUTDIR}/Network_${HOST}.nmap"
        else
                printf "%b\n" "${YELLOW}No ping detected.. TCP Network Scan not implemented in Remote mode.${NC}"
        fi

        HOST="${origHOST}"
        echo; echo; echo
}

portScan() {
        print_sep_green "---------------------Starting Port Scan-----------------------"
        echo

        if ! $REMOTE; then
                nmapProgressBar "${nmapType} -T4 --max-retries 1 --max-scan-delay 20 --open -oN ${OUTDIR}/Port_${HOST}.nmap ${HOST} ${DNSSTRING}"
                assignPorts "${HOST}"
        else
                printf "%b\n" "${YELLOW}Port Scan is not implemented yet in Remote mode.${NC}"
        fi

        echo; echo; echo
}

scriptScan() {
        print_sep_green "---------------------Starting Script Scan-----------------------"
        echo

        if ! $REMOTE; then
                assignPorts "${HOST}"
                if [ -z "${commonPorts}" ]; then
                        printf "%b\n" "${YELLOW}No ports in port scan.. Skipping!${NC}"
                else
                        nmapProgressBar "${nmapType} -sCV -p${commonPorts} --open -oN ${OUTDIR}/Script_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                fi

                if [ -f "${OUTDIR}/Script_${HOST}.nmap" ] && grep -q "Service Info: OS:" "${OUTDIR}/Script_${HOST}.nmap"; then
                        serviceOS="$(sed -n '/Service Info/{s/.* \([^;]*\);.*/\1/p;q}' "${OUTDIR}/Script_${HOST}.nmap")"
                        if [ "${osType}" != "${serviceOS}" ]; then
                                osType="${serviceOS}"
                                printf "\n\n%b\n\n" "${GREEN}OS Detection modified to: ${osType}${NC}"
                        fi
                fi
        else
                printf "%b\n" "${YELLOW}Script Scan is not supported in Remote mode.${NC}"
        fi

        echo; echo; echo
}

fullScan() {
        print_sep_green "---------------------Starting Full Scan------------------------"
        echo

        if ! $REMOTE; then
                nmapProgressBar "${nmapType} -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -v --open -oN ${OUTDIR}/Full_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
                assignPorts "${HOST}"

                # Guard: skip follow-up script scan if no ports found — avoids nmap
                # hanging indefinitely when called with an empty -p "" argument.
                if [ -z "${commonPorts}" ]; then
                        if [ -z "${allPorts}" ]; then
                                echo; echo
                                printf "%b\n\n" "${YELLOW}No open ports found in Full scan. Skipping script scan.${NC}"
                        else
                                echo; echo
                                printf "%b\n\n" "${YELLOW}Making a script scan on all ports${NC}"
                                nmapProgressBar "${nmapType} -sCV -p${allPorts} --open -oN ${OUTDIR}/Full_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                                assignPorts "${HOST}"
                        fi
                else
                        cmpPorts
                        if [ -z "${extraPorts}" ]; then
                                echo; echo
                                allPorts=""
                                printf "%b\n\n" "${YELLOW}No new ports found beyond Port scan${NC}"
                        else
                                echo; echo
                                printf "%b\n\n" "${YELLOW}Making a script scan on extra ports: $(echo "${extraPorts}" | sed 's/,/, /g')${NC}"
                                nmapProgressBar "${nmapType} -sCV -p${extraPorts} --open -oN ${OUTDIR}/Full_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                                assignPorts "${HOST}"
                        fi
                fi
        else
                printf "%b\n" "${YELLOW}Full Scan is not implemented yet in Remote mode.${NC}"
        fi

        echo; echo; echo
}

UDPScan() {
        print_sep_green "----------------------Starting UDP Scan------------------------"
        echo

        if ! $REMOTE; then
                if [ "$(id -u)" != "0" ]; then
                        echo "UDP needs to be run as root, running with sudo..."
                        sudo -v
                        echo
                fi

                nmapProgressBar "sudo ${nmapType} -sU --max-retries 1 --open -oN ${OUTDIR}/UDP_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
                assignPorts "${HOST}"

                if [ -n "${udpPorts}" ]; then
                        echo; echo
                        printf "%b\n\n" "${YELLOW}Making a script scan on UDP ports: $(echo "${udpPorts}" | sed 's/,/, /g')${NC}"
                        if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
                                sudo -v
                                nmapProgressBar "sudo ${nmapType} -sCVU --script vulners --script-args mincvss=7.0 -p${udpPorts} --open -oN ${OUTDIR}/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                        else
                                sudo -v
                                nmapProgressBar "sudo ${nmapType} -sCVU -p${udpPorts} --open -oN ${OUTDIR}/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                        fi
                else
                        echo; echo
                        printf "%b\n\n" "${YELLOW}No UDP ports are open${NC}"
                fi
        else
                printf "%b\n" "${YELLOW}UDP Scan is not implemented yet in Remote mode.${NC}"
        fi

        echo; echo; echo
}

vulnsScan() {
        print_sep_green "---------------------Starting Vulns Scan-----------------------"
        echo

        if ! $REMOTE; then
                assignPorts "${HOST}"

                if [ -z "${allPorts}" ] && [ -z "${commonPorts}" ]; then
                        printf "%b\n" "${YELLOW}No ports found. Run Port or Full scan first.${NC}"
                        echo; echo; echo
                        return
                fi

                if [ -z "${allPorts}" ]; then
                        portType="common"; ports="${commonPorts}"
                else
                        portType="all"; ports="${allPorts}"
                fi

                if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
                        printf "%b\n" "${RED}Please install vulners.nse: https://github.com/vulnersCom/nmap-vulners${NC}"
                        printf "%b\n\n" "${RED}Skipping CVE scan!${NC}"
                else
                        printf "%b\n\n" "${YELLOW}Running CVE scan on ${portType} ports${NC}"
                        nmapProgressBar "${nmapType} -sV --script vulners --script-args mincvss=7.0 -p${ports} --open -oN ${OUTDIR}/CVEs_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
                        echo
                fi

                echo
                printf "%b\n" "${YELLOW}Running Vuln scan on ${portType} ports${NC}"
                printf "%b\n\n" "${YELLOW}This may take a while depending on detected services..${NC}"
                nmapProgressBar "${nmapType} -sV --script vuln -p${ports} --open -oN ${OUTDIR}/Vulns_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
        else
                printf "%b\n" "${YELLOW}Vulns Scan is not supported in Remote mode.${NC}"
        fi

        echo; echo; echo
}

recon() {
        IFS="
"
        reconRecommend "${HOST}" | tee "${OUTDIR}/Recon_${HOST}.nmap"
        allRecon="$(grep "${HOST}" "${OUTDIR}/Recon_${HOST}.nmap" | cut -d ' ' -f 1 | sort | uniq)"

        missingTools=""
        for tool in ${allRecon}; do
                if ! type "${tool}" >/dev/null 2>&1; then
                        missingTools="$(printf "%s %s" "${missingTools}" "${tool}" | awk '{$1=$1};1')"
                fi
        done

        if [ -n "${missingTools}" ]; then
                printf "%b\n" "${RED}Missing tools: ${NC}${missingTools}"
                printf "\n%b\n" "${RED}You can install with:${NC}"
                printf "%b\n\n\n" "${YELLOW}sudo apt install ${missingTools} -y${NC}"
                availableRecon="$(echo "${allRecon}" | tr ' ' '\n' \
                        | awk -vORS=', ' '!/'"$(echo "${missingTools}" | tr ' ' '|')"'/' | sed 's/..$//')"
        else
                availableRecon="$(echo "${allRecon}" | tr '\n' ' ' | sed 's/ /, /g; s/, $//')"
        fi

        secs=30
        count=0
        reconCommand=""

        if [ -n "${availableRecon}" ]; then
                while [ "${reconCommand}" != "!" ]; do
                        printf "%b\n" "${YELLOW}Which commands would you like to run?${NC}"
                        printf "All (Default), %s, Skip <!>\n\n" "${availableRecon}"
                        while [ "${count}" -lt "${secs}" ]; do
                                tlimit=$((secs - count))
                                printf "\033[2K\rRunning Default in (%s)s: " "${tlimit}"
                                reconCommand="$(sh -c '{ { sleep 1; kill -sINT $$; } & }; exec head -n 1')"
                                count=$((count + 1))
                                [ -n "${reconCommand}" ] && break
                        done
                        if expr "${reconCommand}" : '^\([Aa]ll\)$' >/dev/null || [ -z "${reconCommand}" ]; then
                                runRecon "${HOST}" "All"
                                reconCommand="!"
                        elif expr " ${availableRecon}," : ".* ${reconCommand}," >/dev/null; then
                                runRecon "${HOST}" "${reconCommand}"
                                reconCommand="!"
                        elif [ "${reconCommand}" = "Skip" ] || [ "${reconCommand}" = "!" ]; then
                                reconCommand="!"
                                echo; echo; echo
                        else
                                printf "\n%b\n\n" "${RED}Incorrect choice!${NC}"
                        fi
                done
        else
                printf "%b\n\n\n" "${YELLOW}No Recon Recommendations found...${NC}"
        fi

        IFS="${origIFS}"
}

reconRecommend() {
        print_sep_green "---------------------Recon Recommendations---------------------"
        echo

        IFS="
"

        if [ -f "${OUTDIR}/Full_Extra_${HOST}.nmap" ]; then
                ports="${allPorts}"
                file="$(cat "${OUTDIR}/Script_${HOST}.nmap" "${OUTDIR}/Full_Extra_${HOST}.nmap" 2>/dev/null \
                        | grep "open" | grep -v '#' | sort | uniq)"
        elif [ -f "${OUTDIR}/Script_${HOST}.nmap" ]; then
                ports="${commonPorts}"
                file="$(grep "open" "${OUTDIR}/Script_${HOST}.nmap" | grep -v '#')"
        else
                file=""
        fi

        if echo "${file}" | grep -q "25/tcp"; then
                printf "\n%b\n\n" "${YELLOW}SMTP Recon:${NC}"
                echo "smtp-user-enum -U /usr/share/wordlists/metasploit/unix_users.txt -t \"${HOST}\" | tee \"${OUTDIR}/smtp_user_enum_${HOST}.txt\""
                echo
        fi

        if echo "${file}" | grep -q "53/tcp" && [ -n "${DNSSERVER}" ]; then
                printf "\n%b\n\n" "${YELLOW}DNS Recon:${NC}"
                echo "host -l \"${HOST}\" \"${DNSSERVER}\" | tee \"${OUTDIR}/hostname_${HOST}.txt\""
                echo "dnsrecon -r \"${subnet}/24\" -n \"${DNSSERVER}\" | tee \"${OUTDIR}/dnsrecon_${HOST}.txt\""
                echo "dnsrecon -r 127.0.0.0/24 -n \"${DNSSERVER}\" | tee \"${OUTDIR}/dnsrecon-local_${HOST}.txt\""
                echo "dig -x \"${HOST}\" @${DNSSERVER} | tee \"${OUTDIR}/dig_${HOST}.txt\""
                echo
        fi

        if echo "${file}" | grep -iq "http"; then
                printf "\n%b\n\n" "${YELLOW}Web Servers Recon:${NC}"
                for line in ${file}; do
                        if echo "${line}" | grep -iq "http"; then
                                port="$(echo "${line}" | cut -d '/' -f 1)"
                                if echo "${line}" | grep -q "ssl/http"; then
                                        urlType='https://'
                                        echo "sslscan \"${HOST}\" | tee \"${OUTDIR}/sslscan_${HOST}_${port}.txt\""
                                        echo "nikto -host \"${urlType}${HOST}:${port}\" -ssl | tee \"${OUTDIR}/nikto_${HOST}_${port}.txt\""
                                else
                                        urlType='http://'
                                        echo "nikto -host \"${urlType}${HOST}:${port}\" | tee \"${OUTDIR}/nikto_${HOST}_${port}.txt\""
                                fi
                                if type ffuf >/dev/null 2>&1; then
                                        extensions="$(echo 'index' >./index && ffuf -s -w ./index:FUZZ -mc '200,302' -e '.asp,.aspx,.html,.jsp,.php' -u "${urlType}${HOST}:${port}/FUZZ" 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/.$//' && rm -f ./index)"
                                        echo "ffuf -ic -w /usr/share/wordlists/dirb/common.txt -e '${extensions}' -u \"${urlType}${HOST}:${port}/FUZZ\" | tee \"${OUTDIR}/ffuf_${HOST}_${port}.txt\""
                                else
                                        extensions="$(echo 'index' >./index && gobuster dir -w ./index -t 30 -qnkx '.asp,.aspx,.html,.jsp,.php' -s '200,302' -u "${urlType}${HOST}:${port}" 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/.$//' && rm -f ./index)"
                                        echo "gobuster dir -w /usr/share/wordlists/dirb/common.txt -t 30 -ekx '${extensions}' -u \"${urlType}${HOST}:${port}\" -o \"${OUTDIR}/gobuster_${HOST}_${port}.txt\""
                                fi
                                echo
                        fi
                done

                if [ -f "${OUTDIR}/Script_${HOST}.nmap" ]; then
                        cms="$(grep http-generator "${OUTDIR}/Script_${HOST}.nmap" | cut -d ' ' -f 2)"
                        if [ -n "${cms}" ]; then
                                for line in ${cms}; do
                                        port="$(sed -n 'H;x;s/\/.*'"${line}"'.*//p' "${OUTDIR}/Script_${HOST}.nmap")"
                                        if ! case "${cms}" in Joomla|WordPress|Drupal) false;; esac; then
                                                printf "\n%b\n\n" "${YELLOW}CMS Recon:${NC}"
                                        fi
                                        case "${cms}" in
                                        Joomla!)   echo "joomscan --url \"${HOST}:${port}\" | tee \"${OUTDIR}/joomscan_${HOST}_${port}.txt\"" ;;
                                        WordPress) echo "wpscan --url \"${HOST}:${port}\" --enumerate p | tee \"${OUTDIR}/wpscan_${HOST}_${port}.txt\"" ;;
                                        Drupal)    echo "droopescan scan drupal -u \"${HOST}:${port}\" | tee \"${OUTDIR}/droopescan_${HOST}_${port}.txt\"" ;;
                                        esac
                                done
                        fi
                fi
        fi

        if [ -f "${OUTDIR}/UDP_Extra_${HOST}.nmap" ] && grep -q "161/udp.*open" "${OUTDIR}/UDP_Extra_${HOST}.nmap"; then
                printf "\n%b\n\n" "${YELLOW}SNMP Recon:${NC}"
                echo "snmp-check \"${HOST}\" -c public | tee \"${OUTDIR}/snmpcheck_${HOST}.txt\""
                echo "snmpwalk -Os -c public -v1 \"${HOST}\" | tee \"${OUTDIR}/snmpwalk_${HOST}.txt\""
                echo
        fi

        if echo "${file}" | grep -q "389/tcp"; then
                printf "\n%b\n\n" "${YELLOW}ldap Recon:${NC}"
                echo "ldapsearch -x -h \"${HOST}\" -s base | tee \"${OUTDIR}/ldapsearch_${HOST}.txt\""
                echo "ldapsearch -x -h \"${HOST}\" -b \"\$(grep rootDomainNamingContext \"${OUTDIR}/ldapsearch_${HOST}.txt\" | cut -d ' ' -f2)\" | tee \"${OUTDIR}/ldapsearch_DC_${HOST}.txt\""
                echo "nmap -Pn -p 389 --script ldap-search --script-args 'ldap.username=\"\$(grep rootDomainNamingContext \"${OUTDIR}/ldapsearch_${HOST}.txt\" | cut -d \" \" -f2)\"' \"${HOST}\" -oN \"${OUTDIR}/nmap_ldap_${HOST}.txt\""
                echo
        fi

        if echo "${file}" | grep -q "445/tcp"; then
                printf "\n%b\n\n" "${YELLOW}SMB Recon:${NC}"
                echo "smbmap -H \"${HOST}\" | tee \"${OUTDIR}/smbmap_${HOST}.txt\""
                echo "smbclient -L \"//${HOST}/\" -U \"guest\"% | tee \"${OUTDIR}/smbclient_${HOST}.txt\""
                if [ "${osType}" = "Windows" ]; then
                        echo "nmap -Pn -p445 --script vuln -oN \"${OUTDIR}/SMB_vulns_${HOST}.txt\" \"${HOST}\""
                elif [ "${osType}" = "Linux" ]; then
                        echo "enum4linux -a \"${HOST}\" | tee \"${OUTDIR}/enum4linux_${HOST}.txt\""
                fi
                echo
        elif echo "${file}" | grep -q "139/tcp" && [ "${osType}" = "Linux" ]; then
                printf "\n%b\n\n" "${YELLOW}SMB Recon:${NC}"
                echo "enum4linux -a \"${HOST}\" | tee \"${OUTDIR}/enum4linux_${HOST}.txt\""
                echo
        fi

        if echo "${file}" | grep -q "1521/tcp"; then
                printf "\n%b\n\n" "${YELLOW}Oracle Recon:${NC}"
                echo "odat sidguesser -s \"${HOST}\" -p 1521"
                echo "odat passwordguesser -s \"${HOST}\" -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt"
                echo
        fi

        IFS="${origIFS}"
        echo; echo; echo
}

runRecon() {
        echo; echo; echo
        print_sep_green "---------------------Running Recon Commands--------------------"
        echo

        IFS="
"
        mkdir -p ${OUTDIR}/

        if [ "$2" = "All" ]; then
                reconCommands="$(grep "${HOST}" "${OUTDIR}/Recon_${HOST}.nmap")"
        else
                reconCommands="$(grep "${HOST}" "${OUTDIR}/Recon_${HOST}.nmap" | grep "$2")"
        fi

        for line in ${reconCommands}; do
                currentScan="$(echo "${line}" | cut -d ' ' -f 1)"
                fileName="$(echo "${line}" | awk -F '${OUTDIR}/' '{print $2}')"
                if [ -n "${fileName}" ] && [ ! -f "${OUTDIR}/${fileName}" ]; then
                        printf "\n%b\n\n" "${YELLOW}Starting ${currentScan} scan${NC}"
                        eval "${line}"
                        printf "\n%b\n" "${YELLOW}Finished ${currentScan} scan${NC}"
                        printf "%b\n" "${YELLOW}=========================${NC}"
                fi
        done

        IFS="${origIFS}"
        echo; echo; echo
}

footer() {
        print_sep_green "---------------------Finished all scans------------------------"
        echo

        elapsedEnd="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"
        elapsedSeconds=$((elapsedEnd - elapsedStart))

        if [ "${elapsedSeconds}" -gt 3600 ]; then
                hours=$((elapsedSeconds / 3600))
                minutes=$(((elapsedSeconds % 3600) / 60))
                seconds=$(((elapsedSeconds % 3600) % 60))
                printf "%b\n" "${YELLOW}Completed in ${hours} hour(s), ${minutes} minute(s) and ${seconds} second(s)${NC}"
        elif [ "${elapsedSeconds}" -gt 60 ]; then
                minutes=$(((elapsedSeconds % 3600) / 60))
                seconds=$(((elapsedSeconds % 3600) % 60))
                printf "%b\n" "${YELLOW}Completed in ${minutes} minute(s) and ${seconds} second(s)${NC}"
        else
                printf "%b\n" "${YELLOW}Completed in ${elapsedSeconds} seconds${NC}"
        fi
        echo
}

# ---------------------------------------------------------------------------
# run_scan_type — dispatch one scan type for the current $HOST.
# assignPorts() is called first so every scan sees up-to-date port data.
# Script / Vulns / Recon auto-run Port (and Script) as prerequisites when
# their required output files are absent.
# run_scan_type is called directly (no pipe) to stay in the same shell process —
# piping into tee would create a subshell, losing background PIDs and variable
# updates that cross scan-type boundaries.
# ---------------------------------------------------------------------------
run_scan_type() {
        _t="$1"
        assignPorts "${HOST}"

        case "${_t}" in
        [Nn]etwork) networkScan ;;
        [Pp]ort)    portScan ;;
        [Ss]cript)
                [ ! -f "${OUTDIR}/Port_${HOST}.nmap" ] && portScan
                assignPorts "${HOST}"
                scriptScan
                ;;
        [Ff]ull) fullScan ;;
        [Uu][Dd][Pp]) UDPScan ;;
        [Vv]ulns)
                [ ! -f "${OUTDIR}/Port_${HOST}.nmap" ] && portScan
                assignPorts "${HOST}"
                vulnsScan
                ;;
        [Rr]econ)
                [ ! -f "${OUTDIR}/Port_${HOST}.nmap" ]   && portScan
                assignPorts "${HOST}"
                [ ! -f "${OUTDIR}/Script_${HOST}.nmap" ] && scriptScan
                assignPorts "${HOST}"
                recon
                ;;
        [Aa]ll)
                portScan;   assignPorts "${HOST}"
                scriptScan; assignPorts "${HOST}"
                fullScan;   assignPorts "${HOST}"
                UDPScan;    assignPorts "${HOST}"
                vulnsScan;  assignPorts "${HOST}"
                recon
                ;;
        esac
}

# ---------------------------------------------------------------------------
# main_multi — outer loop: every host x every scan type.
# Per-host output structure:
#   <OUTDIR>/<HOST>/<HOST>_<Types>_<YYYYMMDD_HHMMSS>.txt  (one file per run)
# Raw .nmap work files are merged into that single file then deleted.
# ---------------------------------------------------------------------------
main_multi() {
        HOST_LIST="$(build_host_list "${HOST_INPUT}")"
        TYPE_LIST="$(build_type_list "${TYPE_INPUT}")"

        host_count="$(echo "${HOST_LIST}" | grep -c .)"
        type_count="$(echo "${TYPE_LIST}"  | grep -c .)"

        TYPE_LABEL="$(echo "${TYPE_INPUT}" | tr ',' '-' | tr -d ' ')"

        if [ "${host_count}" -gt 1 ] || [ "${type_count}" -gt 1 ]; then
                printf "\n%b\n" "${GREEN}========================================================"
                printf " scanforge  |  Hosts: %s  |  Scan types: %s\n" "${host_count}" "${type_count}"
                printf "%b\n\n" "========================================================${NC}"
        fi

        for HOST in $(echo "${HOST_LIST}"); do
                if ! validate_host "${HOST}"; then
                        printf "%b\n" "${RED}Skipping invalid host: ${HOST}${NC}"
                        continue
                fi

                if [ -n "${OUTPUTDIR_BASE}" ]; then
                        OUTDIR="${OUTPUTDIR_BASE}/${HOST}"
                else
                        OUTDIR="${SCRIPTDIR}/${HOST}"
                fi

                RUN_TS="$(date '+%Y%m%d_%H%M%S')"
                RUNFILE="${OUTDIR}/${HOST}_${TYPE_LABEL}_${RUN_TS}.txt"

                mkdir -p "${OUTDIR}" || {
                        printf "%b\n" "${RED}Cannot create output dir ${OUTDIR}. Skipping.${NC}"
                        continue
                }

                {
                        printf "=========================================================\n"
                        printf " scanforge  |  Host: %s  |  Types: %s\n" "${HOST}" "${TYPE_LABEL}"
                        printf " Started: %s\n" "$(date)"
                        printf "=========================================================\n\n"
                } > "${RUNFILE}"

                printf "%b\n" "${GREEN}Output directory : ${OUTDIR}${NC}"
                printf "%b\n" "${GREEN}Run output file  : ${RUNFILE}${NC}"

                commonPorts=""; allPorts=""; udpPorts=""
                urlIP=""; osType=""; nmapType="${NMAPPATH}"; pingable=false
                subnet=""; kernel=""; ttl=""

                init_host_env
                assignPorts "${HOST}"

                if [ "${host_count}" -gt 1 ]; then
                        printf "\n%b\n" "${GREEN}--------------------------------------------------------"
                        printf " Starting scans for host: %s\n" "${HOST}"
                        printf "%b\n\n" "--------------------------------------------------------${NC}"
                fi

                # Snapshot files that already exist so we only append NEW results to RUNFILE.
                _pre_files=""
                for _f in \
                        "${OUTDIR}/Port_${HOST}.nmap" \
                        "${OUTDIR}/Script_${HOST}.nmap" \
                        "${OUTDIR}/Full_${HOST}.nmap" \
                        "${OUTDIR}/Full_Extra_${HOST}.nmap" \
                        "${OUTDIR}/UDP_${HOST}.nmap" \
                        "${OUTDIR}/UDP_Extra_${HOST}.nmap" \
                        "${OUTDIR}/CVEs_${HOST}.nmap" \
                        "${OUTDIR}/Vulns_${HOST}.nmap" \
                        "${OUTDIR}/Network_${HOST}.nmap" \
                        "${OUTDIR}/Recon_${HOST}.nmap"; do
                        [ -f "${_f}" ] && _pre_files="${_pre_files} ${_f}"
                done

                first_type=true
                for TYPE in $(echo "${TYPE_LIST}"); do
                        if ! validate_type "${TYPE}"; then
                                printf "%b\n" "${RED}Skipping invalid scan type: ${TYPE}${NC}"
                                continue
                        fi

                        if $first_type; then
                                header
                                first_type=false
                        else
                                printf "\n%b\n\n" "${YELLOW}--- Next scan type: ${TYPE} on ${HOST} ---${NC}"
                        fi

                        run_scan_type "${TYPE}"
                done

                {
                        printf "\n=========================================================\n"
                        printf " SCAN RESULTS\n"
                        printf "=========================================================\n\n"
                } >> "${RUNFILE}"

                for _f in \
                        "${OUTDIR}/Network_${HOST}.nmap" \
                        "${OUTDIR}/Port_${HOST}.nmap" \
                        "${OUTDIR}/Script_${HOST}.nmap" \
                        "${OUTDIR}/Full_${HOST}.nmap" \
                        "${OUTDIR}/Full_Extra_${HOST}.nmap" \
                        "${OUTDIR}/UDP_${HOST}.nmap" \
                        "${OUTDIR}/UDP_Extra_${HOST}.nmap" \
                        "${OUTDIR}/CVEs_${HOST}.nmap" \
                        "${OUTDIR}/Vulns_${HOST}.nmap" \
                        "${OUTDIR}/Recon_${HOST}.nmap"; do
                        if [ -f "${_f}" ]; then
                                _is_pre=false
                                for _p in ${_pre_files}; do
                                        [ "${_p}" = "${_f}" ] && _is_pre=true && break
                                done
                                if ! $_is_pre; then
                                        printf "### %s ###\n" "$(basename "${_f}")" >> "${RUNFILE}"
                                        cat "${_f}" >> "${RUNFILE}"
                                        printf "\n" >> "${RUNFILE}"
                                        rm -f "${_f}"
                                fi
                        fi
                done

                {
                        printf "\n=========================================================\n"
                        printf " Finished: %s\n" "$(date)"
                        printf "=========================================================\n"
                } >> "${RUNFILE}"

                footer
                printf "%b\n\n" "${GREEN}All output saved to: ${RUNFILE}${NC}"
        done
}

if [ -z "${TYPE_INPUT}" ] || [ -z "${HOST_INPUT}" ]; then
        usage
fi

_bad_types=""
for _t in $(build_type_list "${TYPE_INPUT}"); do
        validate_type "${_t}" || _bad_types="${_bad_types} ${_t}"
done
if [ -n "${_bad_types}" ]; then
        printf "%b\n" "${RED}Invalid scan type(s):${_bad_types}${NC}"
        usage
fi

if [ ! -f "${HOST_INPUT}" ]; then
        for _h in $(build_host_list "${HOST_INPUT}"); do
                if ! validate_host "${_h}"; then
                        printf "%b\n" "${RED}Invalid IP or URL: ${_h}${NC}"
                        usage
                fi
        done
fi

main_multi
