#!/usr/bin/env bash

# --- Color Definitions ---
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Load Environment Variables
[ -f .env ] && source .env

# ---------------------------------------------------------
# CONFIGURATION VALIDATION
# ---------------------------------------------------------
# Map the .env variable to the one used in the notification function
RESULTS_WEBHOOK="${RESULTS_WEBHOOK:-}"
STATUS_WEBHOOK="${STATUS_WEBHOOK:-}"

if [ ! -f .env ]; then
    echo -e "${YELLOW}[!] Warning: .env file not found. Using system environment variables only.${NC}"
else
    [[ -z "${RESULTS_WEBHOOK}" ]] && echo -e "${RED}[!] Critical: RESULTS_WEBHOOK is not set. Notifications will fail.${NC}"
    [[ -z "${CHAOS_KEY:-}" ]] && echo -e "${YELLOW}[!] Note: CHAOS_KEY not found. Chaos discovery will be skipped.${NC}"
fi

# ---------------------------------------------------------
# DEPENDENCY CHECKER
# ---------------------------------------------------------
check_dependencies() {
    local tools=("subfinder" "unfurl" "dnsx" "httpx" "katana" "naabu" "nuclei" "jq" "curl" "gau")
    local missing_tools=()
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}[!] ERROR: The following required tools are not installed:${NC}"
        for mt in "${missing_tools[@]}"; do echo -e "    - $mt"; done
        echo -e "${YELLOW}[?] Run ./install-deps.sh to fix this.${NC}"
        exit 1
    fi
}
check_dependencies

# ---------------------------------------------------------
# ARGUMENT PARSING
# ---------------------------------------------------------
INPUT=""
PASSTHROUGH_ARGS=()

if [[ $# -eq 0 || "$1" == "-h" || "$1" == "--help" ]]; then
    echo -e "${YELLOW}Usage:${NC}"
    echo "  ./scopewatch.sh <target> [options]"
    echo "  <target> can be a single domain (example.com) or a file (list.txt)"
    echo ""
    echo -e "${YELLOW}Pass-through Options (to engine.sh):${NC}"
    echo -e "  ${CYAN}-p, --ports${NC}        Port range or top-ports [Default: 1-65535]"
    echo -e "  ${CYAN}-s, --severity${NC}     Nuclei severities       [Default: info,low,medium,high,critical]"
    echo -e "  ${CYAN}--threads${NC}          Number of threads       [Default: 10]"
    echo -e "  ${CYAN}--rate${NC}             Requests per second     [Default: 60]"
    echo -e "  ${CYAN}--timeout${NC}          Request timeout (sec)   [Default: 15]"
    echo -e "  ${CYAN}--cidr-file${NC}       CIDR range file         [Default: cidr_ranges.txt]"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  ./scopewatch.sh targets.txt --rate 100 --threads 20"
    echo "  ./scopewatch.sh example.com -p 443,8443 -s critical"
    echo ""
    exit 0
fi

INPUT="$1"
shift 
PASSTHROUGH_ARGS=("$@")

# ---------------------------------------------------------
# EXECUTION LOGIC
# ---------------------------------------------------------
run_scan() {
    local target=$1
    echo -e "${CYAN}--------------------------------------------------${NC}"
    echo -e "${GREEN}🚀 SCOPEWATCH: Starting Scan for $target${NC}"
    echo -e "${CYAN}--------------------------------------------------${NC}"

    ./engine.sh -d "$target" "${PASSTHROUGH_ARGS[@]}" < /dev/null || \
    echo -e "${RED}[!] Scan for $target finished with an error.${NC}"
}

if [[ -f "$INPUT" ]]; then
    echo -e "${CYAN}[+] Input detected as FILE: $INPUT${NC}"
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        domain=$(echo "$domain" | tr -d '\r' | xargs)
        [[ -z "$domain" || "$domain" =~ ^# ]] && continue
        run_scan "$domain"
        echo "$(date): Finished $domain" >> scan_history.log
        echo -e "${YELLOW}[*] Finished $domain. Moving to next...${NC}\n"
    done < "$INPUT"
else
    run_scan "$INPUT"
fi

echo -e "${GREEN}✅ ALL SCANS COMPLETE${NC}"
