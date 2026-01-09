#!/usr/bin/env bash
# ScopeWatch
# Flow: Discovery -> Force Root -> Resolution -> Katana -> Httpx -> CIDR Filter -> Naabu -> Nuclei -> Reporting

[ -f .env ] && source .env

# ---------------------------------------------------------
# CONFIGURATION VALIDATION
# ---------------------------------------------------------
if [ ! -f .env ]; then
    echo -e "${YELLOW}[!] Warning: .env file not found. Using system environment variables only.${NC}"
else
    # Check if critical keys are still empty after sourcing .env
    if [[ -z "${RESULTS_WEBHOOK:-}" ]]; then
        echo -e "${RED}[!] Critical: RESULTS_WEBHOOK is not set. Notifications will fail.${NC}"
    fi
    if [[ -z "${CHAOS_KEY:-}" ]]; then
        echo -e "${YELLOW}[!] Note: CHAOS_KEY not found. Chaos discovery will be skipped.${NC}"
    fi
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
        for mt in "${missing_tools[@]}"; do
            echo -e "    - $mt"
        done
        echo -e "${YELLOW}[?] Install them via: go install github.com/projectdiscovery/toolname/v2/cmd/toolname@latest${NC}"
        exit 1
    fi
}

# Run the check immediately
check_dependencies

set -euo pipefail
IFS=$'\n\t'

# ---------------- Color Definitions ----------------
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ---------------------------------------------------------
# 1. HARD DEFAULTS (Baseline)
# ---------------------------------------------------------
# These are the "Sane Defaults" if the user provides NO flags.
OUTROOT="./output"
THREADS=10
RATE=60
TIMEOUT=15
PORT_RANGE="1-65535"
SEVERITIES="info,low,medium,high,critical"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESOLVERS="$SCRIPT_DIR/resolvers.txt"
CIDR_FILE="cidr_ranges.txt"

# Pull secrets/keys from Environment Variables only
CHAOS_KEY="${CHAOS_KEY:-}"
RESULTS_WEBHOOK="${RESULTS_WEBHOOK:-}"
STATUS_WEBHOOK="${STATUS_WEBHOOK:-}"
DISCORD_USER_ID="${DISCORD_USER_ID:-}"

# Initialize empty vars for required inputs
DOMAIN=""
SUBFILE=""

# ---------------------------------------------------------
# 2. ARGUMENT PARSING (User Overrides)
# ---------------------------------------------------------
# This loop listens to the user. If they use a flag, it 
# replaces the hard defaults set above.
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain)    DOMAIN="$2";      shift 2 ;;
    -f|--file)      SUBFILE="$2";     shift 2 ;;
    -p|--ports)     PORT_RANGE="$2";  shift 2 ;;
    -s|--severity)  SEVERITIES="$2";  shift 2 ;;
    --threads)      THREADS="$2";     shift 2 ;;
    --rate)         RATE="$2";        shift 2 ;;
    --timeout)      TIMEOUT="$2";     shift 2 ;;
    --cidr-file)    CIDR_FILE="$2";   shift 2 ;;
    -h|--help)
      cat <<EOF
Usage: $0 -d example.com [options]

Options:
  -d, --domain      Target domain
  -f, --file        File containing subdomains
  -p, --ports       Port range (e.g., 80,443)
  -s, --severity    Nuclei severities
  --threads         Scan threads
  --rate            Rate limit (RPS)
  --timeout         Request timeout
  --cidr-file       Scan specific IP ranges
EOF
      exit 0 ;;
    *) 
      # If it's the first argument and doesn't start with -, assume it's the domain
      if [[ -z "$DOMAIN" && ! "$1" =~ ^- ]]; then
          DOMAIN="$1"
          shift
      else
          echo -e "${YELLOW}[!] Skipping unknown argument: $1${NC}"
          shift
      fi
      ;;
  esac
done

# ---------------------------------------------------------
# 3. SCAN CONFIGURATION SUMMARY
# ---------------------------------------------------------
echo -e "${YELLOW}--------------------------------------------------${NC}"
echo -e "${GREEN}🔎 SCAN CONFIGURATION CONFIRMED${NC}"
echo -e "${YELLOW}--------------------------------------------------${NC}"
echo -e "Target:       ${CYAN}${DOMAIN:-$SUBFILE}${NC}"
echo -e "Rate Limit:   ${CYAN}$RATE${NC}"
echo -e "Threads:      ${CYAN}$THREADS${NC}"
echo -e "Timeout:      ${CYAN}${TIMEOUT}s${NC}"
echo -e "Ports:        ${CYAN}$PORT_RANGE${NC}"
echo -e "Severities:   ${CYAN}$SEVERITIES${NC}"
echo -e "CIDR Filter:  ${CYAN}$CIDR_FILE${NC}"
echo -e "Discord:      $( [[ -n "$RESULTS_WEBHOOK" ]] && echo -e "${GREEN}Enabled${NC}" || echo -e "${RED}Disabled${NC}" )"
echo -e "${YELLOW}--------------------------------------------------${NC}"
echo ""

# Small pause to allow the user to read/cancel
sleep 2

# ---------------- Paths ----------------
START_TIME=$(date +%s)
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
TARGET="${DOMAIN:-$(basename "$SUBFILE" .txt)}"
OUTDIR="${OUTROOT}/${TARGET}.${TIMESTAMP}"
mkdir -p "$OUTDIR"

NAMES_FILE="$OUTDIR/names.txt"
HOSTS_FILE="$OUTDIR/hosts.txt"
LIVE_URLS="$OUTDIR/live_urls.txt"
NAABU_HOSTS="$OUTDIR/hosts_for_naabu.txt"
NUCLEI_OUT="$OUTDIR/nuclei.jsonl"
NAABU_OUT_JSON="$OUTDIR/naabu.json"
REPORT_FILE="$OUTDIR/vulnerabilities.txt"

# Function to send status updates to the status channel
send_status() {
    if [[ -n "$STATUS_WEBHOOK" ]]; then
        curl -s -X POST -H 'Content-Type: application/json' \
        -d "{\"content\": \"🛰️ **$1** ($TARGET)\"}" "$STATUS_WEBHOOK" > /dev/null
    fi
}

# ---------------- Resolver list refresh ----------------
if [[ ! -s "$RESOLVERS" ]]; then
    echo -e "${YELLOW}[+] Downloading fresh resolvers...${NC}"
    if ! curl -m 10 -fsSL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -o "$RESOLVERS"; then
        echo -e "${RED}[!] Download failed. Creating emergency fallback resolvers...${NC}"
        {
            echo "8.8.8.8"
            echo "8.8.4.4"
            echo "1.1.1.1"
            echo "1.0.0.1"
        } > "$RESOLVERS"
    fi
fi

# ---------------- Stage 1: Discovery (Root Focus) ----------------
send_status "Scan Initiated: Starting discovery..."
echo -e "${CYAN}[+] Starting Advanced Discovery for: $DOMAIN${NC}"

if [[ -n "$DOMAIN" ]]; then
    subfinder -d "$DOMAIN" -all -recursive -silent -o "$OUTDIR/subfinder.txt" || true

    if command -v gau >/dev/null 2>&1; then
        echo -e "${CYAN}[*] Fetching historical archive names via GAU...${NC}"
        gau --subs --threads "$THREADS" "$DOMAIN" 2>/dev/null \
            | unfurl -u domains \
            | sort -u > "$OUTDIR/gau_names.txt" || true
    fi

    if command -v chaos >/dev/null 2>&1; then
        if [[ -n "$CHAOS_KEY" ]]; then
            echo -e "${CYAN}[*] Fetching Chaos results...${NC}"
            chaos -d "$DOMAIN" -silent -key "$CHAOS_KEY" -o "$OUTDIR/chaos.txt" || true
        else
            echo -e "${YELLOW}[!] Chaos key not set. Skipping Chaos...${NC}"
        fi
    fi

else
    cp "$SUBFILE" "$OUTDIR/subfinder.txt"
fi

{
  [[ -f "$OUTDIR/subfinder.txt" ]] && cat "$OUTDIR/subfinder.txt"
  [[ -f "$OUTDIR/chaos.txt" ]] && cat "$OUTDIR/chaos.txt"
  [[ -f "$OUTDIR/gau_names.txt" ]] && cat "$OUTDIR/gau_names.txt"
  echo "$DOMAIN"
  echo "www.$DOMAIN"
} | sed 's/^\*\.//' | tr -d ' ' | grep -v '^$' | sort -u > "$NAMES_FILE"

# ---------------- Stage 2: DNS Resolution ----------------
echo -e "${CYAN}[+] Resolving names with dnsx...${NC}"
dnsx -l "$NAMES_FILE" -r "$RESOLVERS" -rl "$RATE" -a -resp-only -silent -retry 2 -o "$OUTDIR/resolved_ips_raw.txt" || true
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$OUTDIR/resolved_ips_raw.txt" 2>/dev/null | sort -u > "$HOSTS_FILE" || touch "$HOSTS_FILE"

if [[ ! -s "$HOSTS_FILE" ]]; then
    echo -e "${YELLOW}[!] dnsx failed. Trying system fallback...${NC}"
    host "$DOMAIN" | grep "has address" | awk '{print $4}' >> "$HOSTS_FILE" || true
    host "www.$DOMAIN" | grep "has address" | awk '{print $4}' >> "$HOSTS_FILE" || true
    sort -u "$HOSTS_FILE" -o "$HOSTS_FILE"
fi

# ---------------- Stage 3: Httpx Probing (Basic) ----------------
echo -e "${CYAN}[+] Probing with httpx (Validating FQDN)...${NC}"
httpx -l "$NAMES_FILE" -t "$THREADS" -timeout "$TIMEOUT" \
    -follow-redirects -silent \
    -o "$OUTDIR/http_live_simple.txt" || true

cat "$OUTDIR/http_live_simple.txt" | awk '{print $1}' | sort -u > "$LIVE_URLS"

# ---------------- Stage 4: Katana & Validation ----------------
if command -v katana >/dev/null 2>&1 && [[ -s "$LIVE_URLS" ]]; then
    echo -e "${CYAN}[+] Katana: Deep JS & Endpoint Crawl...${NC}"
    katana -list "$LIVE_URLS" -d 3 -jc -kf all -silent -duc -crawl-duration 3m -o "$OUTDIR/katana_raw.txt" || true
    
    if [[ -s "$OUTDIR/katana_raw.txt" ]]; then
        echo -e "${CYAN}[+] Validating Katana findings...${NC}"
        httpx -l "$OUTDIR/katana_raw.txt" -t "$THREADS" -fc 404 \
            -title -status-code -cl -follow-redirects \
            -silent -o "$OUTDIR/katana_live.txt"
        
        cat "$OUTDIR/katana_live.txt"
        
        awk '{print $1}' "$OUTDIR/katana_live.txt" >> "$LIVE_URLS"
        sort -u "$LIVE_URLS" -o "$LIVE_URLS"
        
        echo -e "${GREEN}[+] Total verified live URLs: $(wc -l < "$LIVE_URLS")${NC}"
    fi
fi

# ---------------- Stage 5: CIDR & Naabu ----------------
send_status "Scan Progress: Starting naabu..."
echo -e "${CYAN}[+] Applying CIDR filtering...${NC}"
[[ ! -f "$CIDR_FILE" || ! -s "$CIDR_FILE" ]] && cp "$HOSTS_FILE" "$NAABU_HOSTS" || {
    python3 -c "
import ipaddress as ip
nets = [ip.ip_network(l.strip(),0) for l in open('$CIDR_FILE') if l.strip()]
ips = [l.strip() for l in open('$HOSTS_FILE') if l.strip()]
in_s = [i for i in ips if any(ip.ip_address(i) in n for n in nets)]
out_s = list(set(ips) - set(in_s))
print('\nIn-Scope IPs:'); [print(f' - {i}') for i in in_s]
print('\nOut-of-Scope IPs:'); [print(f' - {i}') for i in out_s]
open('$NAABU_HOSTS','w').write('\n'.join(in_s))
"
}

if [[ -s "$NAABU_HOSTS" ]]; then
    # Start with the standard port flag
    PORT_FLAG="-p"
    FINAL_PORTS="$PORT_RANGE"

    # Smart Port Logic:
    # 1. If input is 'full', Naabu likes '-p full'
    # 2. If input is just a number (e.g., 100), use '-top-ports'
    if [[ "$PORT_RANGE" =~ ^[0-9]+$ ]]; then
        PORT_FLAG="-top-ports"
        FINAL_PORTS="$PORT_RANGE"
    fi

    echo -e "${CYAN}\n[+] Naabu: Discovering ports ($FINAL_PORTS) and fingerprinting with Nmap...${NC}"
    
    # Dynamically pass the flag ($PORT_FLAG) and the value ($FINAL_PORTS)
    naabu -list "$NAABU_HOSTS" "$PORT_FLAG" "$FINAL_PORTS" -rate "$RATE" \
        -nmap-cli "nmap -sV --version-intensity 0" \
        -stats -silent -si 30 -json -o "$NAABU_OUT_JSON"
fi

# ---------------- Stage 6: Nuclei ----------------
send_status "Scan Progress: Starting nuclei..."
echo -e "${CYAN}[+] Preparing targets for Nuclei...${NC}"
TARGETS_FOR_NUCLEI="$OUTDIR/targets_for_nuclei.txt"
> "$TARGETS_FOR_NUCLEI"
[[ -s "$LIVE_URLS" ]] && cat "$LIVE_URLS" | sed -E 's|^(https?://[^/]+).*|\1|' >> "$TARGETS_FOR_NUCLEI"
[[ -s "$NAABU_OUT_JSON" ]] && jq -r '"\(.ip):\(.port)"' "$NAABU_OUT_JSON" 2>/dev/null >> "$TARGETS_FOR_NUCLEI" || true
sort -u "$TARGETS_FOR_NUCLEI" -o "$TARGETS_FOR_NUCLEI"

if [[ -s "$TARGETS_FOR_NUCLEI" ]]; then
    echo -e "${CYAN}[+] Running Nuclei with severity: $SEVERITIES...${NC}"
    on_progress=false
    
    nuclei -l "$TARGETS_FOR_NUCLEI" -severity "$SEVERITIES" \
        -rl "$RATE" -stats -si 30 -jsonl -silent -no-color -o "$NUCLEI_OUT" 2>&1 | \
        sed -u 's/\x1B\[[0-9;]*[JKmsu]//g' | while read -r line; do
        
        # 1. Handle Progress Stat
        if echo "$line" | grep -q '"duration"'; then
            duration=$(echo "$line" | jq -r '.duration // "0:00:00"')
            percent=$(echo "$line" | jq -r '.percent // "0"')
            printf "\r\033[K\033[34m[*] Progress: %s%% | Duration: %s\033[0m" "$percent" "$duration"
            on_progress=true
            
        # 2. Handle Finding
        elif echo "$line" | grep -q '"template-id"'; then
            if [ "$on_progress" = true ]; then
                printf "\n"
                on_progress=false
            fi
            
        # Inside Stage 6 Loop Handle Finding:
        echo "$line" | jq -C -r '
            select(."template-id" != null) |
            .matched_at as $m | 
            .host as $h | 
            .ip as $i | 
            (.extracted_results | if . == null then "" else join(", ") end) as $ext |
            (if ($m != null and $m != "") then $m else (if ($h != null and $h != "") then $h else $i end) end) as $t | 
            "[\(.info.severity|ascii_upcase)] \($t) - \(.info.name)" + (if ($ext != "") then " [\($ext)]" else "" end)
        '
        fi
    done
    echo -e "${GREEN}\n[+] Nuclei scan complete.${NC}"
fi

# ---------------- Stage 7: Human-Readable Report ----------------
echo -e "${CYAN}[+] Generating Human-Readable Report...${NC}"

{
    echo "VULNERABILITY REPORT - $(date)"
    echo "Target: $DOMAIN"
    echo "--------------------------------------------------------------------------------"
} > "$REPORT_FILE"

if [ -s "$NUCLEI_OUT" ]; then
    jq -r '
        select(."template-id" != null) |
        .info.severity as $s | 
        .info.name as $n | 
        (."matched-at" // .matched_at // .host // .ip) as $t | 
        
        # Priority Logic for Info Column
        (."matcher-name" // ."matcher_name") as $m |
        (."extracted-results" // .extracted_results | if . == null then "" else join(", ") end) as $ext |
        
        # If matcher exists, use it. If not, use extracted results.
        (if ($m != null and $m != "") then $m else $ext end) as $final_info |
        
        # Output format with a trailing newline for spacing
        "[\($s|ascii_upcase)] | \($n) | \($t)" + (if ($final_info != "") then " | \($final_info)" else "" end) + "\n"
    ' "$NUCLEI_OUT" | sort -u >> "$REPORT_FILE"
    
    echo -e "${GREEN}[*] Report finalized at: $REPORT_FILE${NC}"
else
    echo -e "${YELLOW}[!] No vulnerabilities identified.${NC}"
    echo -e "[!] No vulnerabilities were identified during this scan.\n" >> "$REPORT_FILE"
fi

# ---------------- Stage 8: Cleanup ----------------
echo -e "${YELLOW}[+] Cleaning up...${NC}"
TEMP_FILES=(
    "$OUTDIR/subfinder.txt" 
    "$OUTDIR/chaos.txt" 
    "$OUTDIR/gau_names.txt" 
    "$OUTDIR/resolved_ips_raw.txt" 
    "$OUTDIR/http_live_simple.txt" 
    "$OUTDIR/katana_raw.txt" 
    "$OUTDIR/katana_live.txt" 
    "$OUTDIR/targets_for_nuclei.txt"
    "$OUTDIR/resume.cfg"
)
for f in "${TEMP_FILES[@]}"; do [[ -f "$f" ]] && rm "$f"; done

# ---------------- Stage 9: Discord Notification ----------------
send_status "Scan Finished!"

if [[ -n "${RESULTS_WEBHOOK:-}" ]]; then
    echo -e "${CYAN}[+] Calculating metrics and sending to Discord...${NC}"
    
    # 1. Calculate Duration
    END_TIME=$(date +%s)
    SECONDS_ELAPSED=$((END_TIME - START_TIME))
    DURATION="$((SECONDS_ELAPSED / 60))m $((SECONDS_ELAPSED % 60))s"

    # 2. Path
    FULL_PATH=$(readlink -f "$OUTDIR")

    # 3. Counts (Ensures 0 if file is missing/empty)
    SUB_COUNT=$([ -f "$NAMES_FILE" ] && wc -l < "$NAMES_FILE" | tr -d '[:space:]' || echo "0")
    URL_COUNT=$([ -f "$LIVE_URLS" ] && wc -l < "$LIVE_URLS" | tr -d '[:space:]' || echo "0")
    PORT_COUNT=$([ -s "$NAABU_OUT_JSON" ] && jq -s 'length' "$NAABU_OUT_JSON" || echo "0")

    # 4. Vulnerabilities (Fixed Logic)
    CRI=$(grep -ic "\[CRITICAL\]" "$REPORT_FILE" 2>/dev/null || true); CRI=${CRI:-0}
    HIG=$(grep -ic "\[HIGH\]" "$REPORT_FILE" 2>/dev/null || true); HIG=${HIG:-0}
    MED=$(grep -ic "\[MEDIUM\]" "$REPORT_FILE" 2>/dev/null || true); MED=${MED:-0}
    LOW=$(grep -ic "\[LOW\]" "$REPORT_FILE" 2>/dev/null || true); LOW=${LOW:-0}
    INF=$(grep -ic "\[INFO\]" "$REPORT_FILE" 2>/dev/null || true); INF=${INF:-0}

    # 5. Discord Styling
    USER_PING=""
    [[ -n "$DISCORD_USER_ID" ]] && USER_PING="<@$DISCORD_USER_ID>"
    
    # Default to Green (Info/Safe)
    COLOR=3066993 
    ALERT_MSG="✅ Scan completed successfully."

    # Logic to change color based on findings
    if [ "$CRI" -gt 0 ]; then
        COLOR=15158332 # Red
        ALERT_MSG="⚠️ **Critical Findings Detected**"
    elif [ "$HIG" -gt 0 ]; then
        COLOR=15105570 # Orange
        ALERT_MSG="🔸 **High Findings Detected**"
    fi

    # 6. Build Payload
    PAYLOAD=$(jq -n \
        --arg target "$TARGET" \
        --arg subs "$SUB_COUNT" \
        --arg ports "$PORT_COUNT" \
        --arg urls "$URL_COUNT" \
        --arg duration "$DURATION" \
        --arg path "$FULL_PATH" \
        --arg color "$COLOR" \
        --arg alert "$ALERT_MSG" \
        --arg ping "$USER_PING" \
        --arg cri "$CRI" --arg hig "$HIG" --arg med "$MED" --arg low "$LOW" --arg inf "$INF" \
        '{
            content: "\($ping) \($alert)",
            embeds: [{
                title: "🚀 ScopeWatch Complete",
                description: "Scan finished for **\($target)**",
                color: ($color | tonumber),
                fields: [
                    { name: "🔍 Subdomains", value: $subs, inline: true },
                    { name: "🔌 Open Ports", value: $ports, inline: true },
                    { name: "🌐 Live URLs", value: $urls, inline: true },
                    { name: "⏱️ Scan Time", value: $duration, inline: true },
                    { 
                      name: "📊 Severity Breakdown", 
                      value: "```\nCritical: \($cri)\nHigh:     \($hig)\nMedium:   \($med)\nLow:      \($low)\nInfo:     \($inf)\n```", 
                      inline: false 
                    },
                    { name: "📂 Full Output Path", value: ("`" + $path + "`"), inline: false }
                ],
                footer: { text: "ScopeWatch" },
                timestamp: now | strftime("%Y-%m-%dT%H:%M:%SZ")
            }]
        }')

    curl -s -X POST -H 'Content-Type: application/json' -d "$PAYLOAD" "$RESULTS_WEBHOOK" > /dev/null
    echo -e "${GREEN}[+] Discord notification sent.${NC}"
fi

# ---------------- Summary (Terminal Output) ----------------
echo -e "${GREEN}--------------------------------------------------------------------------------"
echo -e "[+] Pipeline complete for $TARGET in $DURATION"
echo -e "[*] Human Report: cat $REPORT_FILE"
echo -e "[*] Total Findings: $((CRI + HIG + MED + LOW + INF))"
echo -e "--------------------------------------------------------------------------------${NC}"
