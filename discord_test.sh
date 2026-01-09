#!/usr/bin/env bash

# Load environment
[ -f .env ] && source .env

# --- Configuration ---
RESULTS_WEBHOOK="${RESULTS_WEBHOOK:-}"
DISCORD_USER_ID="${DISCORD_USER_ID:-}"
TARGET="test-domain.com"
OUTDIR="./test_output"
mkdir -p "$OUTDIR"

# 1. Start the Timer (Mimicking engine.sh start)
START_TIME=$(($(date +%s) - 345)) # Sets start time to 5m 45s ago

# 2. Mock the Files
NAMES_FILE="$OUTDIR/names.txt"
LIVE_URLS="$OUTDIR/live_urls.txt"
NAABU_OUT_JSON="$OUTDIR/naabu.json"
REPORT_FILE="$OUTDIR/vulnerabilities.txt"

# Create mock data
echo -e "sub1.test.com\nsub2.test.com\nsub3.test.com" > "$NAMES_FILE"
echo -e "https://sub1.test.com\nhttps://sub2.test.com" > "$LIVE_URLS"
echo -e '{"ip":"1.1.1.1","port":80}\n{"ip":"1.1.1.1","port":443}' > "$NAABU_OUT_JSON"
echo -e "[CRITICAL] | Finding 1\n[MEDIUM] | Finding 2" > "$REPORT_FILE"

# ---------------------------------------------------------
# STAGE 9 LOGIC
# ---------------------------------------------------------
if [[ -z "$RESULTS_WEBHOOK" ]]; then
    echo "ERROR: RESULTS_WEBHOOK not found in .env"
    exit 1
fi

echo "Sending Final Logic Test for Stage 9..."

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

# 4. Vulnerabilities
CRI=$(grep -ic "\[CRITICAL\]" "$REPORT_FILE" 2>/dev/null || true); CRI=${CRI:-0}
HIG=$(grep -ic "\[HIGH\]" "$REPORT_FILE" 2>/dev/null || true); HIG=${HIG:-0}
MED=$(grep -ic "\[MEDIUM\]" "$REPORT_FILE" 2>/dev/null || true); MED=${MED:-0}
LOW=$(grep -ic "\[LOW\]" "$REPORT_FILE" 2>/dev/null || true); LOW=${LOW:-0}
INF=$(grep -ic "\[INFO\]" "$REPORT_FILE" 2>/dev/null || true); INF=${INF:-0}

# 5. Discord Styling
USER_PING=""
[[ -n "$DISCORD_USER_ID" ]] && USER_PING="<@$DISCORD_USER_ID>"
COLOR=15158332 # Red
ALERT_MSG="⚠️ **TEST: CRITICAL FINDINGS DETECTED**"

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
            title: "🚀 ScopeWatch Complete (TEST)",
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
            footer: { text: "ScopeWatch Debugger" },
            timestamp: now | strftime("%Y-%m-%dT%H:%M:%SZ")
        }]
    }')

# 7. Send to Discord
curl -s -X POST -H 'Content-Type: application/json' -d "$PAYLOAD" "$RESULTS_WEBHOOK"

# 8. Cleanup
rm -rf "$OUTDIR"
echo -e "\nDone. Check Discord for the formatted result."
