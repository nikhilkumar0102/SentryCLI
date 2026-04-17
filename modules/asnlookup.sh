#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Professional ASN / IP Intelligence Module
# Clean SOC-Style Output + Human Readable Report
# =============================================================================

# Load API configuration
if [[ -f "${SENTRYCLI_ROOT:-.}/config/api_keys.conf" ]]; then
    source "${SENTRYCLI_ROOT:-.}/config/api_keys.conf" 2>/dev/null || true
fi

# ─────────────────────────────────────────────────────────────────────────────
run_asnlookup() {

    print_section "6. ASN / IP INTELLIGENCE [ASN-6]"

    local input=""

    # Input from REPL set command
    if [[ -n "${MODULE_OPTS[asn]:-}" ]]; then
        input="${MODULE_OPTS[asn]}"
        print_info "Using configured ASN/IP: ${input}"
    elif [[ -n "${MODULE_OPTS[target]:-}" ]]; then
        input="${MODULE_OPTS[target]}"
    elif [[ -n "$1" ]]; then
        input="$1"
    fi

    # Interactive prompt
    if [[ -z "$input" ]]; then
        echo -ne "${CYAN}Enter ASN (e.g. 15169) or IP Address: ${RESET}"
        read -r input
    fi

    [[ -z "$input" ]] && { print_alert "No input provided."; return 1; }

    # Normalize input
    input=$(echo "$input" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        input="AS${input}"
        print_info "Auto-converted to ASN format → ${input}"
    fi

    # Prepare clean report file
    local report_dir="${SENTRYCLI_ROOT:-.}/reports"
    mkdir -p "$report_dir"
    local report="${report_dir}/ASN_Intelligence_$(date '+%Y%m%d_%H%M%S').txt"

    print_subsection "Querying ipapi.is → ${input}"

    _asn_analyze "$input" "$report"

    echo ""
    print_success "Analysis completed successfully"
    print_success "Report saved → ${report}"

    echo -ne "${CYAN}Press ENTER to return to main menu...${RESET}"
    read -r

    CURRENT_MODULE=""
    MODULE_OPTS=()
}

# ─────────────────────────────────────────────────────────────────────────────
_asn_analyze() {
    local query="$1"
    local report="$2"

    local api_url="https://api.ipapi.is/?q=${query}"

    if [[ -n "${IPAPI_IS_API_KEY:-}" ]]; then
        api_url="${api_url}&key=${IPAPI_IS_API_KEY}"
        print_info "Authenticated with API key"
    else
        print_warn "Running in free tier (limited rate)"
    fi

    local raw
    raw=$(curl -s --max-time 20 -H "User-Agent: SentryCLI/2.7" "$api_url")

    if [[ -z "$raw" ]] || ! echo "$raw" | grep -q "{"; then
        print_alert "Failed to retrieve data from ipapi.is"
        echo "ERROR: No response from API" > "$report"
        return 1
    fi

    print_success "Data received successfully"

    # Robust parsing
    local data
    data=$(echo "$raw" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    asn = d.get("asn") if isinstance(d.get("asn"), dict) else d
    loc = d.get("location", {})
    comp = d.get("company", {})
    dc = d.get("datacenter", {})
    ab = d.get("abuse", {}) if isinstance(d.get("abuse"), dict) else {}

    def g(x): return str(x).strip() if x is not None else "N/A"

    print("IP:" + g(d.get("ip")))
    print("ASN:" + g(asn.get("asn")))
    print("ORG:" + g(asn.get("org") or comp.get("name") or asn.get("name")))
    print("DESC:" + g(asn.get("descr") or asn.get("description")))
    print("COUNTRY:" + g(asn.get("country") or loc.get("country_code")))
    print("CITY:" + g(loc.get("city")))
    print("TYPE:" + g(asn.get("type") or comp.get("type")))
    print("ABUSER:" + g(asn.get("abuser_score") or d.get("abuser_score")))
    print("ABUSE:" + g(ab.get("email") or asn.get("abuse")))
    print("CREATED:" + g(asn.get("created")))
    print("UPDATED:" + g(asn.get("updated")))
    print("DC:" + g(dc.get("datacenter")))
    print("IS_DC:" + ("Yes" if d.get("is_datacenter") else "No"))
    print("VPN:" + ("Yes" if d.get("is_vpn") else "No"))
    print("TOR:" + ("Yes" if d.get("is_tor") else "No"))
    print("PROXY:" + ("Yes" if d.get("is_proxy") else "No"))
    print("RAW_JSON_START")
    print(json.dumps(d, indent=2))
except Exception as e:
    print("ERROR:" + str(e))
' 2>/dev/null)

    # Extract fields
    local ip asn org desc country city type abuser abuse created updated dc is_dc vpn tor proxy
    ip=$(echo "$data" | grep "^IP:" | cut -d: -f2-)
    asn=$(echo "$data" | grep "^ASN:" | cut -d: -f2-)
    org=$(echo "$data" | grep "^ORG:" | cut -d: -f2-)
    desc=$(echo "$data" | grep "^DESC:" | cut -d: -f2-)
    country=$(echo "$data" | grep "^COUNTRY:" | cut -d: -f2-)
    city=$(echo "$data" | grep "^CITY:" | cut -d: -f2-)
    type=$(echo "$data" | grep "^TYPE:" | cut -d: -f2-)
    abuser=$(echo "$data" | grep "^ABUSER:" | cut -d: -f2-)
    abuse=$(echo "$data" | grep "^ABUSE:" | cut -d: -f2-)
    created=$(echo "$data" | grep "^CREATED:" | cut -d: -f2-)
    updated=$(echo "$data" | grep "^UPDATED:" | cut -d: -f2-)
    dc=$(echo "$data" | grep "^DC:" | cut -d: -f2-)
    is_dc=$(echo "$data" | grep "^IS_DC:" | cut -d: -f2-)
    vpn=$(echo "$data" | grep "^VPN:" | cut -d: -f2-)
    tor=$(echo "$data" | grep "^TOR:" | cut -d: -f2-)
    proxy=$(echo "$data" | grep "^PROXY:" | cut -d: -f2-)

    [[ "$asn" != "N/A" ]] && asn="AS${asn}"

    # ── Professional Screen Output ─────────────────────────────────────
    echo ""
    echo -e "${BOLD}${WHITE}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${WHITE}║               ASN / IP INTELLIGENCE REPORT                 ║${RESET}"
    echo -e "${BOLD}${WHITE}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    print_kv " Query"           "$query"
    [[ "$ip" != "N/A" ]] && print_kv " IP Address"     "$ip"
    print_kv " ASN"            "$asn"
    print_kv " Organization"   "$org"
    [[ "$desc" != "N/A" ]] && print_kv " Description"    "${desc:0:85}..."
    print_kv " Country"        "$country"
    [[ "$city" != "N/A" ]] && print_kv " City"           "$city"
    print_kv " Type"           "$type"
    print_kv " Abuser Score"   "$abuser"
    [[ "$abuse" != "N/A" ]] && print_kv " Abuse Contact"  "$abuse"
    [[ "$is_dc" != "N/A" ]] && print_kv " Datacenter"     "$is_dc (${dc})"
    [[ "$vpn" != "N/A" ]] && print_kv " VPN"             "$vpn"
    [[ "$tor" != "N/A" ]] && print_kv " Tor Exit"        "$tor"
    [[ "$proxy" != "N/A" ]] && print_kv " Proxy"          "$proxy"
    [[ "$created" != "N/A" ]] && print_kv " ASN Created"   "$created"

    echo ""

    # ── Clean Human-Readable TXT Report ───────────────────────────────
    {
        echo "══════════════════════════════════════════════════════════════"
        echo "              ASN / IP INTELLIGENCE REPORT"
        echo "══════════════════════════════════════════════════════════════"
        echo ""
        echo "Generated On : $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "Query        : $query"
        echo ""
        echo "────────────────────── Core Information ──────────────────────"
        echo "ASN            : $asn"
        echo "Organization   : $org"
        echo "Description    : $desc"
        echo "Country        : $country"
        echo "City           : $city"
        echo "Type           : $type"
        echo ""
        echo "────────────────────── Threat & Risk ────────────────────────"
        echo "Abuser Score   : $abuser"
        echo "Abuse Contact  : $abuse"
        echo ""
        echo "────────────────────── Infrastructure ───────────────────────"
        echo "Is Datacenter  : $is_dc"
        echo "Datacenter     : $dc"
        echo "VPN            : $vpn"
        echo "Tor            : $tor"
        echo "Proxy          : $proxy"
        echo ""
        echo "────────────────────── Timestamps ───────────────────────────"
        echo "Created        : $created"
        echo "Updated        : $updated"
        echo ""
        echo "══════════════════════════════════════════════════════════════"
        echo "RAW JSON RESPONSE"
        echo "══════════════════════════════════════════════════════════════"
        echo "$raw"
        echo ""
        echo "══════════════════════════════════════════════════════════════"
        echo "Report generated by SentryCLI v2.7"
    } > "$report"

    return 0
}
               
