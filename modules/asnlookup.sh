#!/usr/bin/env bash
# =============================================================================
# SentryCLI - ASN Lookup Module
# modules/asnlookup.sh
# Professional ASN Intelligence with clean SOC-style report
# =============================================================================

# ── Module Entry Point ────────────────────────────────────────────────────────
run_asnlookup() {
    print_section "6. ASN LOOKUP [ASN-6]"

    local input=""

    # Parse arguments / REPL support
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --asn|--as|--input)
                input="$2"
                shift 2
                ;;
            --clear-asn|--clear)
                unset ASN 2>/dev/null || true
                print_success "ASN/IP cleared from REPL session"
                return 0
                ;;
            *)
                print_alert "Unknown option: $1"
                echo "Usage: --asn <ASN or IP>"
                return 1
                ;;
        esac
    done

    # REPL set support
    if [[ -z "$input" && -n "${ASN:-}" ]]; then
        input="${ASN}"
        print_info "Using REPL-set ASN/IP → ${input}"
    fi

    # Interactive input
    if [[ -z "$input" ]]; then
        echo -ne "${CYAN}Enter ASN (e.g. AS15169) or IP: ${RESET}"
        read -r input
    fi

    [[ -z "$input" ]] && { print_alert "No ASN or IP provided."; return 1; }
    input=$(echo "$input" | tr -d '[:space:]')

    local report
    report=$(report_init "asnlookup")

    print_subsection "Querying ASN Intelligence → ${input}"
    _asn_analyze "$input" "$report"

    report_finalize "$report"
    log_success "ASNLOOKUP" "Analysis completed successfully"

    echo ""
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
}

# ── Helpers ───────────────────────────────────────────────────────────────────
_report_add() {
    local report="$1"
    local line="$2"
    [[ -n "$report" && -f "$report" ]] || return
    echo -e "$line" >> "$report"
}

_report_add_kv() {
    local report="$1"
    local key="$2"
    local value="$3"
    _report_add "$report" "**${key}**: ${value}"
}

_report_add_raw() {
    local report="$1"
    local title="$2"
    local json="$3"
    [[ -n "$report" && -f "$report" ]] || return
    _report_add "$report" ""
    _report_add "$report" "### ${title}"
    _report_add "$report" '```json'
    echo "${json:0:2000}" >> "$report"
    _report_add "$report" '```'
}

# ── Main ASN Analysis Engine ─────────────────────────────────────────────────
_asn_analyze() {
    local query="$1"
    local report="$2"

    # Clean ASN format (add AS prefix if missing and it's numeric)
    if [[ "$query" =~ ^[0-9]+$ ]]; then
        query="AS${query}"
    fi

    print_info " Querying BGPView & IPInfo..."

    # 1. BGPView API (Best free ASN source)
    local bgp_body
    bgp_body=$(curl -s --max-time 15 "https://api.bgpview.io/asn/${query#AS}")

    if [[ -n "$bgp_body" && "$bgp_body" != *"error"* ]]; then
        print_success " BGPView data retrieved"

        local asn_name=$(echo "$bgp_body" | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get("data",{}).get("name","N/A"))
except: print("N/A")
' 2>/dev/null)

        local asn_description=$(echo "$bgp_body" | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get("data",{}).get("description","N/A"))
except: print("N/A")
' 2>/dev/null)

        local asn_country=$(echo "$bgp_body" | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get("data",{}).get("country_code","N/A"))
except: print("N/A")
' 2>/dev/null)

        local asn_type=$(echo "$bgp_body" | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get("data",{}).get("type","N/A"))
except: print("N/A")
' 2>/dev/null)

        local prefixes=$(echo "$bgp_body" | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin)
    print(len(d.get("data",{}).get("prefixes",[])))
except: print("0")
' 2>/dev/null)

        _report_add_kv "$report" "ASN" "$query"
        _report_add_kv "$report" "Name" "$asn_name"
        _report_add_kv "$report" "Description" "$asn_description"
        _report_add_kv "$report" "Country" "$asn_country"
        _report_add_kv "$report" "Type" "$asn_type"
        _report_add_kv "$report" "Announced Prefixes" "$prefixes"

        print_kv " ASN Name" "$asn_name"
        print_kv " Description" "${asn_description:0:80}..."
        print_kv " Country" "$asn_country"
        print_kv " Type" "$asn_type"
        print_kv " Prefixes" "$prefixes"

        _report_add_raw "$report" "Raw BGPView Response" "$bgp_body"
    else
        print_warn " BGPView lookup failed, trying fallback..."
    fi

    # 2. IPInfo.io fallback (good for IP → ASN)
    if [[ "$query" =~ ^[0-9]+\.[0-9] ]]; then
        print_info " Querying IPInfo for IP..."
        local ipinfo=$(curl -s --max-time 12 "https://ipinfo.io/${query}/json")
        
        if [[ -n "$ipinfo" ]]; then
            local org=$(echo "$ipinfo" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("org","N/A"))' 2>/dev/null)
            local asn=$(echo "$ipinfo" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("asn","N/A"))' 2>/dev/null)
            
            _report_add_kv "$report" "Organization" "$org"
            _report_add_kv "$report" "ASN (from IP)" "$asn"
            
            print_kv " Organization" "$org"
        fi
    fi

    _report_add "$report" ""
    _report_add "$report" "**Analysis completed on:** $(date '+%Y-%m-%d %H:%M:%S %Z')"
    _report_add "$report" "---"

    print_success " ASN Lookup completed"
}
