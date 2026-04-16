#!/usr/bin/env bash
# =============================================================================
# SentryCLI - IP Threat Intelligence Module
# modules/ipcheck.sh
# =============================================================================

# ── Module Entry Point ────────────────────────────────────────────────────────
run_ipcheck() {
    print_section "4. IP THREAT INTELLIGENCE [IP-4]"

    local input=""

    # Parse arguments / REPL support
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ip)
                input="$2"
                shift 2
                ;;
            --clear-ip|--unset-ip|--clear|--unset)
                unset IP 2>/dev/null || true
                print_success "IP address cleared from REPL session"
                return 0
                ;;
            *)
                print_alert "Unknown option: $1"
                echo "Usage: --ip <IP_ADDRESS>"
                return 1
                ;;
        esac
    done

    # REPL set support
    if [[ -z "$input" && -n "${IP:-}" ]]; then
        input="${IP}"
        print_info "Using REPL-set IP → ${input}"
    fi

    # Interactive fallback
    if [[ -z "$input" ]]; then
        echo -ne "${CYAN}Enter IP Address: ${RESET}"
        read -r input
    fi

    [[ -z "$input" ]] && { print_alert "No IP provided."; return 1; }
    input=$(echo "$input" | tr -d '[:space:]')

    # Load config
    local conf_file="${SENTRYCLI_ROOT}/config/api_keys.conf"
    [[ -f "$conf_file" ]] && source "$conf_file" || print_warn "Config file not found"

    echo ""
    print_subsection "API Key Status"
    local abuseipdb_ok=0
    _ip_verify_api_key "AbuseIPDB" "${ABUSEIPDB_API_KEY:-}" && abuseipdb_ok=1

    local report
    report=$(report_init "ipcheck")

    if ! _ip_is_valid_ip "$input"; then
        print_alert "Invalid IPv4 address: ${input}"
        return 1
    fi
    if _ip_is_private "$input"; then
        print_info "Private IP skipped (no external lookup needed)"
        return 0
    fi

    print_subsection "Analyzing IP → ${input}"
    _ipcheck_analyze_ip "$input" "$report" "$abuseipdb_ok"

    report_finalize "$report"
    log_success "IPCHECK" "Analysis completed successfully"

    echo ""
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
}

# ── Helpers (self-contained) ─────────────────────────────────────────────────
_ip_verify_api_key() {
    local service="$1" key="$2"
    if [[ -z "$key" ]]; then
        print_warn " [${service}] No API key configured"
        return 1
    fi
    print_success " [${service}] API key loaded (...${key: -4})"
    return 0
}

_json_get() {
    local json="$1" key="$2"
    if command -v python3 &>/dev/null; then
        echo "$json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    keys = '$key'.split('.')
    v = d
    for k in keys:
        v = v.get(k) if isinstance(v, dict) else ''
    print(v if v is not None else '')
except:
    print('')
" 2>/dev/null
    else
        echo "$json" | grep -o "\"${key}\":[^,}]*" | head -1 | sed 's/^\"[^\"]*\":[[:space:]]*//' | tr -d '"'
    fi
}

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
    echo "${json:0:2500}" >> "$report"
    _report_add "$report" '```'
}

# ── Robust Curl for IP module ────────────────────────────────────────────────
_ip_curl_request() {
    local label="$1"
    local url="$2"
    shift 2
    local tmp_body=$(mktemp /tmp/sentry_body_XXXX.json 2>/dev/null)
    local tmp_err=$(mktemp /tmp/sentry_err_XXXX.txt 2>/dev/null)

    http_code=$(curl -4 -s --retry 3 --retry-delay 2 --max-time 30 \
        -w "%{http_code}" -o "$tmp_body" "${@}" "$url" 2>"$tmp_err")
    local body=$(cat "$tmp_body" 2>/dev/null || echo "")
    rm -f "$tmp_body" "$tmp_err"

    if [[ "$http_code" != "200" || -z "$body" ]]; then
        print_alert " [${label}] Failed (HTTP ${http_code})"
        return 1
    fi
    echo "$body"
    return 0
}

_ip_is_valid_ip() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -ra o <<< "$ip"
    for n in "${o[@]}"; do [[ $n -gt 255 ]] && return 1; done
    return 0
}

_ip_is_private() {
    local ip="$1"
    [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.) ]] && return 0
    return 1
}

# ── Full AbuseIPDB Human-Readable Report (detailed as in original) ───────────
_report_add_abuseipdb_human() {
    local report="$1"
    local abuse_body="$2"
    local ip="$3"

    [[ -z "$abuse_body" || ! -f "$report" ]] && return

    _report_add "$report" ""
    _report_add "$report" "### AbuseIPDB Human-Readable Summary"

    local score countryName usageType isp domain isTor totalReports numDistinctUsers lastReportedAt
    score=$(echo "$abuse_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);data=d.get("data",{});print(data.get("abuseConfidenceScore",0))' 2>/dev/null)
    countryName=$(echo "$abuse_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);data=d.get("data",{});print(data.get("countryName","N/A"))' 2>/dev/null)
    usageType=$(echo "$abuse_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);data=d.get("data",{});print(data.get("usageType","N/A"))' 2>/dev/null)
    isp=$(echo "$abuse_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);data=d.get("data",{});print(data.get("isp","N/A"))' 2>/dev/null)
    domain=$(echo "$abuse_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);data=d.get("data",{});print(data.get("domain","N/A"))' 2>/dev/null)
    isTor=$(echo "$abuse_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);data=d.get("data",{});print("Yes" if data.get("isTor") else "No")' 2>/dev/null)
    totalReports=$(echo "$abuse_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);data=d.get("data",{});print(data.get("totalReports",0))' 2>/dev/null)
    numDistinctUsers=$(echo "$abuse_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);data=d.get("data",{});print(data.get("numDistinctUsers",0))' 2>/dev/null)
    lastReportedAt=$(echo "$abuse_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);data=d.get("data",{});print(data.get("lastReportedAt","N/A"))' 2>/dev/null)

    _report_add_kv "$report" "IP Address" "$ip"
    _report_add_kv "$report" "Country" "$countryName"
    _report_add_kv "$report" "Usage Type" "$usageType"
    _report_add_kv "$report" "ISP" "$isp"
    _report_add_kv "$report" "Domain" "$domain"
    _report_add_kv "$report" "Abuse Confidence Score" "**${score}/100**"
    _report_add_kv "$report" "Is Tor" "$isTor"
    _report_add_kv "$report" "Total Reports" "$totalReports"
    _report_add_kv "$report" "Distinct Reporters" "$numDistinctUsers"
    _report_add_kv "$report" "Last Reported" "$lastReportedAt"

    _report_add "$report" ""
    _report_add "$report" "#### Recent Reports (Latest 5)"
    echo "$abuse_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    reports = d.get("data", {}).get("reports", [])[:5]
    for i, r in enumerate(reports, 1):
        at = r.get("reportedAt", "N/A")
        comment = r.get("comment", "No comment").replace("\n", " ")[:180]
        if len(r.get("comment","")) > 180: comment += "..."
        cat = r.get("categories", [])
        country = r.get("fromIpCountryName", "Unknown")
        print(f"{i}. **{at}**")
        print(f"   • From: {country}")
        print(f"   • Categories: {cat}")
        print(f"   • Comment: {comment}\n")
except: print("Could not parse reports.")
' >> "$report" 2>/dev/null

    _report_add "$report" "---"
}

# ── IP Analysis Core (GeoIP + AbuseIPDB) ─────────────────────────────────────
_ipcheck_analyze_ip() {
    local ip="$1"
    local report="$2"
    local abuse_ok="$3"
    local threat_score=0

    # GeoIP
    print_info " Fetching GeoIP data..."
    local geo_body=$(_ip_curl_request "GeoIP" "http://ip-api.com/json/${ip}?fields=status,country,city,isp,org,proxy,hosting")
    if [[ $? -eq 0 && -n "$geo_body" ]]; then
        local country=$(_json_get "$geo_body" "country")
        local city=$(_json_get "$geo_body" "city")
        local isp=$(_json_get "$geo_body" "isp")
        local proxy=$(_json_get "$geo_body" "proxy")
        local hosting=$(_json_get "$geo_body" "hosting")

        print_kv " Country" "${country:-N/A}"
        print_kv " City" "${city:-N/A}"
        print_kv " ISP" "${isp:-N/A}"
        print_kv " Proxy" "${proxy:-false}"
        print_kv " Hosting" "${hosting:-false}"

        _report_add_kv "$report" "Country" "${country:-N/A}"
        _report_add_kv "$report" "City" "${city:-N/A}"
        _report_add_kv "$report" "ISP" "${isp:-N/A}"
        _report_add_kv "$report" "Proxy Detected" "${proxy:-false}"
        _report_add_kv "$report" "Hosting / Data Center" "${hosting:-false}"
        _report_add_raw "$report" "Raw GeoIP Response" "$geo_body"

        [[ "$proxy" == "true" ]] && ((threat_score += 20))
        [[ "$hosting" == "true" ]] && ((threat_score += 10))
    fi

    # AbuseIPDB (detailed report)
    if [[ $abuse_ok -eq 1 ]]; then
        echo ""
        print_info " Querying AbuseIPDB..."
        local abuse_body=$(_ip_curl_request "AbuseIPDB" \
            "https://api.abuseipdb.com/api/v2/check" \
            -G --data-urlencode "ipAddress=${ip}" \
            --data-urlencode "maxAgeInDays=${ABUSEIPDB_MAX_AGE_DAYS:-90}" \
            --data-urlencode "verbose=true" \
            -H "Key: ${ABUSEIPDB_API_KEY}" -H "Accept: application/json")

        if [[ $? -eq 0 && -n "$abuse_body" ]]; then
            local score=$(echo "$abuse_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("abuseConfidenceScore",0))' 2>/dev/null)
            local tor=$(echo "$abuse_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("true" if d.get("data",{}).get("isTor") else "false")' 2>/dev/null)

            print_kv " [AbuseIPDB] Score" "${score}/100"
            print_kv " [AbuseIPDB] Tor" "$tor"

            _report_add_abuseipdb_human "$report" "$abuse_body" "$ip"

            (( threat_score += score ))
            [[ "$tor" == "true" ]] && (( threat_score += 40 ))
        fi
    fi

    local final_score=$(( threat_score > 100 ? 100 : threat_score < 0 ? 0 : threat_score ))
    print_kv " Final Threat Score" "${final_score}/100"
    if [[ $final_score -ge 70 ]]; then print_critical " VERDICT: ★ MALICIOUS IP"
    elif [[ $final_score -ge 40 ]]; then print_alert " VERDICT: ⚠ LIKELY MALICIOUS"
    else print_success " VERDICT: CLEAN"; fi

    _report_add_kv "$report" "Final Threat Score" "${final_score}/100"
    _report_add_kv "$report" "Verdict" "IP_${final_score}"
    _report_add "$report" "**Analysis completed on:** $(date '+%Y-%m-%d %H:%M:%S %Z')"

    echo "VERDICT:IP_${final_score}"
}
                     
