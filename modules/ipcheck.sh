#!/usr/bin/env bash
# =============================================================================
# SentryCLI - IP / Hash Threat Intelligence Module
# modules/ipcheck.sh
#
# Usage:
# --ip <IP_ADDRESS> → Analyze IPv4 address (AbuseIPDB + VirusTotal)
# --hash <HASH> → Analyze file hash (MD5/SHA1/SHA256/SHA512)
# =============================================================================

# ── JSON extractor ───────────────────────────────────────────────────────────
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
        return
    fi
    echo "$json" | grep -o "\"${key}\":[^,}]*" | head -1 | sed 's/^"[^"]*":[[:space:]]*//' | tr -d '"'
}

# ── Report Helper Functions ──────────────────────────────────────────────────
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

# ── Human-readable AbuseIPDB Report ──────────────────────────────────────────
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

# ── Human-readable VirusTotal Report (NEW) ───────────────────────────────────
_report_add_virustotal_human() {
    local report="$1"
    local vt_body="$2"
    local hash="$3"

    [[ -z "$vt_body" || ! -f "$report" ]] && return

    _report_add "$report" ""
    _report_add "$report" "### VirusTotal Human-Readable Summary"

    # Auto-detect hash type
    local hash_type="Unknown"
    case ${#hash} in
        32) hash_type="MD5" ;;
        40) hash_type="SHA1" ;;
        64) hash_type="SHA256" ;;
        128) hash_type="SHA512" ;;
    esac

    local malicious suspicious harmless undetected size file_type magic first_seen last_analysis popular_threat
    malicious=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0))' 2>/dev/null)
    suspicious=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("suspicious",0))' 2>/dev/null)
    harmless=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("harmless",0))' 2>/dev/null)
    undetected=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("undetected",0))' 2>/dev/null)
    size=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("size",0))' 2>/dev/null)
    file_type=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("type_description","Unknown"))' 2>/dev/null)
    magic=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("magic","Unknown"))' 2>/dev/null)
    first_seen=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("first_submission_date","N/A"))' 2>/dev/null)
    last_analysis=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_date","N/A"))' 2>/dev/null)
    popular_threat=$(echo "$vt_body" | python3 -c '
import sys,json
d=json.load(sys.stdin)
pt = d.get("data",{}).get("attributes",{}).get("popular_threat_classification",{}).get("suggested_threat_label","None")
print(pt)' 2>/dev/null)

    _report_add_kv "$report" "Hash" "$hash"
    _report_add_kv "$report" "Hash Type" "$hash_type"
    _report_add_kv "$report" "File Type" "$file_type"
    _report_add_kv "$report" "Magic" "$magic"
    _report_add_kv "$report" "File Size" "$((size/1024)) KB"
    _report_add_kv "$report" "First Seen" "$first_seen"
    _report_add_kv "$report" "Last Analysis" "$last_analysis"
    _report_add_kv "$report" "Popular Threat Label" "${popular_threat:-None}"

    _report_add "$report" ""
    _report_add "$report" "#### Detection Statistics"
    _report_add_kv "$report" "Malicious" "${malicious}"
    _report_add_kv "$report" "Suspicious" "${suspicious}"
    _report_add_kv "$report" "Harmless" "${harmless}"
    _report_add_kv "$report" "Undetected" "${undetected}"

    # File names (if any)
    _report_add "$report" ""
    _report_add "$report" "#### Known File Names"
    echo "$vt_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    names = d.get("data",{}).get("attributes",{}).get("names", [])[:8]
    if names:
        for name in names:
            print(f"• {name}")
    else:
        print("No file names available.")
except:
    print("Could not parse file names.")
' >> "$report" 2>/dev/null

    _report_add "$report" "---"
}

# ── Robust CURL Function ─────────────────────────────────────────────────────
_ipcheck_curl_request() {
    local label="$1"
    local url="$2"
    shift 2
    local curl_args=("$@")
    local tmp_body=$(mktemp /tmp/sentry_body_XXXX.json 2>/dev/null)
    local tmp_err=$(mktemp /tmp/sentry_err_XXXX.txt 2>/dev/null)
    local http_code exit_code
    http_code=$(curl -4 -s \
        --retry 3 --retry-delay 2 --retry-connrefused \
        --max-time "${API_TIMEOUT:-30}" --connect-timeout 12 \
        -w "%{http_code}" -o "$tmp_body" \
        "${curl_args[@]}" "$url" 2>"$tmp_err")
    exit_code=$?
    local body=$(cat "$tmp_body" 2>/dev/null || echo "")
    local stderr=$(cat "$tmp_err" 2>/dev/null | head -6)
    rm -f "$tmp_err"
    if [[ $exit_code -ne 0 ]]; then
        print_alert " [${label}] Network error (curl ${exit_code})"
        [[ -n "$stderr" ]] && echo " ${stderr}"
        rm -f "$tmp_body"
        return 1
    fi
    if [[ "$http_code" != "200" ]]; then
        print_alert " [${label}] HTTP ${http_code} Error"
        if [[ -n "$body" ]]; then
            echo -e " Response:\n${body:0:900}"
            echo "$body" > "/tmp/${label}_error_$(date +%s).json" 2>/dev/null
        fi
        rm -f "$tmp_body"
        return 1
    fi
    if [[ -z "$body" ]]; then
        print_alert " [${label}] Empty response"
        rm -f "$tmp_body"
        return 1
    fi
    echo "$body"
    rm -f "$tmp_body"
    return 0
}

# ── API Key Verification, IP Validation, etc. (unchanged) ───────────────────
_ipcheck_verify_api_key() {
    local service="$1" key="$2"
    if [[ -z "$key" ]]; then
        print_warn " [${service}] No API key configured"
        return 1
    fi
    local len=${#key}
    print_success " [${service}] API key loaded (${len} chars, ends: ...${key: -4})"
    return 0
}

_ipcheck_is_valid_ip() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -ra o <<< "$ip"
    for n in "${o[@]}"; do [[ $n -gt 255 ]] && return 1; done
    return 0
}

_ipcheck_is_private() {
    local ip="$1"
    [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.) ]] && return 0
    return 1
}

# ── Module Entry Point ───────────────────────────────────────────────────────
run_ipcheck() {
    local mode=""
    local input=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ip)
                mode="ip"
                input="$2"
                shift 2
                ;;
            --hash)
                mode="hash"
                input="$2"
                shift 2
                ;;
            *)
                print_alert "Unknown option: $1"
                echo "Usage:"
                echo " --ip <IP_ADDRESS> → Analyze IPv4 address"
                echo " --hash <HASH> → Analyze file hash (MD5/SHA1/SHA256/SHA512)"
                return 1
                ;;
        esac
    done

    if [[ -z "$mode" ]]; then
        print_section "IP / HASH THREAT INTELLIGENCE MODULE"
        echo -ne " Choose mode (ip/hash): "
        read -r mode_choice
        if [[ "$mode_choice" =~ ^(hash|h)$ ]]; then mode="hash"; else mode="ip"; fi
        echo -ne " Enter ${mode^^}: "
        read -r input
    fi

    [[ -z "$input" ]] && { print_alert "No input provided"; return 1; }

    local conf_file="${SENTRYCLI_ROOT}/config/api_keys.conf"
    if [[ -f "$conf_file" ]]; then
        source "$conf_file"
        print_info "Config loaded: ${conf_file}"
    else
        print_warn "Config file not found: ${conf_file}"
    fi

    echo ""
    print_subsection "API Key Status"
    local abuseipdb_ok=0 virustotal_ok=0
    if _ipcheck_verify_api_key "AbuseIPDB" "${ABUSEIPDB_API_KEY:-}"; then abuseipdb_ok=1; fi
    if _ipcheck_verify_api_key "VirusTotal" "${VIRUSTOTAL_API_KEY:-}"; then virustotal_ok=1; fi

    local report
    report=$(report_init "ipcheck")
    report_section "$report" "Threat Intelligence Results"

    input=$(echo "$input" | tr -d '[:space:]')

    if [[ "$mode" == "hash" ]]; then
        print_subsection "Analyzing HASH → ${input}"
        _ipcheck_analyze_hash "$input" "$report" "$virustotal_ok"
    else
        if ! _ipcheck_is_valid_ip "$input"; then
            print_warn "Invalid IPv4 address: ${input}"
            return 1
        fi
        if _ipcheck_is_private "$input"; then
            print_info "Private IP skipped: ${input}"
            return 0
        fi
        print_subsection "Analyzing IP → ${input}"
        _ipcheck_analyze_ip "$input" "$report" "$abuseipdb_ok" "$virustotal_ok"
    fi

    report_finalize "$report"
    log_success "IPCHECK" "Analysis completed successfully"
}

# ── Analyze IP (unchanged except calling human function) ─────────────────────
_ipcheck_analyze_ip() {
    local ip="$1"
    local report="$2"
    local abuse_ok="$3"
    local vt_ok="$4"
    local threat_score=0

    # GeoIP (unchanged)
    print_info " Fetching GeoIP data..."
    local geo_body=$(_ipcheck_curl_request "GeoIP" "http://ip-api.com/json/${ip}?fields=status,country,city,isp,org,proxy,hosting")
    if [[ $? -eq 0 && -n "$geo_body" ]]; then
        local country=$( _json_get "$geo_body" "country")
        local city=$( _json_get "$geo_body" "city")
        local isp=$( _json_get "$geo_body" "isp")
        local proxy=$( _json_get "$geo_body" "proxy")
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

    # AbuseIPDB
    if [[ $abuse_ok -eq 1 ]]; then
        echo ""
        print_info " Querying AbuseIPDB..."
        local abuse_body=$(_ipcheck_curl_request "AbuseIPDB" \
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

# ── Analyze Hash (Updated with human-readable report) ────────────────────────
_ipcheck_analyze_hash() {
    local hash="$1"
    local report="$2"
    local vt_ok="$3"

    if [[ $vt_ok -ne 1 ]]; then
        print_alert "VirusTotal API key is required for hash analysis"
        echo "VERDICT:HASH_ERROR"
        return
    fi

    print_info " Querying VirusTotal for file hash..."
    local vt_body
    vt_body=$(_ipcheck_curl_request "VirusTotal" \
        "https://www.virustotal.com/api/v3/files/${hash}" \
        -H "x-apikey: ${VIRUSTOTAL_API_KEY}")

    if [[ $? -ne 0 || -z "$vt_body" ]]; then
        print_alert "Failed to retrieve VirusTotal report for the hash"
        echo "VERDICT:HASH_ERROR"
        return
    fi

    local malicious suspicious
    malicious=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0))' 2>/dev/null)
    suspicious=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("suspicious",0))' 2>/dev/null)

    print_kv " [VirusTotal] Malicious engines" "${malicious}"
    print_kv " [VirusTotal] Suspicious engines" "${suspicious}"

    # Human-readable rich report
    _report_add_virustotal_human "$report" "$vt_body" "$hash"

    local score=0
    if [[ "${malicious}" -ge 5 ]]; then
        print_critical " VERDICT: ★ MALICIOUS FILE"
        score=90
    elif [[ "${malicious}" -gt 0 || "${suspicious}" -gt 0 ]]; then
        print_alert " VERDICT: ⚠ SUSPICIOUS FILE"
        score=55
    else
        print_success " VERDICT: CLEAN FILE"
        score=10
    fi

    print_kv " Threat Score" "${score}/100"

    _report_add_kv "$report" "Final Threat Score" "${score}/100"
    _report_add_kv "$report" "Verdict" "HASH_${score}"
    _report_add "$report" "**Analysis completed on:** $(date '+%Y-%m-%d %H:%M:%S %Z')"

    echo "VERDICT:HASH_${score}"
}
