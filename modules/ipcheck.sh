#!/usr/bin/env bash

# =============================================================================
# SentryCLI - IP / Hash Threat Intelligence Module
# modules/ipcheck.sh
#
# Usage:
#   --ip   <IP_ADDRESS>     → Analyze IPv4 address (AbuseIPDB + VirusTotal)
#   --hash <HASH>           → Analyze file hash (MD5/SHA1/SHA256) using VirusTotal only
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
        print_alert "  [${label}] Network error (curl ${exit_code})"
        [[ -n "$stderr" ]] && echo "    ${stderr}"
        rm -f "$tmp_body"
        return 1
    fi

    if [[ "$http_code" != "200" ]]; then
        print_alert "  [${label}] HTTP ${http_code} Error"
        if [[ -n "$body" ]]; then
            echo -e "    Response:\n${body:0:900}"
            echo "$body" > "/tmp/${label}_error_$(date +%s).json" 2>/dev/null
        fi
        rm -f "$tmp_body"
        return 1
    fi

    if [[ -z "$body" ]]; then
        print_alert "  [${label}] Empty response"
        rm -f "$tmp_body"
        return 1
    fi

    echo "$body"
    rm -f "$tmp_body"
    return 0
}

# ── API Key Verification ─────────────────────────────────────────────────────
_ipcheck_verify_api_key() {
    local service="$1" key="$2"
    if [[ -z "$key" ]]; then
        print_warn "  [${service}] No API key configured"
        return 1
    fi
    local len=${#key}
    print_success "  [${service}] API key loaded (${len} chars, ends: ...${key: -4})"
    return 0
}

# ── IP Validation ────────────────────────────────────────────────────────────
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

    # Parse command line arguments
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
                echo "  --ip   <IP_ADDRESS>     → Analyze IPv4 address"
                echo "  --hash <HASH>           → Analyze file hash (MD5/SHA1/SHA256)"
                return 1
                ;;
        esac
    done

    # Interactive mode if no arguments provided
    if [[ -z "$mode" ]]; then
        print_section "IP / HASH THREAT INTELLIGENCE MODULE"
        echo -ne "  Choose mode (ip/hash): "
        read -r mode_choice
        if [[ "$mode_choice" =~ ^(hash|h)$ ]]; then
            mode="hash"
        else
            mode="ip"
        fi

        echo -ne "  Enter ${mode^^}: "
        read -r input
    fi

    [[ -z "$input" ]] && { print_alert "No input provided"; return 1; }

    # Load API keys
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
        # IP Mode
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

# ── Analyze IP (AbuseIPDB + VirusTotal) ─────────────────────────────────────
_ipcheck_analyze_ip() {
    local ip="$1"
    local report="$2"
    local abuse_ok="$3"
    local vt_ok="$4"

    local threat_score=0

    # GeoIP
    print_info "  Fetching GeoIP data..."
    local geo_body=$(_ipcheck_curl_request "GeoIP" "http://ip-api.com/json/${ip}?fields=status,country,city,isp,org,proxy,hosting")

    if [[ $? -eq 0 && -n "$geo_body" ]]; then
        local country=$( _json_get "$geo_body" "country")
        local city=$(   _json_get "$geo_body" "city")
        local isp=$(    _json_get "$geo_body" "isp")
        local proxy=$(  _json_get "$geo_body" "proxy")
        local hosting=$(_json_get "$geo_body" "hosting")

        print_kv "  Country" "${country:-N/A}"
        print_kv "  City"    "${city:-N/A}"
        print_kv "  ISP"     "${isp:-N/A}"
        print_kv "  Proxy"   "${proxy:-false}"
        print_kv "  Hosting" "${hosting:-false}"

        [[ "$proxy" == "true" ]] && ((threat_score += 20))
        [[ "$hosting" == "true" ]] && ((threat_score += 10))
    fi

    # AbuseIPDB
    if [[ $abuse_ok -eq 1 ]]; then
        echo ""
        print_info "  Querying AbuseIPDB..."
        local abuse_body=$(_ipcheck_curl_request "AbuseIPDB" \
            "https://api.abuseipdb.com/api/v2/check" \
            -G \
            --data-urlencode "ipAddress=${ip}" \
            --data-urlencode "maxAgeInDays=${ABUSEIPDB_MAX_AGE_DAYS:-90}" \
            --data-urlencode "verbose=true" \
            -H "Key: ${ABUSEIPDB_API_KEY}" \
            -H "Accept: application/json")

        if [[ $? -eq 0 && -n "$abuse_body" ]]; then
            local score=$(echo "$abuse_body" | python3 -c '
import sys,json
d=json.load(sys.stdin)
print(d.get("data",{}).get("abuseConfidenceScore",0))' 2>/dev/null)

            local tor=$(echo "$abuse_body" | python3 -c '
import sys,json
d=json.load(sys.stdin)
print("true" if d.get("data",{}).get("isTor") else "false")' 2>/dev/null)

            print_kv "  [AbuseIPDB] Score" "${score}/100"
            print_kv "  [AbuseIPDB] Tor" "$tor"

            (( threat_score += score ))
            [[ "$tor" == "true" ]] && (( threat_score += 40 ))
        fi
    fi

    # Final Verdict for IP
    local final_score=$(( threat_score > 100 ? 100 : threat_score < 0 ? 0 : threat_score ))
    print_kv "  Final Threat Score" "${final_score}/100"

    if [[ $final_score -ge 70 ]]; then
        print_critical "  VERDICT: ★ MALICIOUS IP"
    elif [[ $final_score -ge 40 ]]; then
        print_alert "  VERDICT: ⚠ LIKELY MALICIOUS"
    else
        print_success "  VERDICT: CLEAN"
    fi

    echo "VERDICT:IP_${final_score}"
}

# ── Analyze Hash (VirusTotal Only) ──────────────────────────────────────────
_ipcheck_analyze_hash() {
    local hash="$1"
    local report="$2"
    local vt_ok="$3"

    if [[ $vt_ok -ne 1 ]]; then
        print_alert "VirusTotal API key is required for hash analysis"
        echo "VERDICT:HASH_ERROR"
        return
    fi

    print_info "  Querying VirusTotal for file hash..."

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
    malicious=$(echo "$vt_body" | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0))
except: print(0)' 2>/dev/null)

    suspicious=$(echo "$vt_body" | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("suspicious",0))
except: print(0)' 2>/dev/null)

    print_kv "  [VirusTotal] Malicious engines"   "${malicious}"
    print_kv "  [VirusTotal] Suspicious engines" "${suspicious}"

    local score=0
    if [[ "${malicious}" -ge 5 ]]; then
        print_critical "  VERDICT: ★ MALICIOUS FILE"
        score=90
    elif [[ "${malicious}" -gt 0 || "${suspicious}" -gt 0 ]]; then
        print_alert "  VERDICT: ⚠ SUSPICIOUS FILE"
        score=55
    else
        print_success "  VERDICT: CLEAN FILE"
        score=10
    fi

    print_kv "  Threat Score" "${score}/100"
    echo "VERDICT:HASH_${score}"
}
                         
