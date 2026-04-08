#!/usr/bin/env bash

# =============================================================================
# SentryCLI - IP Threat Intelligence Module
# modules/ipcheck.sh
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

# ── FIXED & ROBUST CURL FUNCTION ─────────────────────────────────────────────
_ipcheck_curl_request() {
    local label="$1"
    local url="$2"
    shift 2
    local curl_args=("$@")

    local tmp_body=$(mktemp /tmp/sentry_body_XXXX.json 2>/dev/null)
    local tmp_err=$(mktemp /tmp/sentry_err_XXXX.txt 2>/dev/null)
    local tmp_headers=$(mktemp /tmp/sentry_hdrs_XXXX.txt 2>/dev/null)

    local http_code exit_code

    http_code=$(curl -4 -s \
        --retry 3 --retry-delay 2 --retry-connrefused \
        --max-time "${API_TIMEOUT:-30}" --connect-timeout 12 \
        -D "$tmp_headers" -w "%{http_code}" -o "$tmp_body" \
        "${curl_args[@]}" "$url" 2>"$tmp_err")

    exit_code=$?

    local body=$(cat "$tmp_body" 2>/dev/null || echo "")
    local stderr=$(cat "$tmp_err" 2>/dev/null | head -6)

    rm -f "$tmp_err"

    # DNS fallback
    if [[ $exit_code -eq 6 ]]; then
        print_warn "  [${label}] DNS failed — retrying with Google DNS..."
        http_code=$(curl -4 -s --dns-servers 8.8.8.8 \
            --retry 2 --max-time 20 -w "%{http_code}" -o "$tmp_body" \
            "${curl_args[@]}" "$url" 2>"$tmp_err")
        exit_code=$?
        body=$(cat "$tmp_body" 2>/dev/null || echo "")
    fi

    if [[ $exit_code -ne 0 ]]; then
        print_alert "  [${label}] Network error (curl ${exit_code})"
        [[ -n "$stderr" ]] && echo "    ${stderr}"
        rm -f "$tmp_body" "$tmp_headers"
        return 1
    fi

    if [[ "$http_code" != "200" ]]; then
        print_alert "  [${label}] HTTP ${http_code} Error"
        if [[ -n "$body" ]]; then
            echo -e "    API Response:\n${body:0:900}"
            echo "$body" > "/tmp/${label}_error_$(date +%s).json" 2>/dev/null
            print_info "    Full response saved to /tmp/${label}_error_*.json"
        fi
        rm -f "$tmp_body" "$tmp_headers"
        return 1
    fi

    if [[ -z "$body" ]]; then
        print_alert "  [${label}] Empty response"
        rm -f "$tmp_body" "$tmp_headers"
        return 1
    fi

    rm -f "$tmp_headers"
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

# ── IP checks ────────────────────────────────────────────────────────────────
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
    local ips_input=("$@")

    print_section "IP THREAT INTELLIGENCE MODULE"

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

    if [[ $abuseipdb_ok -eq 0 && $virustotal_ok -eq 0 ]]; then
        print_warn "No API keys active — limited to offline checks"
    fi

    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed"
        return 1
    fi

    if [[ ${#ips_input[@]} -eq 0 ]]; then
        echo -ne "  Enter IP address(es): "
        read -r raw
        IFS=', ' read -ra ips_input <<< "$raw"
    fi

    [[ ${#ips_input[@]} -eq 0 ]] && { print_alert "No IPs provided"; return 1; }

    local report=$(report_init "ipcheck")
    report_section "$report" "Results"

    for ip in "${ips_input[@]}"; do
        ip=$(echo "$ip" | tr -d '[:space:]')
        [[ -z "$ip" ]] && continue

        if ! _ipcheck_is_valid_ip "$ip"; then
            print_warn "Invalid IPv4: ${ip}"
            continue
        fi
        if _ipcheck_is_private "$ip"; then
            print_info "Private IP skipped: ${ip}"
            continue
        fi

        _ipcheck_analyze_ip "$ip" "$report" "$abuseipdb_ok" "$virustotal_ok"
    done

    report_finalize "$report"
}

# ── Analyze Single IP ────────────────────────────────────────────────────────
_ipcheck_analyze_ip() {
    local ip="$1" report="$2" abuse_ok="$3" vt_ok="$4"
    local threat_score=0
    local -a details=()

    print_subsection "Analyzing → ${ip}"
    report_section "$report" "IP: ${ip}"

    # GeoIP
    print_info "  GeoIP lookup..."
    local geo_body=$(_ipcheck_curl_request "GeoIP" "http://ip-api.com/json/${ip}?fields=status,country,city,isp,org,proxy,hosting")
    if [[ $? -eq 0 && -n "$geo_body" ]]; then
        local country=$(_json_get "$geo_body" "country")
        local city=$(_json_get "$geo_body" "city")
        local isp=$(_json_get "$geo_body" "isp")
        local proxy=$(_json_get "$geo_body" "proxy")
        local hosting=$(_json_get "$geo_body" "hosting")

        print_kv "  Country" "${country:-N/A}"
        print_kv "  City"    "${city:-N/A}"
        print_kv "  ISP"     "${isp:-N/A}"
        print_kv "  Proxy"   "${proxy:-false}"
        print_kv "  Hosting" "${hosting:-false}"

        [[ "$proxy" == "true" ]] && ((threat_score += 20)) && details+=("Proxy/VPN detected")
        [[ "$hosting" == "true" ]] && ((threat_score += 10)) && details+=("Hosting / Datacenter")
    fi

    # AbuseIPDB
    if [[ $abuse_ok -eq 1 ]]; then
        echo ""
        print_info "  Querying AbuseIPDB..."

        local abuse_body
        abuse_body=$(_ipcheck_curl_request "AbuseIPDB" \
            "https://api.abuseipdb.com/api/v2/check" \
            -G \
            --data-urlencode "ipAddress=${ip}" \
            --data-urlencode "maxAgeInDays=${ABUSEIPDB_MAX_AGE_DAYS:-90}" \
            --data-urlencode "verbose=true" \
            -H "Key: ${ABUSEIPDB_API_KEY}" \
            -H "Accept: application/json")

        # Debug file (very useful)
        echo "$abuse_body" > "/tmp/abuseipdb_debug.log" 2>/dev/null
        print_info "  Raw AbuseIPDB response saved → /tmp/abuseipdb_debug.log"

        if [[ $? -eq 0 && -n "$abuse_body" ]]; then
            local score=0 tor="false" whitelisted="false"

            if command -v python3 &>/dev/null; then
                score=$(echo "$abuse_body" | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get("data",{}).get("abuseConfidenceScore",0))
except: print(0)' 2>/dev/null)

                tor=$(echo "$abuse_body" | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin)
    print("true" if d.get("data",{}).get("isTor") else "false")
except: print("false")' 2>/dev/null)

                whitelisted=$(echo "$abuse_body" | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin)
    print("true" if d.get("data",{}).get("isWhitelisted") else "false")
except: print("false")' 2>/dev/null)
            fi

            print_kv "  [AbuseIPDB] Score" "${score}/100"
            print_kv "  [AbuseIPDB] Tor" "$tor"
            print_kv "  [AbuseIPDB] Whitelisted" "$whitelisted"

            (( threat_score += score ))
            [[ "$whitelisted" == "true" ]] && (( threat_score -= 25 ))
            [[ "$tor" == "true" ]] && (( threat_score += 40 )) && details+=("Tor Exit Node")
        fi
    fi

    # Offline checks
    _ipcheck_offline_heuristic "$ip" threat_score details

    # Verdict
    local final_score=$(( threat_score > 100 ? 100 : threat_score < 0 ? 0 : threat_score ))

    print_kv "  Final Threat Score" "${final_score}/100"

    if [[ $final_score -ge 70 ]]; then
        print_critical "  VERDICT: ★ MALICIOUS"
    elif [[ $final_score -ge 40 ]]; then
        print_alert "  VERDICT: ⚠ LIKELY MALICIOUS"
    elif [[ $final_score -ge 15 ]]; then
        print_warn "  VERDICT: ? SUSPICIOUS"
    else
        print_success "  VERDICT: ✔ CLEAN"
    fi

    report_append "$report" "Score: ${final_score} | Verdict: ${verdict:-UNKNOWN}"
}

# ── Offline Heuristics ───────────────────────────────────────────────────────
_ipcheck_offline_heuristic() {
    local ip="$1"
    local -n score=$2
    local -n det=$3

    local rev_ip=$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')

    local spamhaus=$(dig +short "${rev_ip}.zen.spamhaus.org" 2>/dev/null | head -1)
    if [[ -n "$spamhaus" && "$spamhaus" =~ ^127\. ]]; then
        (( score += 35 ))
        det+=("Spamhaus ZEN")
        print_alert "  → Listed on Spamhaus ZEN"
    fi
}
