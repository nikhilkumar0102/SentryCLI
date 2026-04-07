#!/usr/bin/env bash
# =============================================================================
# SentryCLI - IP Threat Intelligence Module
# modules/ipcheck.sh
#
# Queries AbuseIPDB and VirusTotal APIs to classify IPs as
# malicious or clean, returning threat scores and summaries.
# =============================================================================

# ── IP Validation ────────────────────────────────────────────────────────────
_ipcheck_is_valid_ip() {
    local ip="$1"
    local pattern='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [[ ! "$ip" =~ $pattern ]]; then
        return 1
    fi
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [[ $octet -gt 255 ]]; then
            return 1
        fi
    done
    return 0
}

# ── Is Private IP ─────────────────────────────────────────────────────────────
_ipcheck_is_private() {
    local ip="$1"
    if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|169\.254\.) ]]; then
        return 0
    fi
    return 1
}

# ── Module Entry Point ────────────────────────────────────────────────────────
run_ipcheck() {
    local ips_input=("$@")

    print_section "IP THREAT INTELLIGENCE MODULE"
    log_info "IPCHECK" "Module started"

    # Load API keys
    if [[ -f "${SENTRYCLI_ROOT}/config/api_keys.conf" ]]; then
        # shellcheck source=/dev/null
        source "${SENTRYCLI_ROOT}/config/api_keys.conf"
    fi

    # If no IPs passed, prompt interactively
    if [[ ${#ips_input[@]} -eq 0 ]]; then
        echo -ne "  ${CYAN}${BOLD}Enter IP address(es) (space or comma separated):${RESET} "
        read -r ip_input_raw
        IFS=', ' read -ra ips_input <<< "$ip_input_raw"
    fi

    if [[ ${#ips_input[@]} -eq 0 ]]; then
        print_alert "No IP addresses provided. Aborting."
        log_error "IPCHECK" "No IPs provided"
        return 1
    fi

    # Initialize report
    local report
    report=$(report_init "ipcheck")
    report_section "$report" "IP Threat Intelligence Results"

    # Warn if no API keys configured
    local api_available=0
    [[ -n "$ABUSEIPDB_API_KEY" ]]  && (( api_available++ ))
    [[ -n "$VIRUSTOTAL_API_KEY" ]] && (( api_available++ ))

    if [[ $api_available -eq 0 ]]; then
        print_warn "No API keys configured in config/api_keys.conf"
        print_warn "Running in OFFLINE mode — basic IP classification only"
        log_warn "IPCHECK" "No API keys configured — offline mode"
        report_append "$report" "Mode: OFFLINE (no API keys)"
    else
        print_info "API providers available: ${api_available}"
        report_append "$report" "Mode: ONLINE ($api_available API provider(s))"
    fi

    echo ""

    # Process each IP
    local malicious_ips=()
    local clean_ips=()
    local unknown_ips=()

    for ip in "${ips_input[@]}"; do
        ip=$(echo "$ip" | tr -d '[:space:]')
        [[ -z "$ip" ]] && continue

        if ! _ipcheck_is_valid_ip "$ip"; then
            print_warn "Invalid IP format: $ip — skipping"
            continue
        fi

        if _ipcheck_is_private "$ip"; then
            print_info "Private/internal IP: ${ip} — skipping external lookup"
            continue
        fi

        local result
        result=$(_ipcheck_analyze_ip "$ip" "$report")
        local verdict
        verdict=$(echo "$result" | grep "^VERDICT:" | cut -d: -f2 | tr -d ' ')

        case "$verdict" in
            MALICIOUS) malicious_ips+=("$ip") ;;
            CLEAN)     clean_ips+=("$ip") ;;
            *)         unknown_ips+=("$ip") ;;
        esac
    done

    # Summary
    _ipcheck_summary "$report" malicious_ips[@] clean_ips[@] unknown_ips[@]

    report_finalize "$report"
    log_success "IPCHECK" "IP check complete. Malicious: ${#malicious_ips[@]}, Clean: ${#clean_ips[@]}"

    # Export malicious IPs for use by correlation engine
    MALICIOUS_IPS=("${malicious_ips[@]}")
}

# ── Analyze Single IP ─────────────────────────────────────────────────────────
_ipcheck_analyze_ip() {
    local ip="$1"
    local report="$2"

    print_subsection "Analyzing: ${ip}"
    report_section "$report" "IP: $ip"

    local verdict="UNKNOWN"
    local threat_score=0
    local details=()

    # ── Basic GeoIP (ip-api.com — free, no key required) ───────────────────
    if command -v curl &>/dev/null; then
        local geo_response
        geo_response=$(curl -s --max-time "${API_TIMEOUT:-10}" \
            "http://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,org,as,proxy,hosting" \
            2>/dev/null)

        if [[ -n "$geo_response" ]]; then
            local country city isp org is_proxy is_hosting
            country=$(echo "$geo_response"    | grep -o '"country":"[^"]*"'    | cut -d'"' -f4)
            city=$(echo "$geo_response"       | grep -o '"city":"[^"]*"'       | cut -d'"' -f4)
            isp=$(echo "$geo_response"        | grep -o '"isp":"[^"]*"'        | cut -d'"' -f4)
            org=$(echo "$geo_response"        | grep -o '"org":"[^"]*"'        | cut -d'"' -f4)
            is_proxy=$(echo "$geo_response"   | grep -o '"proxy":[a-z]*'       | cut -d: -f2)
            is_hosting=$(echo "$geo_response" | grep -o '"hosting":[a-z]*'     | cut -d: -f2)

            print_kv "  Country"    "${country:-N/A}"
            print_kv "  City"       "${city:-N/A}"
            print_kv "  ISP"        "${isp:-N/A}"
            print_kv "  Org/ASN"    "${org:-N/A}"
            print_kv "  Proxy/VPN"  "${is_proxy:-false}"
            print_kv "  Hosting"    "${is_hosting:-false}"

            report_append "$report" "GeoIP: $country / $city | ISP: $isp | Proxy: $is_proxy | Hosting: $is_hosting"

            [[ "$is_proxy"   == "true" ]] && (( threat_score += 20 )) && details+=("VPN/Proxy detected")
            [[ "$is_hosting" == "true" ]] && (( threat_score += 10 )) && details+=("Hosting provider")
        fi
    fi

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    if [[ -n "$ABUSEIPDB_API_KEY" ]] && command -v curl &>/dev/null; then
        print_info "  Querying AbuseIPDB..."
        local abuse_response
        abuse_response=$(curl -s --max-time "${API_TIMEOUT:-10}" \
            -G "https://api.abuseipdb.com/api/v2/check" \
            --data-urlencode "ipAddress=${ip}" \
            -d "maxAgeInDays=90" \
            -d "verbose" \
            -H "Key: ${ABUSEIPDB_API_KEY}" \
            -H "Accept: application/json" \
            2>/dev/null)

        if echo "$abuse_response" | grep -q '"abuseConfidenceScore"'; then
            local abuse_score total_reports last_report country_code usage_type domain
            abuse_score=$(echo "$abuse_response"    | grep -o '"abuseConfidenceScore":[0-9]*'    | cut -d: -f2)
            total_reports=$(echo "$abuse_response"  | grep -o '"totalReports":[0-9]*'            | cut -d: -f2)
            last_report=$(echo "$abuse_response"    | grep -o '"lastReportedAt":"[^"]*"'         | cut -d'"' -f4)
            usage_type=$(echo "$abuse_response"     | grep -o '"usageType":"[^"]*"'              | cut -d'"' -f4)
            domain=$(echo "$abuse_response"         | grep -o '"domain":"[^"]*"'                 | cut -d'"' -f4)

            echo ""
            print_kv "  [AbuseIPDB] Confidence Score" "${abuse_score}/100"
            print_kv "  [AbuseIPDB] Total Reports"    "$total_reports"
            print_kv "  [AbuseIPDB] Last Reported"    "${last_report:-Never}"
            print_kv "  [AbuseIPDB] Usage Type"       "${usage_type:-unknown}"
            print_kv "  [AbuseIPDB] Domain"           "${domain:-N/A}"

            report_append "$report" "AbuseIPDB Score: $abuse_score/100 | Reports: $total_reports | Type: $usage_type"

            if [[ -n "$abuse_score" ]]; then
                (( threat_score += abuse_score ))
                if [[ $abuse_score -ge ${ABUSEIPDB_THREAT_THRESHOLD:-25} ]]; then
                    details+=("AbuseIPDB score: ${abuse_score}/100")
                fi
            fi

            log_info "IPCHECK" "AbuseIPDB $ip: score=$abuse_score reports=$total_reports"
        else
            local error_msg
            error_msg=$(echo "$abuse_response" | grep -o '"detail":"[^"]*"' | cut -d'"' -f4)
            print_warn "  AbuseIPDB query failed: ${error_msg:-unknown error}"
        fi
    fi

    # ── VirusTotal ───────────────────────────────────────────────────────────
    if [[ -n "$VIRUSTOTAL_API_KEY" ]] && command -v curl &>/dev/null; then
        print_info "  Querying VirusTotal..."
        local vt_response
        vt_response=$(curl -s --max-time "${API_TIMEOUT:-10}" \
            "https://www.virustotal.com/api/v3/ip_addresses/${ip}" \
            -H "x-apikey: ${VIRUSTOTAL_API_KEY}" \
            2>/dev/null)

        if echo "$vt_response" | grep -q '"last_analysis_stats"'; then
            local vt_malicious vt_suspicious vt_clean vt_harmless
            vt_malicious=$(echo "$vt_response"   | grep -o '"malicious":[0-9]*'   | head -1 | cut -d: -f2)
            vt_suspicious=$(echo "$vt_response"  | grep -o '"suspicious":[0-9]*'  | head -1 | cut -d: -f2)
            vt_harmless=$(echo "$vt_response"    | grep -o '"harmless":[0-9]*'    | head -1 | cut -d: -f2)
            vt_clean=$(echo "$vt_response"       | grep -o '"undetected":[0-9]*'  | head -1 | cut -d: -f2)

            echo ""
            print_kv "  [VirusTotal] Malicious engines"  "${vt_malicious:-0}"
            print_kv "  [VirusTotal] Suspicious engines" "${vt_suspicious:-0}"
            print_kv "  [VirusTotal] Harmless"           "${vt_harmless:-0}"
            print_kv "  [VirusTotal] Undetected"         "${vt_clean:-0}"

            report_append "$report" "VirusTotal: Malicious=$vt_malicious Suspicious=$vt_suspicious Harmless=$vt_harmless"

            if [[ ${vt_malicious:-0} -gt 0 ]]; then
                (( threat_score += (vt_malicious * 10) ))
                details+=("VirusTotal: ${vt_malicious} engine(s) flagged malicious")
            fi

            log_info "IPCHECK" "VirusTotal $ip: malicious=$vt_malicious"
        else
            local vt_error
            vt_error=$(echo "$vt_response" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
            print_warn "  VirusTotal query failed: ${vt_error:-unknown error}"
        fi
    fi

    # ── Offline heuristics (when no API keys) ────────────────────────────────
    if [[ $api_available -eq 0 ]]; then
        _ipcheck_offline_heuristic "$ip" "$report" threat_score details
    fi

    # ── Final Verdict ─────────────────────────────────────────────────────────
    echo ""
    local display_score=$(( threat_score > 100 ? 100 : threat_score ))
    print_kv "  Combined Threat Score" "${display_score}/100"

    if [[ $display_score -ge 70 ]]; then
        verdict="MALICIOUS"
        print_critical "  VERDICT: ★ MALICIOUS — High confidence threat"
    elif [[ $display_score -ge 40 ]]; then
        verdict="MALICIOUS"
        print_alert "  VERDICT: ⚠ SUSPICIOUS — Likely malicious"
    elif [[ $display_score -ge 15 ]]; then
        verdict="UNKNOWN"
        print_warn "  VERDICT: ? SUSPICIOUS — Investigate further"
    else
        verdict="CLEAN"
        print_success "  VERDICT: ✔ CLEAN — No significant threats detected"
    fi

    if [[ ${#details[@]} -gt 0 ]]; then
        print_info "  Threat indicators:"
        for d in "${details[@]}"; do
            echo -e "    ${YELLOW}• $d${RESET}"
        done
    fi

    report_append "$report" "THREAT SCORE: $display_score/100"
    report_append "$report" "VERDICT: $verdict"
    log_info "IPCHECK" "IP $ip verdict: $verdict (score: $display_score)"

    echo "VERDICT:$verdict"
}

# ── Offline Heuristic Analysis ────────────────────────────────────────────────
_ipcheck_offline_heuristic() {
    local ip="$1"
    local report="$2"
    local -n _score=$3
    local -n _details=$4

    print_info "  Running offline heuristic checks..."

    # Check if IP resolves to known suspicious TLDs or patterns
    local rdns
    rdns=$(dig +short -x "$ip" 2>/dev/null | head -1)
    if [[ -n "$rdns" ]]; then
        print_kv "  Reverse DNS" "$rdns"
        # Flag dynamic/residential-looking hostnames
        if echo "$rdns" | grep -qiE "(dynamic|dsl|cable|pool|dhcp|ppp|customer|adsl|broadband)"; then
            (( _score += 15 ))
            _details+=("Reverse DNS suggests dynamic/residential IP")
        fi
    fi

    # Tor exit node check via local list (basic)
    # In real use, would check against DNSBL
    local tor_check
    tor_check=$(dig +short "${ip}.dnsel.torproject.org" 2>/dev/null)
    if [[ "$tor_check" == "127.0.0.2" ]]; then
        (( _score += 40 ))
        _details+=("Tor exit node detected")
        print_warn "  Tor exit node detected!"
    fi
}

# ── Summary Report ────────────────────────────────────────────────────────────
_ipcheck_summary() {
    local report="$1"
    local -n _malicious=$2
    local -n _clean=$3
    local -n _unknown=$4

    print_section "IP INTELLIGENCE SUMMARY"
    report_section "$report" "Summary"

    print_kv "Total IPs checked"  "$(( ${#_malicious[@]} + ${#_clean[@]} + ${#_unknown[@]} ))"
    print_kv "Malicious/Suspicious" "${#_malicious[@]}"
    print_kv "Clean"               "${#_clean[@]}"
    print_kv "Unknown/Inconclusive" "${#_unknown[@]}"

    report_append "$report" "Total IPs    : $(( ${#_malicious[@]} + ${#_clean[@]} + ${#_unknown[@]} ))"
    report_append "$report" "Malicious    : ${#_malicious[@]}"
    report_append "$report" "Clean        : ${#_clean[@]}"
    report_append "$report" "Unknown      : ${#_unknown[@]}"

    if [[ ${#_malicious[@]} -gt 0 ]]; then
        echo ""
        print_alert "Malicious IPs:"
        for ip in "${_malicious[@]}"; do
            print_critical "  ✘ $ip"
            report_append "$report" "MALICIOUS: $ip"
        done
    fi

    if [[ ${#_clean[@]} -gt 0 ]]; then
        echo ""
        print_success "Clean IPs:"
        for ip in "${_clean[@]}"; do
            echo -e "  ${GREEN}✔ $ip${RESET}"
            report_append "$report" "CLEAN: $ip"
        done
    fi
}
