#!/usr/bin/env bash
# =============================================================================
# SentryCLI - WAF Detector [WAF-14] - Enhanced
# modules/wafdetect.sh
# Detects Web Application Firewalls (Cloudflare, Sucuri, ModSecurity, Akamai, etc.)
# =============================================================================

run_wafdetect() {

    print_section "14. WAF DETECTOR [WAF-14]"

    # ── Resolve target ─────────────────────────────────────────────────────
    local target=""
    if [[ -n "${MODULE_OPTS[target]:-}" ]]; then
        target="${MODULE_OPTS[target]}"
        print_info "Using REPL-set target → ${target}"
    elif [[ -n "${MODULE_OPTS[host]:-}" ]]; then
        target="${MODULE_OPTS[host]}"
        print_info "Using REPL-set target → ${target}"
    elif [[ -n "${1:-}" ]]; then
        target="$1"
    fi

    if [[ -z "$target" ]]; then
        echo -ne "${CYAN}Enter Target Domain/URL (e.g. example.com): ${RESET}"
        read -r target
    fi

    [[ -z "$target" ]] && { print_alert "No target provided."; return 1; }

    # Normalize
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="https://${target}"
    fi

    local domain
    domain=$(echo "$target" | sed -E 's|https?://||' | sed 's|/.*||' | tr -d '[:space:]' 2>/dev/null || true)

    # ── Init Report ────────────────────────────────────────────────────────
    local report
    report=$(report_init "WAF_Detection_${domain//[^a-zA-Z0-9._-]/_}")

    report_section "$report" "Scan Target"
    report_append "$report" "Target : $target"
    report_append "$report" "Domain : $domain"

    print_subsection "Analyzing WAF Protection on → ${domain}"
    echo ""

    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed."
        report_finalize "$report"
        return 1
    fi

    # ── Fetch normal response ──────────────────────────────────────────────
    print_info "Sending detection probes..."

    local headers body
    headers=$(curl -s -I -L --max-time 12 --connect-timeout 8 \
        -A "Mozilla/5.0 (compatible; SentryCLI/2.8)" \
        "$target" 2>/dev/null) || true

    body=$(curl -s -L --max-time 15 --connect-timeout 8 \
        -A "Mozilla/5.0 (compatible; SentryCLI/2.8)" \
        "$target" 2>/dev/null) || true

    # HTTP fallback
    if [[ -z "$headers" ]] && [[ -z "$body" ]] && [[ "$target" =~ ^https:// ]]; then
        local http_target="http://${target#https://}"
        print_warn "HTTPS unreachable — retrying with HTTP..."
        headers=$(curl -s -I -L --max-time 12 --connect-timeout 8 \
            -A "Mozilla/5.0 (compatible; SentryCLI/2.8)" "$http_target" 2>/dev/null) || true
        body=$(curl -s -L --max-time 15 --connect-timeout 8 \
            -A "Mozilla/5.0 (compatible; SentryCLI/2.8)" "$http_target" 2>/dev/null) || true
        target="$http_target"
        report_append "$report" "URL (fallback) : $target"
    fi

    if [[ -z "$headers" ]] && [[ -z "$body" ]]; then
        print_alert "No response from target."
        report_append "$report" "ERROR: No response received."
        report_finalize "$report"
        return 1
    fi

    # ── Safe detection helper ──────────────────────────────────────────────
    _detect() {
        echo "$1" | grep -qiE "$2" 2>/dev/null || false
    }

    _header() {
        printf '%s' "$headers" | grep -i "^${1}:" | head -1 \
            | cut -d':' -f2- | sed 's/^[[:space:]]*//' | tr -d '\r' 2>/dev/null || true
    }

    # ── WAF Detection Logic (Enhanced with multiple vectors) ───────────────
    local waf_found="None / Not Detected"
    local confidence=0
    local evidence=""

    # Cloudflare
    if _detect "$headers" 'cloudflare|cf-ray|cf-cache-status|__cfduid|cf-request-id'; then
        waf_found="Cloudflare"
        confidence=95
        evidence="CF-Ray / CF-Cache-Status headers"

    # Sucuri
    elif _detect "$headers" 'sucuri|x-sucuri|cloudproxy'; then
        waf_found="Sucuri CloudProxy"
        confidence=92
        evidence="X-Sucuri / CloudProxy headers"

    # ModSecurity / OWASP
    elif _detect "$headers $body" 'mod_security|modsecurity|owasp'; then
        waf_found="ModSecurity (OWASP)"
        confidence=85
        evidence="ModSecurity signature"

    # Akamai
    elif _detect "$headers" 'akamai|akamai-gtm|edgekey'; then
        waf_found="Akamai"
        confidence=88
        evidence="Akamai headers"

    # AWS WAF
    elif _detect "$headers" 'awselb|aws-waf|waf'; then
        waf_found="AWS WAF"
        confidence=87
        evidence="AWS WAF / ELB headers"

    # Imperva / Incapsula
    elif _detect "$headers" 'imperva|incapsula|x-cdn|incap'; then
        waf_found="Imperva / Incapsula"
        confidence=90
        evidence="Imperva / Incap headers"

    # Fastly
    elif _detect "$headers" 'fastly|surrogate-key|x-fastly'; then
        waf_found="Fastly Next-Gen WAF"
        confidence=82
        evidence="Fastly headers"

    # Wordfence (WordPress specific)
    elif _detect "$body" 'wordfence|wf-alert|blocked by wordfence'; then
        waf_found="Wordfence WAF"
        confidence=80
        evidence="Wordfence block signature"

    # Generic WAF signatures
    elif _detect "$body" 'blocked|forbidden|security|waf|firewall|403 forbidden'; then
        waf_found="Generic / Unknown WAF"
        confidence=60
        evidence="Generic blocking pattern detected"
    fi

    # ── Extract key headers for report ─────────────────────────────────────
    local h_server h_cf h_via
    h_server=$(_header "Server")
    h_cf=$(_header "CF-Ray")
    h_via=$(_header "Via")

    # ── Report & Display ───────────────────────────────────────────────────
    report_section "$report" "WAF Detection Results"
    report_append "$report" "Detected WAF     : $waf_found"
    report_append "$report" "Confidence       : ${confidence}%"
    report_append "$report" "Evidence         : ${evidence:-N/A}"
    report_append "$report" "Server Header    : ${h_server:-Not disclosed}"
    report_append "$report" "Cloudflare Ray   : ${h_cf:-None}"

    echo ""
    echo -e "${BOLD}${WHITE}WAF DETECTION RESULTS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"      "$target"
    print_kv "Detected WAF" "$waf_found"
    print_kv "Confidence"   "${confidence}%"
    print_kv "Evidence"     "${evidence:-N/A}"
    print_kv "Server"       "${h_server:-Not disclosed}"
    echo ""

    if [[ "$confidence" -ge 75 ]]; then
        print_success "WAF Identified: ${waf_found} (${confidence}%)"
    elif [[ "$waf_found" == "None / Not Detected" ]]; then
        print_warn "No WAF detected — target may be unprotected"
    else
        print_warn "Possible WAF detected (medium confidence)"
    fi

    # ── Security Notes ─────────────────────────────────────────────────────
    report_section "$report" "Security Notes"
    echo ""
    echo -e "${BOLD}${WHITE}SECURITY NOTES${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    if [[ "$waf_found" == "Cloudflare" ]]; then
        print_info "Cloudflare detected — strong default protection"
        print_warn "Check Security Level, WAF rules, and Bot Fight Mode"
    elif [[ "$waf_found" == "Sucuri CloudProxy" ]]; then
        print_info "Sucuri detected — good malware & DDoS protection"
    elif [[ "$waf_found" == "ModSecurity (OWASP)" ]]; then
        print_warn "ModSecurity is present — common false positives on aggressive scans"
    elif [[ "$waf_found" == "None / Not Detected" ]]; then
        print_critical "No WAF detected — consider adding Cloudflare / Sucuri / ModSecurity"
    else
        print_info "WAF detected — good baseline protection"
    fi
    echo ""

    # Raw headers
    report_section "$report" "Raw HTTP Headers"
    printf '%s\n' "$headers" >> "$report" 2>/dev/null || true

    report_finalize "$report"
    log_success "WAFDETECT" "Scan complete for $domain — $waf_found (${confidence}%)"

    # ── Summary ────────────────────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"      "$domain"
    print_kv "WAF"         "$waf_found"
    print_kv "Confidence"  "${confidence}%"
    print_kv "Report Saved" "$report"
    echo ""

    print_success "WAF Detection completed successfully!"
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
    echo ""

    return 0
}
             
