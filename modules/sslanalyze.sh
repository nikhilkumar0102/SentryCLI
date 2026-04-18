#!/usr/bin/env bash
# =============================================================================
# SentryCLI - SSL/TLS Security Analyzer [SSL-15] - Enhanced
# modules/sslanalyze.sh
# Analyzes SSL/TLS certificate, cipher suites, protocol versions & vulnerabilities
# =============================================================================

run_sslanalyze() {

    print_section "15. SSL/TLS SECURITY ANALYZER [SSL-15]"

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

    # Normalize domain
    local domain
    domain=$(echo "$target" | sed -E 's|https?://||' | sed 's|/.*||' | tr -d '[:space:]' 2>/dev/null || true)

    local url="https://${domain}"

    # ── Initialize Report ──────────────────────────────────────────────────
    local report
    report=$(report_init "SSL_TLS_Analysis_${domain//[^a-zA-Z0-9._-]/_}")

    report_section "$report" "Scan Target"
    report_append "$report" "Target : ${domain}"
    report_append "$report" "URL    : ${url}"

    print_subsection "Performing SSL/TLS Security Analysis → ${domain}"
    echo ""

    # Check for required tools
    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed."
        report_finalize "$report"
        return 1
    fi

    if ! command -v openssl &>/dev/null; then
        print_warn "openssl not found. Some advanced checks will be limited."
    fi

    # ── Fetch SSL Information ──────────────────────────────────────────────
    print_info "Connecting to SSL/TLS endpoint..."

    local cert_info headers
    headers=$(curl -s -I -L --max-time 10 --connect-timeout 8 \
        -A "Mozilla/5.0 (compatible; SentryCLI/2.8)" "$url" 2>/dev/null) || true

    # Get certificate details using openssl
    cert_info=$(echo | openssl s_client -connect "${domain}:443" -servername "${domain}" \
        -quiet -no_check_time 2>/dev/null | openssl x509 -noout -text 2>/dev/null) || true

    # Fallback if openssl fails
    if [[ -z "$cert_info" ]]; then
        print_warn "openssl s_client failed. Falling back to basic curl check."
        cert_info=$(curl -s -v --max-time 8 "$url" 2>&1 | grep -E 'subject|issuer|expire|SSL' || true)
    fi

    if [[ -z "$cert_info" ]] && [[ -z "$headers" ]]; then
        print_alert "Could not establish SSL/TLS connection."
        report_append "$report" "ERROR: Unable to connect to SSL port 443"
        report_finalize "$report"
        return 1
    fi

    # ── Safe Helper ────────────────────────────────────────────────────────
    _detect() {
        echo "$1" | grep -qiE "$2" 2>/dev/null || false
    }

    # ── SSL/TLS Analysis ───────────────────────────────────────────────────
    local issuer expiry_days protocol cipher grade="Unknown"
    local issues=0

    # Issuer
    issuer=$(echo "$cert_info" | grep -i "Issuer:" | head -1 | sed 's/.*Issuer: //' 2>/dev/null || true)
    [[ -z "$issuer" ]] && issuer=$(echo "$cert_info" | grep -i "O=" | head -1 2>/dev/null || true)

    # Expiry
    local expiry_date
    expiry_date=$(echo "$cert_info" | grep -i "Not After" | head -1 | sed 's/.*Not After : //' 2>/dev/null || true)
    if [[ -n "$expiry_date" ]]; then
        expiry_days=$(date -d "$expiry_date" +%s 2>/dev/null)
        if [[ -n "$expiry_days" ]]; then
            expiry_days=$(( (expiry_days - $(date +%s)) / 86400 ))
        fi
    fi

    # Protocol & Cipher
    protocol=$(echo | openssl s_client -connect "${domain}:443" -servername "${domain}" \
        -quiet 2>&1 | grep -E 'Protocol|Cipher' | head -2 2>/dev/null || true)

    cipher=$(echo "$protocol" | grep -oE 'Cipher\s*:\s*[^ ]+' | cut -d':' -f2- | xargs 2>/dev/null || true)
    protocol=$(echo "$protocol" | grep -oE 'Protocol\s*:\s*[^ ]+' | cut -d':' -f2- | xargs 2>/dev/null || true)

    # Grade Calculation
    if _detect "$protocol" 'TLSv1\.3'; then
        grade="A+"
    elif _detect "$protocol" 'TLSv1\.2'; then
        grade="A"
    elif _detect "$protocol" 'TLSv1\.1|TLSv1'; then
        grade="C"
        ((issues++))
    else
        grade="F"
        ((issues++))
    fi

    if _detect "$cipher" 'RC4|DES|3DES|MD5|NULL|EXP|ADH'; then
        grade="D"
        ((issues++))
    fi

    # ── Report Writing ─────────────────────────────────────────────────────
    report_section "$report" "SSL/TLS Analysis Results"
    report_append "$report" "Issuer          : ${issuer:-Unknown}"
    report_append "$report" "Days to Expiry  : ${expiry_days:-Unknown}"
    report_append "$report" "Protocol        : ${protocol:-Unknown}"
    report_append "$report" "Cipher Suite    : ${cipher:-Unknown}"
    report_append "$report" "Overall Grade   : ${grade}"
    report_append "$report" "Issues Found    : ${issues}"

    # ── Display Results ────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}${WHITE}SSL/TLS SECURITY RESULTS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"         "$domain"
    print_kv "Issuer"         "${issuer:-Unknown}"
    print_kv "Days to Expiry" "${expiry_days:-Unknown}"
    print_kv "Protocol"       "${protocol:-Unknown}"
    print_kv "Cipher"         "${cipher:-Unknown}"
    print_kv "Security Grade" "${grade}"
    echo ""

    if [[ "$grade" == "A+" || "$grade" == "A" ]]; then
        print_success "Excellent SSL/TLS Configuration (${grade})"
    elif [[ "$grade" == "C" ]]; then
        print_warn "Average SSL/TLS — Upgrade recommended"
    else
        print_critical "Weak SSL/TLS Configuration (${grade}) — Immediate action needed!"
    fi

    # Expiry Warning
    if [[ -n "$expiry_days" ]] && [[ "$expiry_days" -lt 30 ]]; then
        print_critical "Certificate expires in ${expiry_days} days!"
    fi

    # ── Security Notes ─────────────────────────────────────────────────────
    report_section "$report" "Security Recommendations"
    echo ""
    echo -e "${BOLD}${WHITE}RECOMMENDATIONS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    if [[ "$grade" != "A+" ]]; then
        print_warn "Upgrade to TLS 1.3 only"
        print_warn "Use strong cipher suites (ECDHE + AES-GCM)"
    fi
    print_warn "Enable HSTS (Strict-Transport-Security)"
    print_warn "Use Let's Encrypt or Cloudflare for auto-renewal"
    echo ""

    # Raw Data
    report_section "$report" "Raw Certificate Information"
    echo "$cert_info" >> "$report" 2>/dev/null || true

    report_section "$report" "Raw HTTP Headers"
    printf '%s\n' "$headers" >> "$report" 2>/dev/null || true

    report_finalize "$report"
    log_success "SSLANALYZE" "Completed for $domain — Grade: $grade"

    # ── Summary ────────────────────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"         "$domain"
    print_kv "SSL Grade"      "$grade"
    print_kv "Expiry Days"    "${expiry_days:-N/A}"
    print_kv "Report Saved"   "$report"
    echo ""

    print_success "SSL/TLS Analysis completed successfully!"
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
    echo ""

    return 0
}
