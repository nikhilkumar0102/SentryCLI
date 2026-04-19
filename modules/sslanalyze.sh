#!/usr/bin/env bash
# =============================================================================
# SentryCLI - SSL/TLS Security Analyzer [SSL-15]
# modules/sslanalyze.sh
#
# Analyzes SSL/TLS certificate details, protocol versions, cipher suites,
# known vulnerabilities, and HSTS. Grades the configuration A+ to F.
#
# Pattern mirrors ipcheck.sh exactly:
#   - report_init / report_section / report_append / report_finalize
#   - || true on every pipeline that can return non-zero under set -e
#   - issues=$(( issues + 1 )) NOT (( issues++ ))  ← crash fix
#   - NEVER touches CURRENT_MODULE or MODULE_OPTS
# =============================================================================

run_sslanalyze() {

    print_section "15. SSL/TLS SECURITY ANALYZER [SSL-15]"

    # ── Resolve target ─────────────────────────────────────────────────────
    local target=""
    if   [[ -n "${MODULE_OPTS[target]:-}" ]]; then
        target="${MODULE_OPTS[target]}"
        print_info "Using REPL-set target → ${target}"
    elif [[ -n "${MODULE_OPTS[host]:-}" ]]; then
        target="${MODULE_OPTS[host]}"
        print_info "Using REPL-set target → ${target}"
    elif [[ -n "${1:-}" ]]; then
        target="$1"
    fi

    if [[ -z "$target" ]]; then
        echo -ne "${CYAN}Enter Target Domain (e.g. example.com): ${RESET}"
        read -r target
    fi

    [[ -z "$target" ]] && { print_alert "No target provided."; return 1; }

    # Strip scheme and path — work with bare domain only
    local domain
    domain=$(echo "$target" \
        | sed -E 's|https?://||' \
        | sed 's|/.*||' \
        | tr -d '[:space:]' 2>/dev/null) || true

    local url="https://${domain}"

    # ── Tool checks ────────────────────────────────────────────────────────
    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed."
        return 1
    fi

    local have_openssl=0
    command -v openssl &>/dev/null && have_openssl=1 || true

    if [[ $have_openssl -eq 0 ]]; then
        print_warn "openssl not found — certificate details will be limited"
    fi

    # ── Init report ────────────────────────────────────────────────────────
    local report
    report=$(report_init "SSL_TLS_${domain//[^a-zA-Z0-9._-]/_}")

    report_section "$report" "Scan Target"
    report_append  "$report" "Target : $domain"
    report_append  "$report" "URL    : $url"

    print_subsection "SSL/TLS Security Analysis → ${domain}"
    echo ""
    print_info "Connecting to port 443..."

    # ══════════════════════════════════════════════════════════════════════
    # STEP 1 — openssl s_client: full handshake output
    # ══════════════════════════════════════════════════════════════════════
    local sc_out=""
    local cert_text=""

    if [[ $have_openssl -eq 1 ]]; then
        # Full handshake — gives Protocol + Cipher line
        sc_out=$(echo Q | timeout 10 openssl s_client \
            -connect "${domain}:443" \
            -servername "${domain}" \
            -status \
            2>/dev/null) || true

        # Certificate text for field extraction
        cert_text=$(echo Q | timeout 10 openssl s_client \
            -connect "${domain}:443" \
            -servername "${domain}" \
            2>/dev/null \
            | openssl x509 -noout -text 2>/dev/null) || true
    fi

    # Basic curl connectivity check — also gets HSTS header
    local headers=""
    headers=$(curl -s -I -L \
        --max-time 10 --connect-timeout 8 \
        -A "Mozilla/5.0 (compatible; SentryCLI/2.8)" \
        "$url" 2>/dev/null) || true

    if [[ -z "$sc_out" ]] && [[ -z "$headers" ]]; then
        print_alert "Could not establish connection to ${domain}:443"
        report_append "$report" "ERROR: No SSL/TLS connection established"
        report_finalize "$report"
        log_error "SSLANALYZE" "No connection to $domain:443"
        return 1
    fi

    # ══════════════════════════════════════════════════════════════════════
    # STEP 2 — Extract certificate fields
    # Every grep MUST end with || true — no-match = exit 1 kills main.sh
    # ══════════════════════════════════════════════════════════════════════

    # ── TLS protocol version ───────────────────────────────────────────────
    # s_client prints "New, TLSv1.3, Cipher is ..." on the handshake line
    local tls_version=""
    tls_version=$(echo "$sc_out" \
        | grep -oE 'TLSv[0-9.]+|SSLv[0-9.]+' \
        | head -1 \
        | tr -d '\r\n' 2>/dev/null) || true

    # ── Negotiated cipher suite ────────────────────────────────────────────
    local cipher_suite=""
    cipher_suite=$(echo "$sc_out" \
        | grep "Cipher is" \
        | sed 's/.*Cipher is //' \
        | tr -d '\r\n' 2>/dev/null) || true

    # ── Server public key size ─────────────────────────────────────────────
    local key_bits=""
    key_bits=$(echo "$sc_out" \
        | grep -oE 'Server public key is [0-9]+ bit' \
        | grep -oE '[0-9]+' 2>/dev/null) || true

    # ── Certificate issuer ─────────────────────────────────────────────────
    local cert_issuer=""
    cert_issuer=$(echo "$cert_text" \
        | grep -i "Issuer:" \
        | head -1 \
        | sed 's/.*Issuer:[[:space:]]*//' \
        | tr -d '\r\n' 2>/dev/null) || true

    # ── Certificate subject / CN ───────────────────────────────────────────
    local cert_subject=""
    cert_subject=$(echo "$cert_text" \
        | grep -i "Subject:" \
        | grep -v "Public\|Alternative\|Issuer" \
        | head -1 \
        | sed 's/.*Subject:[[:space:]]*//' \
        | tr -d '\r\n' 2>/dev/null) || true

    # ── Subject Alternative Names ──────────────────────────────────────────
    local cert_sans=""
    cert_sans=$(echo "$cert_text" \
        | grep -A2 "Subject Alternative Name" \
        | grep "DNS:" \
        | sed 's/[[:space:]]//g' \
        | tr ',' '\n' \
        | grep "DNS:" \
        | head -8 \
        | tr '\n' ' ' 2>/dev/null) || true

    # ── Signature algorithm ────────────────────────────────────────────────
    local sig_algo=""
    sig_algo=$(echo "$cert_text" \
        | grep -i "Signature Algorithm" \
        | head -1 \
        | sed 's/.*Signature Algorithm:[[:space:]]*//' \
        | tr -d '\r\n' 2>/dev/null) || true

    # ── Validity dates ─────────────────────────────────────────────────────
    local not_before="" not_after=""
    not_before=$(echo "$cert_text" \
        | grep -i "Not Before" \
        | head -1 \
        | sed 's/.*Not Before:[[:space:]]*//' \
        | tr -d '\r\n' 2>/dev/null) || true

    not_after=$(echo "$cert_text" \
        | grep -i "Not After" \
        | head -1 \
        | sed 's/.*Not After[[:space:]]*:[[:space:]]*//' \
        | tr -d '\r\n' 2>/dev/null) || true

    # ── Days until expiry ──────────────────────────────────────────────────
    local expiry_days="Unknown"
    if [[ -n "$not_after" ]]; then
        local expiry_epoch now_epoch
        expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null) || true
        now_epoch=$(date +%s 2>/dev/null) || true
        if [[ -n "$expiry_epoch" ]] && [[ -n "$now_epoch" ]]; then
            expiry_days=$(( (expiry_epoch - now_epoch) / 86400 ))
        fi
    fi

    # ── OCSP Stapling ─────────────────────────────────────────────────────
    local ocsp_status=""
    ocsp_status=$(echo "$sc_out" \
        | grep -i "OCSP response" \
        | head -1 \
        | tr -d '\r\n' 2>/dev/null) || true
    [[ -z "$ocsp_status" ]] && ocsp_status="Not stapled"

    # ── HSTS header ────────────────────────────────────────────────────────
    local hsts_header=""
    hsts_header=$(echo "$headers" \
        | grep -i "^Strict-Transport-Security:" \
        | head -1 \
        | cut -d':' -f2- \
        | sed 's/^[[:space:]]*//' \
        | tr -d '\r\n' 2>/dev/null) || true

    # ── Certificate transparency (SCT) ─────────────────────────────────────
    local ct_status=""
    ct_status=$(echo "$sc_out" \
        | grep -i "Signed Certificate Timestamp\|sct" \
        | head -1 \
        | tr -d '\r\n' 2>/dev/null) || true
    [[ -z "$ct_status" ]] && ct_status="Not detected"

    # ══════════════════════════════════════════════════════════════════════
    # STEP 3 — Protocol version probes (check what old versions are accepted)
    # ══════════════════════════════════════════════════════════════════════
    print_info "Probing legacy protocol support..."

    # _ssl_probe <openssl_flag> <label>
    # Returns "SUPPORTED" or "REJECTED" safely under set -e
    _ssl_probe() {
        local flag="$1"
        local result
        result=$(echo Q | timeout 6 openssl s_client \
            -connect "${domain}:443" \
            -servername "${domain}" \
            "${flag}" 2>&1) || true
        if echo "$result" | grep -qi "CONNECTED" 2>/dev/null || false; then
            echo "SUPPORTED"
        else
            echo "REJECTED"
        fi
    }

    local proto_tls13="N/A" proto_tls12="N/A" proto_tls11="N/A" proto_tls10="N/A" proto_ssl3="N/A"

    if [[ $have_openssl -eq 1 ]]; then
        # TLS 1.3
        if openssl s_client -help 2>&1 | grep -q "tls1_3" 2>/dev/null || false; then
            proto_tls13=$(_ssl_probe "-tls1_3")
        fi
        proto_tls12=$(_ssl_probe "-tls1_2")
        proto_tls11=$(_ssl_probe "-tls1_1")
        proto_tls10=$(_ssl_probe "-tls1")
        # SSLv3 — most openssl builds have it disabled
        proto_ssl3=$(echo Q | timeout 6 openssl s_client \
            -connect "${domain}:443" \
            -servername "${domain}" \
            -ssl3 2>&1 \
            | grep -q "CONNECTED" 2>/dev/null \
            && echo "SUPPORTED" || echo "REJECTED") || true
    fi

    # ══════════════════════════════════════════════════════════════════════
    # STEP 4 — Vulnerability checks
    # ══════════════════════════════════════════════════════════════════════
    local -a vulns=()
    local -a passes=()

    # POODLE — SSLv3 accepted
    if [[ "$proto_ssl3" == "SUPPORTED" ]]; then
        vulns+=("POODLE (SSLv3 accepted — server accepts downgrade)")
    else
        passes+=("POODLE — SSLv3 rejected ✔")
    fi

    # BEAST — TLS 1.0 accepted
    if [[ "$proto_tls10" == "SUPPORTED" ]]; then
        vulns+=("BEAST (TLS 1.0 accepted — CBC-mode cipher risk)")
    else
        passes+=("BEAST — TLS 1.0 rejected ✔")
    fi

    # SWEET32 — 3DES cipher
    if echo "$cipher_suite" | grep -qi "3DES\|DES-CBC3" 2>/dev/null || false; then
        vulns+=("SWEET32 (3DES cipher negotiated)")
    else
        passes+=("SWEET32 — 3DES not negotiated ✔")
    fi

    # EXPORT / FREAK — weak export ciphers
    if echo "$sc_out" | grep -qiE "EXP-|EXPORT" 2>/dev/null || false; then
        vulns+=("FREAK / EXPORT cipher negotiated")
    else
        passes+=("FREAK — no EXPORT ciphers ✔")
    fi

    # RC4 — broken stream cipher
    if echo "$cipher_suite" | grep -qi "RC4" 2>/dev/null || false; then
        vulns+=("RC4 cipher negotiated (broken stream cipher)")
    else
        passes+=("RC4 — not negotiated ✔")
    fi

    # NULL cipher
    if echo "$cipher_suite" | grep -qi "NULL" 2>/dev/null || false; then
        vulns+=("NULL cipher — no encryption")
    else
        passes+=("NULL cipher — not used ✔")
    fi

    # Weak key size
    if [[ -n "$key_bits" ]] && [[ "$key_bits" -lt 2048 ]] 2>/dev/null; then
        vulns+=("Weak RSA key: ${key_bits} bits (minimum 2048 required)")
    elif [[ -n "$key_bits" ]]; then
        passes+=("Key size: ${key_bits} bits ✔")
    fi

    # SHA-1 signature
    if echo "$sig_algo" | grep -qi "sha1\|sha-1" 2>/dev/null || false; then
        vulns+=("SHA-1 signature algorithm (deprecated, browser-distrusted)")
    else
        passes+=("Signature algorithm: ${sig_algo:-unknown} ✔")
    fi

    # Self-signed
    if [[ -n "$cert_issuer" ]] && [[ -n "$cert_subject" ]]; then
        local issuer_cn subject_cn
        issuer_cn=$(echo "$cert_issuer" | grep -oE 'CN=[^,]+' | head -1 2>/dev/null) || true
        subject_cn=$(echo "$cert_subject" | grep -oE 'CN=[^,]+' | head -1 2>/dev/null) || true
        if [[ -n "$issuer_cn" ]] && [[ "$issuer_cn" == "$subject_cn" ]]; then
            vulns+=("Self-signed certificate (not trusted by browsers)")
        fi
    fi

    # HSTS missing
    if [[ -z "$hsts_header" ]]; then
        vulns+=("HSTS missing — vulnerable to SSL-stripping attacks")
    else
        passes+=("HSTS present: $hsts_header ✔")
    fi

    # Certificate expiry
    if [[ "$expiry_days" != "Unknown" ]]; then
        if [[ "$expiry_days" -lt 0 ]] 2>/dev/null; then
            vulns+=("Certificate EXPIRED ${expiry_days#-} days ago!")
        elif [[ "$expiry_days" -lt 14 ]] 2>/dev/null; then
            vulns+=("Certificate expires in ${expiry_days} days — CRITICAL")
        elif [[ "$expiry_days" -lt 30 ]] 2>/dev/null; then
            vulns+=("Certificate expires in ${expiry_days} days — renew soon")
        else
            passes+=("Certificate valid for ${expiry_days} more days ✔")
        fi
    fi

    # ══════════════════════════════════════════════════════════════════════
    # STEP 5 — Grade calculation
    # Uses issues=$(( issues + 1 )) NOT (( issues++ ))
    # (( issues++ )) when issues=0 returns exit code 1 = kills main.sh
    # ══════════════════════════════════════════════════════════════════════
    local grade="A+" grade_color="$GREEN"
    local issues=0

    # Degrade based on TLS version
    if   [[ "$tls_version" == "TLSv1.3" ]]; then
        : # stays A+
    elif [[ "$tls_version" == "TLSv1.2" ]]; then
        grade="A"
    elif [[ "$tls_version" == "TLSv1.1" ]]; then
        grade="C"; issues=$(( issues + 1 ))
    elif [[ "$tls_version" == "TLSv1" ]]; then
        grade="C"; issues=$(( issues + 1 ))
    elif [[ -n "$tls_version" ]]; then
        grade="F"; issues=$(( issues + 1 ))
    fi

    # Degrade for old protocol support
    [[ "$proto_ssl3" == "SUPPORTED" ]]  && { grade="F"; issues=$(( issues + 1 )); }
    [[ "$proto_tls10" == "SUPPORTED" ]] && { [[ "$grade" == "A+" || "$grade" == "A" ]] && grade="B"; issues=$(( issues + 1 )); } || true
    [[ "$proto_tls11" == "SUPPORTED" ]] && { [[ "$grade" == "A+" || "$grade" == "A" ]] && grade="B"; issues=$(( issues + 1 )); } || true

    # Degrade for weak ciphers
    if echo "$cipher_suite" | grep -qiE 'RC4|DES|3DES|NULL|EXP|ADH|MD5' 2>/dev/null || false; then
        grade="D"; issues=$(( issues + 1 ))
    fi

    # Degrade for weak key
    if [[ -n "$key_bits" ]] && [[ "$key_bits" -lt 2048 ]] 2>/dev/null; then
        grade="F"; issues=$(( issues + 1 ))
    fi

    # Degrade for SHA-1
    if echo "$sig_algo" | grep -qi "sha1\|sha-1" 2>/dev/null || false; then
        [[ "$grade" == "A+" || "$grade" == "A" ]] && grade="B"
        issues=$(( issues + 1 ))
    fi

    # Degrade for missing HSTS
    [[ -z "$hsts_header" ]] && { [[ "$grade" == "A+" ]] && grade="A"; issues=$(( issues + 1 )); } || true

    # Degrade for vulnerability count
    [[ ${#vulns[@]} -ge 3 ]] && grade="D"
    [[ ${#vulns[@]} -ge 5 ]] && grade="F"

    # Set grade color
    case "$grade" in
        "A+") grade_color="$GREEN"  ;;
        "A")  grade_color="$GREEN"  ;;
        "B")  grade_color="$YELLOW" ;;
        "C")  grade_color="$YELLOW" ;;
        "D")  grade_color="$RED"    ;;
        "F")  grade_color="$RED"    ;;
    esac

    # ══════════════════════════════════════════════════════════════════════
    # DISPLAY RESULTS
    # ══════════════════════════════════════════════════════════════════════

    # ── Certificate Info ───────────────────────────────────────────────────
    report_section "$report" "Certificate Information"

    echo -e "${BOLD}${WHITE}CERTIFICATE INFORMATION${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Domain"          "$domain"
    print_kv "Subject"         "${cert_subject:-Unknown}"
    print_kv "Issuer"          "${cert_issuer:-Unknown}"
    print_kv "SANs"            "${cert_sans:-Unknown}"
    print_kv "Valid From"      "${not_before:-Unknown}"
    print_kv "Expires"         "${not_after:-Unknown}"
    print_kv "Days Remaining"  "${expiry_days}"
    print_kv "Key Size"        "${key_bits:+${key_bits} bits}${key_bits:-Unknown}"
    print_kv "Sig Algorithm"   "${sig_algo:-Unknown}"
    print_kv "OCSP Stapling"   "$ocsp_status"
    print_kv "CT (SCT)"        "$ct_status"
    echo ""

    report_append "$report" "Subject        : ${cert_subject:-Unknown}"
    report_append "$report" "Issuer         : ${cert_issuer:-Unknown}"
    report_append "$report" "SANs           : ${cert_sans:-Unknown}"
    report_append "$report" "Valid From     : ${not_before:-Unknown}"
    report_append "$report" "Expires        : ${not_after:-Unknown}"
    report_append "$report" "Days Remaining : ${expiry_days}"
    report_append "$report" "Key Size       : ${key_bits:+${key_bits} bits}${key_bits:-Unknown}"
    report_append "$report" "Sig Algorithm  : ${sig_algo:-Unknown}"
    report_append "$report" "OCSP Stapling  : $ocsp_status"

    # Expiry warning
    if [[ "$expiry_days" != "Unknown" ]]; then
        if [[ "$expiry_days" -lt 0 ]] 2>/dev/null; then
            print_critical "Certificate has EXPIRED!"
        elif [[ "$expiry_days" -lt 14 ]] 2>/dev/null; then
            print_critical "Certificate expires in ${expiry_days} days — renew IMMEDIATELY"
        elif [[ "$expiry_days" -lt 30 ]] 2>/dev/null; then
            print_warn "Certificate expires in ${expiry_days} days — renew soon"
        else
            print_success "Certificate valid for ${expiry_days} more days"
        fi
    fi
    echo ""

    # ── TLS Configuration ──────────────────────────────────────────────────
    report_section "$report" "TLS Configuration"

    echo -e "${BOLD}${WHITE}TLS CONFIGURATION${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Negotiated Version" "${tls_version:-Unknown}"
    print_kv "Cipher Suite"       "${cipher_suite:-Unknown}"
    print_kv "HSTS"               "${hsts_header:-MISSING}"
    echo ""

    # Protocol support table
    echo -e "  ${BOLD}Protocol Support:${RESET}"
    _proto_line() {
        local label="$1" status="$2" safe="$3"
        if [[ "$status" == "SUPPORTED" ]]; then
            if [[ "$safe" == "yes" ]]; then
                printf "    ${GREEN}✔${RESET}  %-12s ${GREEN}Supported${RESET}\n" "$label"
            else
                printf "    ${RED}✘${RESET}  %-12s ${RED}Supported (INSECURE)${RESET}\n" "$label"
            fi
        elif [[ "$status" == "REJECTED" ]]; then
            printf "    ${GREEN}✔${RESET}  %-12s ${DIM}Rejected (good)${RESET}\n" "$label"
        else
            printf "    ${DIM}?${RESET}  %-12s ${DIM}N/A / not tested${RESET}\n" "$label"
        fi
    }
    _proto_line "TLS 1.3"  "$proto_tls13"  "yes"
    _proto_line "TLS 1.2"  "$proto_tls12"  "yes"
    _proto_line "TLS 1.1"  "$proto_tls11"  "no"
    _proto_line "TLS 1.0"  "$proto_tls10"  "no"
    _proto_line "SSL 3.0"  "$proto_ssl3"   "no"
    echo ""

    report_append "$report" "Negotiated TLS : ${tls_version:-Unknown}"
    report_append "$report" "Cipher Suite   : ${cipher_suite:-Unknown}"
    report_append "$report" "HSTS           : ${hsts_header:-MISSING}"
    report_append "$report" "TLS 1.3        : $proto_tls13"
    report_append "$report" "TLS 1.2        : $proto_tls12"
    report_append "$report" "TLS 1.1        : $proto_tls11"
    report_append "$report" "TLS 1.0        : $proto_tls10"
    report_append "$report" "SSL 3.0        : $proto_ssl3"

    # ── Vulnerability Summary ──────────────────────────────────────────────
    report_section "$report" "Vulnerability Assessment"

    echo -e "${BOLD}${WHITE}VULNERABILITY ASSESSMENT${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    if [[ ${#vulns[@]} -gt 0 ]]; then
        for v in "${vulns[@]}"; do
            print_critical "$v"
            report_append "$report" "[VULN] $v"
        done
    else
        print_success "No known vulnerabilities detected"
        report_append "$report" "No vulnerabilities detected"
    fi
    echo ""

    if [[ ${#passes[@]} -gt 0 ]]; then
        echo -e "  ${BOLD}${WHITE}Passed Checks:${RESET}"
        for p in "${passes[@]}"; do
            echo -e "    ${GREEN}✔${RESET}  ${DIM}${p}${RESET}"
            report_append "$report" "[PASS] $p"
        done
    fi
    echo ""

    # ── Security Grade ─────────────────────────────────────────────────────
    report_section "$report" "Security Grade"
    report_append  "$report" "Grade  : $grade"
    report_append  "$report" "Issues : $issues"

    echo -e "${BOLD}${WHITE}SECURITY GRADE${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    echo -e "  Grade  : ${grade_color}${BOLD}${grade}${RESET}"
    echo -e "  Issues : ${grade_color}${issues}${RESET} found"
    echo ""

    case "$grade" in
        "A+") print_success "Excellent SSL/TLS configuration — industry best practice" ;;
        "A")  print_success "Good SSL/TLS configuration" ;;
        "B")  print_warn    "Acceptable — minor improvements recommended" ;;
        "C")  print_warn    "Below standard — legacy protocols should be disabled" ;;
        "D")  print_alert   "Weak configuration — immediate remediation required" ;;
        "F")  print_critical "Critical SSL/TLS failures — urgent action required" ;;
    esac
    echo ""

    # ── Recommendations ────────────────────────────────────────────────────
    report_section "$report" "Recommendations"

    echo -e "${BOLD}${WHITE}RECOMMENDATIONS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    [[ "$proto_tls13" != "SUPPORTED" ]] && {
        print_warn "Enable TLS 1.3 — significantly stronger than TLS 1.2"
        report_append "$report" "REC: Enable TLS 1.3"
    }
    [[ "$proto_tls11" == "SUPPORTED" ]] && {
        print_warn "Disable TLS 1.1 — deprecated by RFC 8996"
        report_append "$report" "REC: Disable TLS 1.1"
    }
    [[ "$proto_tls10" == "SUPPORTED" ]] && {
        print_warn "Disable TLS 1.0 — deprecated by RFC 8996"
        report_append "$report" "REC: Disable TLS 1.0"
    }
    [[ "$proto_ssl3" == "SUPPORTED" ]] && {
        print_critical "Disable SSLv3 immediately — POODLE attack vector"
        report_append "$report" "REC: Disable SSLv3 immediately (POODLE)"
    }
    [[ -z "$hsts_header" ]] && {
        print_warn "Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        report_append "$report" "REC: Add HSTS header with preload"
    }
    if [[ -n "$key_bits" ]] && [[ "$key_bits" -lt 2048 ]] 2>/dev/null; then
        print_critical "Upgrade RSA key to minimum 2048 bits (prefer 4096 or ECDSA P-256)"
        report_append "$report" "REC: Upgrade to RSA-4096 or ECDSA P-256"
    fi
    echo -e "  ${DIM}Recommended ciphers: ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256${RESET}"
    echo -e "  ${DIM}Use Mozilla SSL Config Generator: ssl-config.mozilla.org${RESET}"
    report_append "$report" "REF: https://ssl-config.mozilla.org"
    echo ""

    # ── Raw data in report ─────────────────────────────────────────────────
    report_section "$report" "Raw openssl s_client Output"
    printf '%s\n' "$sc_out" >> "$report" 2>/dev/null || true

    report_section "$report" "Raw Certificate Text"
    printf '%s\n' "$cert_text" >> "$report" 2>/dev/null || true

    report_section "$report" "Raw HTTP Headers"
    printf '%s\n' "$headers" >> "$report" 2>/dev/null || true

    # ── Finalize ───────────────────────────────────────────────────────────
    report_finalize "$report"
    log_success "SSLANALYZE" "Completed for $domain — Grade: $grade (${issues} issues, ${#vulns[@]} vulns)"

    # ── Summary ────────────────────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"           "$domain"
    print_kv "TLS Version"      "${tls_version:-Unknown}"
    print_kv "Cipher Suite"     "${cipher_suite:-Unknown}"
    print_kv "Days to Expiry"   "${expiry_days}"
    print_kv "Vulnerabilities"  "${#vulns[@]} found"
    print_kv "Security Grade"   "$grade"
    print_kv "Report Saved"     "$report"
    echo ""

    print_success "SSL/TLS Analysis completed successfully!"
    echo ""

    # ── Return to REPL ─────────────────────────────────────────────────────
    # NEVER touch CURRENT_MODULE or MODULE_OPTS — main.sh owns that state.
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
    echo ""

    return 0
}
