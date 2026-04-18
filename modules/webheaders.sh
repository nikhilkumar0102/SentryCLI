#!/usr/bin/env bash
# =============================================================================
# SentryCLI - HTTP Security Headers Analyzer Module [WEB-9]
# modules/webheaders.sh
# =============================================================================

run_webheaders() {

    print_section "9. HTTP SECURITY HEADERS ANALYZER [WEB-9]"

    # ── Resolve target ─────────────────────────────────────────────────────
    local target=""

    if   [[ -n "${MODULE_OPTS[target]:-}" ]]; then
        target="${MODULE_OPTS[target]}"
        print_info "Using REPL-set target → ${target}"
    elif [[ -n "${MODULE_OPTS[url]:-}" ]]; then
        target="${MODULE_OPTS[url]}"
        print_info "Using REPL-set target → ${target}"
    elif [[ -n "${1:-}" ]]; then
        target="$1"
    fi

    if [[ -z "$target" ]]; then
        echo -ne "${CYAN}Enter target URL or domain (e.g. example.com): ${RESET}"
        read -r target
    fi

    [[ -z "$target" ]] && { print_alert "No target provided."; return 1; }

    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed."
        return 1
    fi

    # ── Normalize URL ──────────────────────────────────────────────────────
    local url="$target"
    if [[ ! "$url" =~ ^https?:// ]]; then
        url="https://${target}"
    fi

    # ── Init report ────────────────────────────────────────────────────────
    local report
    report=$(report_init "WebHeaders_${target//[^a-zA-Z0-9._-]/_}")

    report_section "$report" "Scan Target"
    report_append  "$report" "Target : $target"
    report_append  "$report" "URL    : $url"

    print_subsection "Fetching headers from ${url}"
    echo ""
    print_info "Sending request..."

    # ── Fetch headers ──────────────────────────────────────────────────────
    local raw_headers=""
    raw_headers=$(curl -s -D - -o /dev/null \
        --max-time 15 --connect-timeout 8 --max-redirs 5 -L \
        -A "Mozilla/5.0 (compatible; SentryCLI/2.7)" \
        "$url" 2>/dev/null) || true

    # Fallback http
    if [[ -z "$raw_headers" ]] && [[ "$url" =~ ^https:// ]]; then
        local http_url="http://${url#https://}"
        print_warn "HTTPS unreachable — retrying with HTTP..."
        raw_headers=$(curl -s -D - -o /dev/null \
            --max-time 15 --connect-timeout 8 --max-redirs 5 -L \
            -A "Mozilla/5.0 (compatible; SentryCLI/2.7)" \
            "$http_url" 2>/dev/null) || true
        url="$http_url"
        report_append "$report" "URL (fallback) : $url"
    fi

    if [[ -z "$raw_headers" ]]; then
        print_alert "No response from ${url}."
        report_append "$report" "ERROR: No response received."
        report_finalize "$report"
        log_error "WEBHEADERS" "No response from $url"
        return 1
    fi

    # ── Header extractor ───────────────────────────────────────────────────
    # CRITICAL: must end with '|| true' so grep exit-1 (no match) never
    # triggers set -e and kills main.sh. This was the root crash cause.
    _wh_get() {
        printf '%s' "$raw_headers" \
            | grep -i "^${1}:" \
            | head -1 \
            | cut -d':' -f2- \
            | sed 's/^[[:space:]]*//' \
            | tr -d '\r\n' \
            || true
    }

    # ── Parse headers ──────────────────────────────────────────────────────
    local status="" server="" content_type=""
    local hsts="" xframe="" xcto="" xss="" csp="" referrer="" permissions="" cto="" feature=""

    status=$(printf '%s' "$raw_headers"  | grep -i "^HTTP/"  | tail -1 | tr -d '\r' || true)
    server=$(_wh_get "Server")
    content_type=$(_wh_get "Content-Type")
    hsts=$(_wh_get "Strict-Transport-Security")
    xframe=$(_wh_get "X-Frame-Options")
    xcto=$(_wh_get "X-Content-Type-Options")
    xss=$(_wh_get "X-XSS-Protection")
    csp=$(_wh_get "Content-Security-Policy")
    referrer=$(_wh_get "Referrer-Policy")
    permissions=$(_wh_get "Permissions-Policy")
    feature=$(_wh_get "Feature-Policy")
    cto=$(_wh_get "Cross-Origin-Opener-Policy")

    # ── Score setup ────────────────────────────────────────────────────────
    # Use var=$(( var + 1 )) NOT (( var++ )) — (( 0 )) returns exit 1 under set -e
    local score=0
    local max_score=8
    local missing_headers=()
    local present_headers=()

    # ── CONNECTION INFO ────────────────────────────────────────────────────
    report_section "$report" "Connection Info"
    report_append  "$report" "Status       : ${status:-Unknown}"
    report_append  "$report" "Server       : ${server:-Not disclosed}"
    report_append  "$report" "Content-Type : ${content_type:-Not set}"

    echo -e "${BOLD}${WHITE}CONNECTION INFO${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "URL"          "$url"
    print_kv "Status"       "${status:-Unknown}"
    print_kv "Server"       "${server:-Not disclosed}"
    print_kv "Content-Type" "${content_type:-Not set}"
    echo ""

    # ── SECURITY HEADERS ──────────────────────────────────────────────────
    report_section "$report" "Security Headers"

    echo -e "${BOLD}${WHITE}SECURITY HEADERS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    _wh_check() {
        local label="$1" value="$2" hname="$3"
        if [[ -n "$value" ]]; then
            printf "  ${GREEN}✔${RESET}  %-38s ${GREEN}%s${RESET}\n" "$label" "${value:0:55}"
            present_headers+=("$hname")
            report_append "$report" "[PASS]    ${hname}: ${value}"
            score=$(( score + 1 ))
        else
            printf "  ${RED}✘${RESET}  %-38s ${RED}MISSING${RESET}\n" "$label"
            missing_headers+=("$hname")
            report_append "$report" "[MISSING] ${hname}"
        fi
    }

    _wh_check "Strict-Transport-Security (HSTS)" "$hsts"        "Strict-Transport-Security"
    _wh_check "X-Frame-Options"                  "$xframe"      "X-Frame-Options"
    _wh_check "X-Content-Type-Options"           "$xcto"        "X-Content-Type-Options"
    _wh_check "X-XSS-Protection"                 "$xss"         "X-XSS-Protection"
    _wh_check "Content-Security-Policy"          "$csp"         "Content-Security-Policy"
    _wh_check "Referrer-Policy"                  "$referrer"    "Referrer-Policy"
    _wh_check "Permissions-Policy"               "$permissions" "Permissions-Policy"
    _wh_check "Cross-Origin-Opener-Policy"       "$cto"         "Cross-Origin-Opener-Policy"

    if [[ -n "$feature" ]]; then
        printf "  ${YELLOW}ℹ${RESET}  %-38s ${YELLOW}%s${RESET} ${DIM}(legacy)${RESET}\n" \
               "Feature-Policy" "${feature:0:55}"
        report_append "$report" "[INFO]    Feature-Policy (legacy): ${feature}"
    fi

    echo ""

    # ── RISK ANALYSIS ─────────────────────────────────────────────────────
    report_section "$report" "Risk Analysis"

    echo -e "${BOLD}${WHITE}RISK ANALYSIS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    local risks_found=0

    if [[ -n "$server" ]] && echo "$server" | grep -qiE '[0-9]\.[0-9]' 2>/dev/null || false; then
        print_critical "Server discloses version: ${server}"
        report_append "$report" "[RISK] Server version disclosure: $server"
        risks_found=$(( risks_found + 1 ))
    fi

    if [[ "$url" =~ ^https:// ]] && [[ -z "$hsts" ]]; then
        print_critical "HSTS missing — vulnerable to SSL-stripping / downgrade"
        report_append "$report" "[RISK] HSTS missing on HTTPS endpoint"
        risks_found=$(( risks_found + 1 ))
    fi

    if [[ -z "$xframe" ]] && [[ -z "$csp" ]]; then
        print_critical "No X-Frame-Options or CSP — clickjacking risk"
        report_append "$report" "[RISK] Clickjacking — no X-Frame-Options or CSP"
        risks_found=$(( risks_found + 1 ))
    fi

    if [[ -z "$xcto" ]]; then
        print_critical "X-Content-Type-Options missing — MIME sniffing risk"
        report_append "$report" "[RISK] MIME sniffing — X-Content-Type-Options missing"
        risks_found=$(( risks_found + 1 ))
    fi

    if [[ -z "$csp" ]]; then
        print_critical "Content-Security-Policy missing — XSS risk elevated"
        report_append "$report" "[RISK] XSS risk elevated — CSP missing"
        risks_found=$(( risks_found + 1 ))
    fi

    if [[ $risks_found -eq 0 ]]; then
        echo -e "  ${GREEN}No critical risks detected.${RESET}"
        report_append "$report" "No critical risks detected."
    fi

    echo ""

    # ── RECOMMENDATIONS ────────────────────────────────────────────────────
    if [[ ${#missing_headers[@]} -gt 0 ]]; then
        report_section "$report" "Recommendations"
        echo -e "${BOLD}${WHITE}RECOMMENDATIONS${RESET}"
        echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

        for h in "${missing_headers[@]}"; do
            case "$h" in
                "Strict-Transport-Security")
                    echo -e "  ${YELLOW}►${RESET} ${CYAN}Strict-Transport-Security: max-age=31536000; includeSubDomains; preload${RESET}"
                    report_append "$report" "ADD: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    ;;
                "X-Frame-Options")
                    echo -e "  ${YELLOW}►${RESET} ${CYAN}X-Frame-Options: DENY${RESET}"
                    report_append "$report" "ADD: X-Frame-Options: DENY"
                    ;;
                "X-Content-Type-Options")
                    echo -e "  ${YELLOW}►${RESET} ${CYAN}X-Content-Type-Options: nosniff${RESET}"
                    report_append "$report" "ADD: X-Content-Type-Options: nosniff"
                    ;;
                "X-XSS-Protection")
                    echo -e "  ${YELLOW}►${RESET} ${CYAN}X-XSS-Protection: 1; mode=block${RESET}"
                    report_append "$report" "ADD: X-XSS-Protection: 1; mode=block"
                    ;;
                "Content-Security-Policy")
                    echo -e "  ${YELLOW}►${RESET} ${CYAN}Content-Security-Policy: default-src 'self'${RESET}"
                    report_append "$report" "ADD: Content-Security-Policy: default-src 'self'"
                    ;;
                "Referrer-Policy")
                    echo -e "  ${YELLOW}►${RESET} ${CYAN}Referrer-Policy: strict-origin-when-cross-origin${RESET}"
                    report_append "$report" "ADD: Referrer-Policy: strict-origin-when-cross-origin"
                    ;;
                "Permissions-Policy")
                    echo -e "  ${YELLOW}►${RESET} ${CYAN}Permissions-Policy: geolocation=(), microphone=(), camera=()${RESET}"
                    report_append "$report" "ADD: Permissions-Policy: geolocation=(), microphone=(), camera=()"
                    ;;
                "Cross-Origin-Opener-Policy")
                    echo -e "  ${YELLOW}►${RESET} ${CYAN}Cross-Origin-Opener-Policy: same-origin${RESET}"
                    report_append "$report" "ADD: Cross-Origin-Opener-Policy: same-origin"
                    ;;
            esac
        done
        echo ""
    fi

    # ── GRADE ──────────────────────────────────────────────────────────────
    local pct grade grade_color
    pct=$(( score * 100 / max_score ))

    if   [[ $pct -ge 90 ]]; then grade="A+"; grade_color="$GREEN"
    elif [[ $pct -ge 75 ]]; then grade="B";  grade_color="$GREEN"
    elif [[ $pct -ge 55 ]]; then grade="C";  grade_color="$YELLOW"
    elif [[ $pct -ge 35 ]]; then grade="D";  grade_color="$YELLOW"
    else                          grade="F";  grade_color="$RED"
    fi

    report_section "$report" "Security Grade"
    report_append  "$report" "Score : ${score} / ${max_score} (${pct}%)"
    report_append  "$report" "Grade : ${grade}"

    echo -e "${BOLD}${WHITE}SECURITY GRADE${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    echo -e "  Score : ${grade_color}${BOLD}${score} / ${max_score}${RESET}  (${pct}%)"
    echo -e "  Grade : ${grade_color}${BOLD}${grade}${RESET}"
    echo ""

    # ── Raw headers in report ──────────────────────────────────────────────
    report_section "$report" "Raw HTTP Response Headers"
    printf '%s\n' "$raw_headers" >> "$report"

    # ── Finalize ───────────────────────────────────────────────────────────
    report_finalize "$report"
    log_success "WEBHEADERS" "Scan complete for $target — Grade: $grade (${score}/${max_score})"

    # ── SUMMARY ────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"          "$target"
    print_kv "Status"          "${status:-Unknown}"
    print_kv "Headers Present" "${score} / ${max_score}"
    print_kv "Headers Missing" "${#missing_headers[@]}"
    print_kv "Risks Detected"  "$risks_found"
    print_kv "Security Grade"  "${grade}  (${pct}%)"
    print_kv "Report Saved"    "$report"
    echo ""

    print_success "HTTP Header Scan Completed Successfully!"
    echo ""

    # ── Return to REPL ─────────────────────────────────────────────────────
    # Never touch CURRENT_MODULE or MODULE_OPTS — main.sh owns that state.
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
    echo ""

    return 0
}
