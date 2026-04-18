#!/usr/bin/env bash
# =============================================================================
# SentryCLI - HTTP Security Headers Analyzer Module [WEB-9]
# modules/webheaders.sh
#
# Fetches and grades HTTP security headers with report saving and REPL return.
# =============================================================================

run_webheaders() {

    print_section "9. HTTP SECURITY HEADERS ANALYZER [WEB-9]"

    # ── Resolve target from REPL opts or argument ──────────────────────────
    local target=""

    if [[ -n "${MODULE_OPTS[target]:-}" ]]; then
        target="${MODULE_OPTS[target]}"
        print_info "Using target → ${target}"
    elif [[ -n "${MODULE_OPTS[url]:-}" ]]; then
        target="${MODULE_OPTS[url]}"
        print_info "Using target → ${target}"
    elif [[ -n "${1:-}" ]]; then
        target="$1"
    fi

    # Interactive fallback
    if [[ -z "$target" ]]; then
        echo -ne "${CYAN}Enter Target URL or domain (e.g. https://example.com): ${RESET}"
        read -r target
    fi

    [[ -z "$target" ]] && { print_alert "No target provided."; return 1; }

    # Check curl
    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed — cannot fetch HTTP headers."
        return 1
    fi

    # ── Normalize URL ──────────────────────────────────────────────────────
    local url="$target"
    if [[ ! "$url" =~ ^https?:// ]]; then
        url="https://${target}"
    fi

    # ── Prepare report via helper (matches recon.sh pattern) ──────────────
    local safe_name
    safe_name=$(echo "$target" | sed 's|https\?://||g' | tr -c 'a-zA-Z0-9._-' '_')
    local report
    report=$(report_init "WebHeaders_${safe_name}")

    print_subsection "Analyzing Security Headers → ${url}"
    echo ""
    print_info "Fetching HTTP headers..."

    # ── Fetch headers (follow redirects, 15s timeout) ──────────────────────
    local raw_headers
    raw_headers=$(curl -s -D - -o /dev/null \
        --max-time 15 \
        --connect-timeout 8 \
        --max-redirs 5 \
        -L \
        -A "Mozilla/5.0 (compatible; SentryCLI/2.7; Security-Scanner)" \
        "$url" 2>&1)

    # If https failed, retry with http
    if [[ -z "$raw_headers" ]] && [[ "$url" =~ ^https:// ]]; then
        local http_url="${url/https:\/\//http://}"
        print_warn "HTTPS unreachable — retrying with HTTP..."
        raw_headers=$(curl -s -D - -o /dev/null \
            --max-time 15 \
            --connect-timeout 8 \
            --max-redirs 5 \
            -L \
            -A "Mozilla/5.0 (compatible; SentryCLI/2.7; Security-Scanner)" \
            "$http_url" 2>&1)
        url="$http_url"
    fi

    if [[ -z "$raw_headers" ]]; then
        print_alert "No response from ${url}. Host may be down or unreachable."
        return 1
    fi

    # ── Parse individual headers ───────────────────────────────────────────
    _wh_get() {
        echo "$raw_headers" | grep -i "^${1}:" | head -1 \
            | cut -d':' -f2- | sed 's/^[[:space:]]*//' | tr -d '\r'
    }

    local status server content_type
    status=$(echo "$raw_headers" | grep -i "^HTTP/" | tail -1 | tr -d '\r')
    server=$(_wh_get "Server")
    content_type=$(_wh_get "Content-Type")

    # Security headers
    local hsts xframe xcto xss csp referrer permissions cto feature
    hsts=$(_wh_get "Strict-Transport-Security")
    xframe=$(_wh_get "X-Frame-Options")
    xcto=$(_wh_get "X-Content-Type-Options")
    xss=$(_wh_get "X-XSS-Protection")
    csp=$(_wh_get "Content-Security-Policy")
    referrer=$(_wh_get "Referrer-Policy")
    permissions=$(_wh_get "Permissions-Policy")
    feature=$(_wh_get "Feature-Policy")
    cto=$(_wh_get "Cross-Origin-Opener-Policy")

    # ── Score tracking ─────────────────────────────────────────────────────
    local score=0
    local max_score=9
    local missing_headers=()
    local present_headers=()

    # ── Display: Connection Info ───────────────────────────────────────────
    report_section "$report" "Connection Info"

    echo -e "${BOLD}${WHITE}CONNECTION INFO${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "  URL"          "$url"
    print_kv "  Status"       "${status:-Unknown}"
    print_kv "  Server"       "${server:-Not disclosed}"
    print_kv "  Content-Type" "${content_type:-Not set}"

    report_append "$report" "URL         : $url"
    report_append "$report" "Status      : ${status:-Unknown}"
    report_append "$report" "Server      : ${server:-Not disclosed}"
    report_append "$report" "Content-Type: ${content_type:-Not set}"
    echo ""

    # ── Display: Security Headers ──────────────────────────────────────────
    report_section "$report" "Security Headers"

    echo -e "${BOLD}${WHITE}SECURITY HEADERS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    # Helper: print present/missing with scoring
    # NOTE: Using score=$(( score + 1 )) instead of (( score++ )) to avoid
    # set -e killing the script when score is 0 (arithmetic returns exit 1)
    _wh_check() {
        local label="$1"
        local value="$2"
        local header_name="$3"
        if [[ -n "$value" ]]; then
            printf "  ${GREEN}✔${RESET}  %-38s ${GREEN}%s${RESET}\n" "$label" "${value:0:55}"
            present_headers+=("$header_name: $value")
            report_append "$report" "[PASS] ${header_name}: ${value}"
            score=$(( score + 1 ))
        else
            printf "  ${RED}✘${RESET}  %-38s ${RED}MISSING${RESET}\n" "$label"
            missing_headers+=("$header_name")
            report_append "$report" "[MISSING] ${header_name}"
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

    # Feature-Policy is legacy but still checked
    if [[ -n "$feature" ]]; then
        printf "  ${YELLOW}ℹ${RESET}  %-38s ${YELLOW}%s${RESET} ${DIM}(legacy)${RESET}\n" \
               "Feature-Policy" "${feature:0:55}"
        report_append "$report" "[INFO] Feature-Policy (legacy): ${feature}"
    fi

    echo ""

    # ── Risk Flags ─────────────────────────────────────────────────────────
    report_section "$report" "Risk Analysis"

    echo -e "${BOLD}${WHITE}RISK ANALYSIS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    local risks_found=0

    if [[ -n "$server" ]] && echo "$server" | grep -qiE '[0-9]\.[0-9]'; then
        print_critical "  Server header discloses version: ${server}"
        report_append "$report" "[RISK] Server version disclosure: $server"
        risks_found=$(( risks_found + 1 ))
    fi

    if [[ "$url" =~ ^https:// ]] && [[ -z "$hsts" ]]; then
        print_critical "  HSTS missing — HTTPS site vulnerable to downgrade attacks"
        report_append "$report" "[RISK] HSTS missing on HTTPS endpoint"
        risks_found=$(( risks_found + 1 ))
    fi

    if [[ -z "$xframe" ]] && [[ -z "$csp" ]]; then
        print_critical "  No X-Frame-Options or CSP — clickjacking risk"
        report_append "$report" "[RISK] Clickjacking — no X-Frame-Options or CSP frame-ancestors"
        risks_found=$(( risks_found + 1 ))
    fi

    if [[ -z "$xcto" ]]; then
        print_critical "  X-Content-Type-Options missing — MIME sniffing risk"
        report_append "$report" "[RISK] MIME sniffing — X-Content-Type-Options missing"
        risks_found=$(( risks_found + 1 ))
    fi

    if [[ -z "$csp" ]]; then
        print_critical "  Content-Security-Policy missing — XSS risk elevated"
        report_append "$report" "[RISK] XSS risk elevated — CSP missing"
        risks_found=$(( risks_found + 1 ))
    fi

    [[ $risks_found -eq 0 ]] && echo -e "  ${GREEN}No critical risks detected.${RESET}"
    echo ""

    # ── Missing Headers Recommendations ───────────────────────────────────
    if [[ ${#missing_headers[@]} -gt 0 ]]; then
        report_section "$report" "Recommendations"

        echo -e "${BOLD}${WHITE}RECOMMENDATIONS${RESET}"
        echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
        for h in "${missing_headers[@]}"; do
            case "$h" in
                "Strict-Transport-Security")
                    echo -e "  ${YELLOW}►${RESET} Add: ${CYAN}Strict-Transport-Security: max-age=31536000; includeSubDomains; preload${RESET}"
                    report_append "$report" "RECOMMEND: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    ;;
                "X-Frame-Options")
                    echo -e "  ${YELLOW}►${RESET} Add: ${CYAN}X-Frame-Options: DENY${RESET}"
                    report_append "$report" "RECOMMEND: X-Frame-Options: DENY"
                    ;;
                "X-Content-Type-Options")
                    echo -e "  ${YELLOW}►${RESET} Add: ${CYAN}X-Content-Type-Options: nosniff${RESET}"
                    report_append "$report" "RECOMMEND: X-Content-Type-Options: nosniff"
                    ;;
                "X-XSS-Protection")
                    echo -e "  ${YELLOW}►${RESET} Add: ${CYAN}X-XSS-Protection: 1; mode=block${RESET}"
                    report_append "$report" "RECOMMEND: X-XSS-Protection: 1; mode=block"
                    ;;
                "Content-Security-Policy")
                    echo -e "  ${YELLOW}►${RESET} Add: ${CYAN}Content-Security-Policy: default-src 'self'${RESET}"
                    report_append "$report" "RECOMMEND: Content-Security-Policy: default-src 'self'"
                    ;;
                "Referrer-Policy")
                    echo -e "  ${YELLOW}►${RESET} Add: ${CYAN}Referrer-Policy: strict-origin-when-cross-origin${RESET}"
                    report_append "$report" "RECOMMEND: Referrer-Policy: strict-origin-when-cross-origin"
                    ;;
                "Permissions-Policy")
                    echo -e "  ${YELLOW}►${RESET} Add: ${CYAN}Permissions-Policy: geolocation=(), microphone=(), camera=()${RESET}"
                    report_append "$report" "RECOMMEND: Permissions-Policy: geolocation=(), microphone=(), camera=()"
                    ;;
                "Cross-Origin-Opener-Policy")
                    echo -e "  ${YELLOW}►${RESET} Add: ${CYAN}Cross-Origin-Opener-Policy: same-origin${RESET}"
                    report_append "$report" "RECOMMEND: Cross-Origin-Opener-Policy: same-origin"
                    ;;
            esac
        done
        echo ""
    fi

    # ── Security Grade ─────────────────────────────────────────────────────
    local grade grade_color
    local pct
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
    echo -e "  Score  : ${grade_color}${score} / ${max_score}${RESET} (${pct}%)"
    echo -e "  Grade  : ${grade_color}${BOLD}${grade}${RESET}"
    echo ""

    # ── Finalise report (writes footer & closes file) ──────────────────────
    report_finalize "$report"
    log_success "WEBHEADERS" "HTTP header scan complete for $target — Grade: $grade (${score}/${max_score})"

    # ── Scan Summary ──────────────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"          "$target"
    print_kv "URL"             "$url"
    print_kv "Headers Present" "$score / $max_score"
    print_kv "Headers Missing" "${#missing_headers[@]}"
    print_kv "Security Grade"  "$grade (${pct}%)"
    print_kv "Report Saved"    "$report"
    echo ""

    echo -e "${GREEN}${BOLD}✔ HTTP Header Scan Completed Successfully!${RESET}"
    echo -e "${CYAN}Report saved at:${RESET} ${WHITE}${report}${RESET}"
    echo ""
    echo -e "${DIM}You can review the detailed report later from the reports directory.${RESET}"
    echo ""

    # ── Return to REPL — DO NOT reset CURRENT_MODULE or unset MODULE_OPTS ─
    # main.sh REPL owns that state; module only signals it is done.
    echo -ne "${CYAN}Press ENTER to return to the SentryCLI main menu...${RESET}"
    read -r
    echo ""

    return 0
}
