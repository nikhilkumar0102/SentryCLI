#!/usr/bin/env bash
# =============================================================================
# SentryCLI - CORS Misconfiguration Checker [CORS-20] - Enhanced
# modules/corscheck.sh
# Detects dangerous CORS configurations, wildcard origins, and trust issues
# =============================================================================

run_corscheck() {

    print_section "20. CORS MISCONFIGURATION CHECKER [CORS-20]"

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

    # ── Initialize Report ──────────────────────────────────────────────────
    local report
    report=$(report_init "CORS_Check_${domain//[^a-zA-Z0-9._-]/_}")

    report_section "$report" "Scan Target"
    report_append "$report" "Target : $target"
    report_append "$report" "Domain : $domain"

    print_subsection "Checking CORS Configuration on → ${domain}"
    echo ""

    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed."
        report_finalize "$report"
        return 1
    fi

    # ── Safe helper functions ──────────────────────────────────────────────
    _header() {
        printf '%s' "$1" | grep -i "^${2}:" | head -1 \
            | cut -d':' -f2- | sed 's/^[[:space:]]*//' | tr -d '\r' 2>/dev/null || true
    }

    # ── Test with different Origin headers ─────────────────────────────────
    print_info "Sending CORS probes with different Origin values..."

    local origins=("https://evil.com" "null" "https://${domain}.evil.com" "*")
    local vulnerabilities=0
    local -a issues=()

    for origin in "${origins[@]}"; do
        local headers
        headers=$(curl -s -I -L --max-time 10 --connect-timeout 6 \
            -A "Mozilla/5.0 (compatible; SentryCLI/2.8)" \
            -H "Origin: ${origin}" \
            "$target" 2>/dev/null) || true

        local acao
        acao=$(_header "$headers" "Access-Control-Allow-Origin")
        local acac
        acac=$(_header "$headers" "Access-Control-Allow-Credentials")

        if [[ -n "$acao" ]]; then
            echo -e "  ${YELLOW}→${RESET} Origin: ${origin} | ACAO: ${acao:-None} | Credentials: ${acac:-None}"

            if [[ "$acao" == "*" && "$acac" == "true" ]]; then
                issues+=("CRITICAL: Access-Control-Allow-Origin: * + Allow-Credentials: true")
                ((vulnerabilities++))
            elif [[ "$acao" == "*" ]]; then
                issues+=("HIGH: Wildcard (*) origin allowed")
                ((vulnerabilities++))
            elif [[ "$acao" == "$origin" || "$acao" == "null" ]]; then
                issues+=("HIGH: Origin reflection / Trusted arbitrary origin")
                ((vulnerabilities++))
            fi
        fi
    done

    # Normal request for baseline
    local normal_headers
    normal_headers=$(curl -s -I -L --max-time 10 --connect-timeout 6 \
        -A "Mozilla/5.0 (compatible; SentryCLI/2.8)" "$target" 2>/dev/null) || true

    local final_acao final_acac
    final_acao=$(_header "$normal_headers" "Access-Control-Allow-Origin")
    final_acac=$(_header "$normal_headers" "Access-Control-Allow-Credentials")

    # ── Report & Display ───────────────────────────────────────────────────
    report_section "$report" "CORS Analysis Results"
    report_append "$report" "Access-Control-Allow-Origin     : ${final_acao:-Not Present}"
    report_append "$report" "Access-Control-Allow-Credentials : ${final_acac:-Not Present}"
    report_append "$report" "Vulnerabilities Detected         : ${vulnerabilities}"

    echo ""
    echo -e "${BOLD}${WHITE}CORS MISCONFIGURATION RESULTS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"                      "$domain"
    print_kv "Allow-Origin"               "${final_acao:-Not Set}"
    print_kv "Allow-Credentials"          "${final_acac:-Not Set}"
    print_kv "Risk Level"                 "${vulnerabilities} issues found"
    echo ""

    if [[ $vulnerabilities -eq 0 ]]; then
        print_success "CORS appears properly configured."
    elif [[ $vulnerabilities -ge 2 ]]; then
        print_critical "CRITICAL CORS Misconfiguration Detected!"
    else
        print_warn "Potential CORS issues found."
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        echo ""
        echo -e "${RED}Found Issues:${RESET}"
        for issue in "${issues[@]}"; do
            echo -e "   ${RED}●${RESET} $issue"
            report_append "$report" "ISSUE: $issue"
        done
    fi

    # ── Security Notes ─────────────────────────────────────────────────────
    report_section "$report" "Security Recommendations"
    echo ""
    echo -e "${BOLD}${WHITE}RECOMMENDATIONS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_warn "Never use Access-Control-Allow-Origin: * with Allow-Credentials: true"
    print_warn "Explicitly define trusted origins only"
    print_warn "Avoid reflecting Origin header without validation"
    print_warn "Consider using CORS middleware with strict origin checking"
    print_info  "Use tools like CORS Tester or Nuclei for deeper testing"
    echo ""

    # Raw headers
    report_section "$report" "Raw HTTP Headers (with Origin probe)"
    printf '%s\n' "$normal_headers" >> "$report" 2>/dev/null || true

    report_finalize "$report"
    log_success "CORSCHECK" "Completed for $domain — ${vulnerabilities} issues found"

    # ── Summary ────────────────────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"               "$domain"
    print_kv "CORS Issues"         "$vulnerabilities"
    print_kv "Report Saved"        "$report"
    echo ""

    print_success "CORS Misconfiguration check completed!"
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
    echo ""

    return 0
}
