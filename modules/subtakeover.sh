#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Subdomain Takeover Checker [SUB-17] - Enhanced
# modules/subtakeover.sh
# Detects potential Subdomain Takeover vulnerabilities (dangling DNS records)
# =============================================================================

run_subtakeover() {

    print_section "17. SUBDOMAIN TAKEOVER CHECKER [SUB-17]"

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
        echo -ne "${CYAN}Enter Target Domain (e.g. example.com): ${RESET}"
        read -r target
    fi

    [[ -z "$target" ]] && { print_alert "No target provided."; return 1; }

    # Clean domain
    local domain
    domain=$(echo "$target" | sed -E 's|https?://||' | sed 's|/.*||' | tr -d '[:space:]' 2>/dev/null || true)

    # ── Initialize Report ──────────────────────────────────────────────────
    local report
    report=$(report_init "Subdomain_Takeover_${domain//[^a-zA-Z0-9._-]/_}")

    report_section "$report" "Scan Target"
    report_append "$report" "Target Domain : $domain"

    print_subsection "Checking for Subdomain Takeover on → *.${domain}"
    echo ""

    if ! command -v dig &>/dev/null && ! command -v host &>/dev/null; then
        print_alert "Neither dig nor host command found. Install dnsutils/bind-utils."
        report_finalize "$report"
        return 1
    fi

    # ── Get subdomains (using multiple sources) ────────────────────────────
    print_info "Discovering subdomains..."

    local subdomains=()
    
    # Method 1: Common subdomains list + check
    local common_subs="www admin dev staging test api mail ftp cdn shop blog app login portal"
    for sub in $common_subs; do
        subdomains+=("$sub.$domain")
    done

    # Method 2: Try to get from crt.sh (if curl works)
    print_info "Querying crt.sh for more subdomains..."
    local crt_subs
    crt_subs=$(curl -s "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
               grep -oE '"name_value":"[^"]+' | cut -d'"' -f4 | sort -u 2>/dev/null || true)

    if [[ -n "$crt_subs" ]]; then
        while read -r sub; do
            [[ -n "$sub" && "$sub" != "*."* ]] && subdomains+=("$sub")
        done <<< "$crt_subs"
    fi

    # Remove duplicates
    local unique_subs=($(printf '%s\n' "${subdomains[@]}" | sort -u))
    print_info "Checking ${#unique_subs[@]} potential subdomains..."

    # ── Takeover Signatures ────────────────────────────────────────────────
    declare -A takeover_signatures=(
        ["github"]="There isn't a GitHub Pages site here|404 Not Found"
        ["heroku"]="herokuapp.com|No such app"
        ["aws"]="NoSuchBucket|aws.amazon.com"
        ["azure"]="azurewebsites.net|404 Web Site not found"
        ["cloudfront"]="Bad Request|The request could not be satisfied"
        ["shopify"]="Sorry, this shop is currently unavailable"
        ["wordpress"]="Do you want to create a new site|WordPress.com"
        ["bitbucket"]="Repository not found"
        ["squarespace"]="To claim this domain|Squarespace"
    )

    local vulnerable_count=0
    local -a findings=()

    # ── Main Check Loop ────────────────────────────────────────────────────
    for sub in "${unique_subs[@]}"; do
        printf "  Checking %-35s" "$sub"

        # Get DNS record
        local record
        if command -v dig &>/dev/null; then
            record=$(dig +short "$sub" 2>/dev/null || true)
        else
            record=$(host "$sub" 2>/dev/null | grep 'has address' | awk '{print $4}' || true)
        fi

        if [[ -z "$record" ]]; then
            echo -e " ${YELLOW}→ No DNS${RESET}"
            continue
        fi

        # Check if subdomain points to a service
        local response
        response=$(curl -s -I -L --max-time 8 --connect-timeout 6 \
            -A "Mozilla/5.0 (compatible; SentryCLI/2.8)" "https://$sub" 2>/dev/null || true)

        local is_vulnerable=false
        local service=""

        for svc in "${!takeover_signatures[@]}"; do
            if echo "$response" | grep -qiE "${takeover_signatures[$svc]}"; then
                is_vulnerable=true
                service="$svc"
                break
            fi
        done

        if [[ "$is_vulnerable" == true ]]; then
            echo -e " ${RED}→ VULNERABLE${RESET} (${service})"
            findings+=("$sub → ${service} (Possible Takeover)")
            ((vulnerable_count++))
        else
            echo -e " ${GREEN}→ OK${RESET}"
        fi
    done

    # ── Final Results ──────────────────────────────────────────────────────
    report_section "$report" "Subdomain Takeover Results"
    report_append "$report" "Total Subdomains Checked : ${#unique_subs[@]}"
    report_append "$report" "Potential Takeovers     : $vulnerable_count"

    echo ""
    echo -e "${BOLD}${WHITE}SUBDOMAIN TAKEOVER RESULTS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    if [[ $vulnerable_count -gt 0 ]]; then
        print_critical "⚠ ${vulnerable_count} POTENTIAL SUBDOMAIN TAKEOVER(S) FOUND!"
        for finding in "${findings[@]}"; do
            echo -e "   ${RED}●${RESET} $finding"
            report_append "$report" "VULNERABLE: $finding"
        done
    else
        print_success "No obvious subdomain takeovers detected."
        report_append "$report" "No vulnerable subdomains found."
    fi

    echo ""

    # ── Security Notes ─────────────────────────────────────────────────────
    report_section "$report" "Security Recommendations"
    echo ""
    echo -e "${BOLD}${WHITE}RECOMMENDATIONS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_warn "Remove dangling CNAME/A records pointing to unused services"
    print_warn "Claim unused accounts on GitHub, Heroku, AWS, etc."
    print_warn "Use 'CNAME flattening' or proper DNS validation"
    print_warn "Regularly monitor subdomains with tools like Sublist3r + Nuclei"
    echo ""

    report_finalize "$report"
    log_success "SUBTAKEOVER" "Scan complete for $domain — $vulnerable_count possible takeovers"

    # ── Summary ────────────────────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target Domain"        "$domain"
    print_kv "Subdomains Checked"  "${#unique_subs[@]}"
    print_kv "Potential Takeovers" "$vulnerable_count"
    print_kv "Report Saved"        "$report"
    echo ""

    print_success "Subdomain Takeover check completed!"
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
    echo ""

    return 0
}
