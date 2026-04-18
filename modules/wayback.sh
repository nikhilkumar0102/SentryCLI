#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Wayback Machine Archive Analyzer [WAYBACK-19] - Enhanced
# modules/wayback.sh
# Checks historical snapshots, exposed old files, directories & sensitive info
# =============================================================================

run_wayback() {

    print_section "19. WAYBACK MACHINE ARCHIVE ANALYZER [WAYBACK-19]"

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
    report=$(report_init "Wayback_Analysis_${domain//[^a-zA-Z0-9._-]/_}")

    report_section "$report" "Scan Target"
    report_append "$report" "Target Domain : $domain"

    print_subsection "Analyzing Wayback Machine Archives for → ${domain}"
    echo ""

    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed."
        report_finalize "$report"
        return 1
    fi

    print_info "Querying Wayback Machine (archive.org)..."

    # Get list of archived snapshots
    local wayback_data
    wayback_data=$(curl -s "https://web.archive.org/cdx/search/cdx?url=*.${domain}&output=json&limit=500&fl=original,timestamp,statuscode" 2>/dev/null || true)

    if [[ -z "$wayback_data" ]] || [[ "$wayback_data" == "[]" ]]; then
        print_warn "No archives found for this domain on Wayback Machine."
        report_append "$report" "No historical archives found."
        report_finalize "$report"
        return 1
    fi

    # ── Extract interesting paths ──────────────────────────────────────────
    print_info "Analyzing archived URLs for sensitive files..."

    local -a sensitive_patterns=(
        "wp-config.php" ".env" "config.php" "database.sql" "backup" ".bak" ".old"
        "admin" "login" "phpinfo" "test" "debug" "api-key" "credentials"
        "robots.txt" "sitemap.xml" ".git" ".svn" "web.config" "settings"
    )

    local -a findings=()
    local total_archives exposed_count=0

    total_archives=$(echo "$wayback_data" | grep -o 'http' | wc -l)

    # Smart parsing of archived URLs
    while read -r url; do
        [[ -z "$url" ]] && continue
        
        for pattern in "${sensitive_patterns[@]}"; do
            if echo "$url" | grep -qi "$pattern"; then
                findings+=("$url")
                ((exposed_count++))
                break
            fi
        done
    done < <(echo "$wayback_data" | grep -oE 'http[s]?://[^"]+' | sort -u 2>/dev/null || true)

    # ── Display Results ────────────────────────────────────────────────────
    report_section "$report" "Wayback Machine Analysis"
    report_append "$report" "Total Archived Snapshots : ${total_archives}"
    report_append "$report" "Potentially Exposed Files : ${exposed_count}"

    echo ""
    echo -e "${BOLD}${WHITE}WAYBACK MACHINE RESULTS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Domain"                    "$domain"
    print_kv "Total Archived URLs"     "${total_archives}"
    print_kv "Potentially Exposed"     "${exposed_count}"
    echo ""

    if [[ $exposed_count -gt 0 ]]; then
        print_critical "⚠ ${exposed_count} Potentially Sensitive Files Found in Archives!"
        echo ""
        for item in "${findings[@]}"; do
            echo -e "   ${RED}→${RESET} ${item}"
            report_append "$report" "EXPOSED: ${item}"
        done
    else
        print_success "No obviously sensitive files found in public archives."
    fi

    # ── Security Recommendations ───────────────────────────────────────────
    report_section "$report" "Security Recommendations"
    echo ""
    echo -e "${BOLD}${WHITE}RECOMMENDATIONS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_warn "Remove sensitive files from web root (especially .env, wp-config, backups)"
    print_warn "Block Wayback Machine crawling using robots.txt:"
    print_warn "   User-agent: ArchiveTeam"
    print_warn "   User-agent: ia_archiver"
    print_warn "   Disallow: /"
    print_warn "Use <meta name=\"robots\" content=\"noarchive\"> in important pages"
    print_warn "Regularly check archive.org for your domain"
    echo ""

    report_finalize "$report"
    log_success "WAYBACK" "Analysis complete for $domain — ${exposed_count} exposed items found"

    # ── Summary ────────────────────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"               "$domain"
    print_kv "Archived Snapshots"   "${total_archives}"
    print_kv "Exposed Findings"     "${exposed_count}"
    print_kv "Report Saved"         "$report"
    echo ""

    print_success "Wayback Machine Analysis completed successfully!"
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
    echo ""

    return 0
}
