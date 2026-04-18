#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Robots.txt & Sensitive Files Analyzer
# Analyzes robots.txt for disallowed paths and potential sensitive directories
# =============================================================================

run_robotsanalyzer() {

    print_section "49. ROBOTS.TXT & SENSITIVE FILES ANALYZER"

    local target=""

    # Get target from REPL
    if [[ -n "${MODULE_OPTS[target]:-}" ]]; then
        target="${MODULE_OPTS[target]}"
        print_info "Using target → ${target}"
    elif [[ -n "$1" ]]; then
        target="$1"
    fi

    # Interactive input
    if [[ -z "$target" ]]; then
        echo -ne "${CYAN}Enter Target Domain (e.g. example.com): ${RESET}"
        read -r target
    fi

    [[ -z "$target" ]] && { print_alert "No target provided."; return 1; }

    # Clean target (remove http/https)
    target=$(echo "$target" | sed -E 's|https?://||' | awk -F/ '{print $1}')

    local report_dir="${SENTRYCLI_ROOT:-.}/reports"
    mkdir -p "$report_dir"
    local report="${report_dir}/RobotsAnalyzer_${target}_$(date '+%Y%m%d_%H%M%S').txt"

    print_subsection "Analyzing robots.txt → ${target}"
    echo ""

    # Fetch robots.txt
    print_info "Fetching robots.txt..."
    local robots_content
    robots_content=$(curl -s --max-time 15 -L "https://${target}/robots.txt")

    if [[ -z "$robots_content" || "$robots_content" == *"404"* || "$robots_content" == *"Not Found"* ]]; then
        print_warn "robots.txt not found or empty on this target."
        echo "User-Agent: *" > temp_robots.txt
        echo "Disallow: /" >> temp_robots.txt
        robots_content=$(cat temp_robots.txt)
    else
        print_success "robots.txt retrieved successfully"
    fi

    # Save full report
    {
        echo "========================================"
        echo "   ROBOTS.TXT & SENSITIVE PATHS REPORT"
        echo "========================================"
        echo ""
        echo "Target      : https://${target}"
        echo "Scan Date   : $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "----------------------------------------"
        echo ""
        echo "=== RAW robots.txt CONTENT ==="
        echo ""
        echo "$robots_content"
        echo ""
        echo "----------------------------------------"
        echo "ANALYSIS RESULTS"
        echo "----------------------------------------"
    } > "$report"

    # Parse and analyze
    echo -e "${BOLD}${WHITE}ROBOTS.TXT ANALYSIS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    local sensitive_paths=()
    local disallowed_count=0

    echo "$robots_content" | while IFS= read -r line; do
        if [[ "$line" =~ ^Disallow: ]]; then
            local path
            path=$(echo "$line" | awk '{print $2}')
            ((disallowed_count++))
            
            echo -e " ${YELLOW}Disallow${RESET} → ${path}"
            
            # Highlight sensitive paths
            case "$path" in
                *admin*|*login*|*wp-admin*|*config*|*backup*|*db*|*sql*|*env*|*.git*|*phpmyadmin*|*dashboard*)
                    print_critical "   ⚠ Sensitive path detected → ${path}"
                    sensitive_paths+=("$path")
                    ;;
            esac
            
            echo "Disallow: ${path}" >> "$report"
        elif [[ "$line" =~ ^Sitemap: ]]; then
            local sitemap
            sitemap=$(echo "$line" | awk '{print $2}')
            print_success "   Sitemap found → ${sitemap}"
            echo "Sitemap: ${sitemap}" >> "$report"
        elif [[ "$line" =~ ^User-agent: ]]; then
            echo -e "${DIM}User-Agent: ${line#User-agent: }${RESET}"
        fi
    done

    # Summary
    echo ""
    echo -e "${BOLD}${WHITE}SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target" "https://${target}"
    print_kv "Disallow Rules" "$disallowed_count"
    print_kv "Sensitive Paths" "${#sensitive_paths[@]}"
    print_kv "Report Saved" "${report}"

    if [[ ${#sensitive_paths[@]} -gt 0 ]]; then
        print_alert "   ⚠ Potential sensitive directories found!"
    else
        print_success "   No obvious sensitive paths detected"
    fi

    echo ""
    print_success "Robots.txt analysis completed!"
    print_success "Report saved → ${report}"

    echo ""
    echo -ne "${CYAN}Press ENTER to return to main menu...${RESET}"
    read -r

    # Return to main menu
    CURRENT_MODULE=""
    MODULE_OPTS=()
}
               
