#!/usr/bin/env bash
# =============================================================================
# SentryCLI - JavaScript Library Vulnerability Scanner [JS-16] - Enhanced
# modules/jsvulnscan.sh
# Detects outdated/vulnerable JS libraries (jQuery, Bootstrap, Lodash, React, Vue, etc.)
# =============================================================================

run_jsvulnscan() {

    print_section "16. JAVASCRIPT LIBRARY VULNERABILITY SCANNER [JS-16]"

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
    report=$(report_init "JS_Libraries_${domain//[^a-zA-Z0-9._-]/_}")

    report_section "$report" "Scan Target"
    report_append "$report" "Target : $target"
    report_append "$report" "Domain : $domain"

    print_subsection "Scanning JavaScript Libraries on → ${domain}"
    echo ""

    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed."
        report_finalize "$report"
        return 1
    fi

    # ── Fetch page body ────────────────────────────────────────────────────
    print_info "Fetching page and analyzing JavaScript libraries..."

    local body
    body=$(curl -s -L --max-time 20 --connect-timeout 8 \
        -A "Mozilla/5.0 (compatible; SentryCLI/2.8)" \
        "$target" 2>/dev/null) || true

    if [[ -z "$body" ]]; then
        print_alert "Failed to retrieve page content."
        report_append "$report" "ERROR: Empty response"
        report_finalize "$report"
        return 1
    fi

    # ── Safe detection helper ──────────────────────────────────────────────
    _detect() {
        echo "$body" | grep -oiE "$1" 2>/dev/null || false
    }

    _extract_version() {
        echo "$body" | grep -oE "$1" | head -1 | grep -oE '[0-9]+\.[0-9.]+' 2>/dev/null || echo "Unknown"
    }

    # ── JS Libraries Database (with known vulnerable versions) ─────────────
    local -a libs=()
    local vulnerable_count=0

    # jQuery
    if _detect 'jquery.*[0-9]'; then
        local ver
        ver=$(_extract_version 'jquery[./-]([0-9.]+)')
        libs+=("jQuery|$ver|3.7.1")
        [[ "$ver" =~ ^(1\.|2\.) ]] && { vulnerable_count=$((vulnerable_count+1)); }
    fi

    # Bootstrap
    if _detect 'bootstrap'; then
        local ver
        ver=$(_extract_version 'bootstrap[./-]([0-9.]+)')
        libs+=("Bootstrap|$ver|5.3.3")
        [[ "$ver" =~ ^(3\.|4\.) ]] && { vulnerable_count=$((vulnerable_count+1)); }
    fi

    # Lodash
    if _detect 'lodash'; then
        local ver
        ver=$(_extract_version 'lodash[./-]([0-9.]+)')
        libs+=("Lodash|$ver|4.17.21")
        [[ "$ver" =~ ^(4\.(0|1[0-7])) ]] && { vulnerable_count=$((vulnerable_count+1)); }
    fi

    # React
    if _detect 'react'; then
        local ver
        ver=$(_extract_version 'react[./-]([0-9.]+)')
        libs+=("React|$ver|18.3.1")
    fi

    # Vue.js
    if _detect 'vue\.js|__VUE__'; then
        local ver
        ver=$(_extract_version 'vue[./-]([0-9.]+)')
        libs+=("Vue.js|$ver|3.4.38")
    fi

    # Angular
    if _detect 'angular'; then
        local ver
        ver=$(_extract_version 'angular[./-]([0-9.]+)')
        libs+=("Angular|$ver|19.0.0")
    fi

    # Moment.js (Highly vulnerable)
    if _detect 'moment\.js|momentjs'; then
        local ver
        ver=$(_extract_version 'moment[./-]([0-9.]+)')
        libs+=("Moment.js|$ver|2.30.1")
        vulnerable_count=$((vulnerable_count+1))
    fi

    # Additional common libraries
    if _detect 'swfobject|prototype|scriptaculous|mootools'; then
        libs+=("Legacy Library|Detected|High Risk")
        vulnerable_count=$((vulnerable_count+1))
    fi

    # ── Display & Report Results ───────────────────────────────────────────
    report_section "$report" "Detected JavaScript Libraries"

    echo ""
    echo -e "${BOLD}${WHITE}JAVASCRIPT LIBRARIES SCAN RESULTS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    if [[ ${#libs[@]} -eq 0 ]]; then
        echo -e "  ${YELLOW}No JavaScript libraries detected.${RESET}"
        report_append "$report" "No JS libraries detected."
    else
        printf "  ${BOLD}%-22s %-12s %-12s Status${RESET}\n" "Library" "Version" "Latest"
        echo -e "  ${DIM}$(printf '%.0s─' {1..60})${RESET}"

        for lib in "${libs[@]}"; do
            IFS='|' read -r name ver latest <<< "$lib"
            local status="✅ Current"
            [[ "$ver" != "Unknown" && "$ver" != "$latest" ]] && status="${YELLOW}⚠ Outdated${RESET}"
            [[ "$name" == *"Legacy"* ]] && status="${RED}❌ High Risk${RESET}"

            printf "  ${WHITE}%-22s ${CYAN}%-12s ${DIM}%-12s${RESET} %s\n" "$name" "${ver:-Unknown}" "$latest" "$status"
            report_append "$report" "${name} | Version: ${ver:-Unknown} | Latest: ${latest} | ${status}"
        done
    fi

    echo ""
    if [[ $vulnerable_count -gt 0 ]]; then
        print_critical "Found ${vulnerable_count} potentially vulnerable/outdated JS library(ies)!"
    else
        print_success "No critical vulnerable JS libraries detected."
    fi

    # ── Security Notes ─────────────────────────────────────────────────────
    report_section "$report" "Security Recommendations"
    echo ""
    echo -e "${BOLD}${WHITE}RECOMMENDATIONS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_warn "Always keep JavaScript libraries updated to latest versions"
    print_warn "Use Subresource Integrity (SRI) for CDNs"
    print_warn "Remove unused libraries (especially Moment.js, old jQuery)"
    print_warn "Consider using modern frameworks with built-in security"
    echo ""

    report_finalize "$report"
    log_success "JSVULNSCAN" "Completed for $domain — ${#libs[@]} libraries found, $vulnerable_count vulnerable"

    # ── Summary ────────────────────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"                "$domain"
    print_kv "Libraries Detected"   "${#libs[@]}"
    print_kv "Vulnerable/Outdated"  "$vulnerable_count"
    print_kv "Report Saved"         "$report"
    echo ""

    print_success "JavaScript Library Scan completed successfully!"
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
    echo ""

    return 0
}
