#!/usr/bin/env bash
# =============================================================================
# SentryCLI - CMS Detection Module [CMS-10]
# modules/cmsdetect.sh
#
# Detects WordPress, Joomla, Drupal, Shopify, Magento, Laravel etc.
# Pattern mirrors ipcheck.sh / fixed webheaders.sh exactly.
# =============================================================================

run_cmsdetect() {

    print_section "10. CMS DETECTION [CMS-10]"

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
        echo -ne "${CYAN}Enter Target Domain/URL (e.g. example.com): ${RESET}"
        read -r target
    fi

    [[ -z "$target" ]] && { print_alert "No target provided."; return 1; }

    # Normalize URL
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="https://${target}"
    fi

    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed."
        return 1
    fi

    # ── Init report (same as ipcheck / webheaders pattern) ─────────────────
    local safe_name="${target//[^a-zA-Z0-9._-]/_}"
    local report
    report=$(report_init "CMS_Detection_${safe_name}")

    report_section "$report" "Scan Target"
    report_append  "$report" "Target : $target"

    print_subsection "Analyzing CMS on → ${target}"
    echo ""
    print_info "Sending detection probes..."

    # ── Fetch page (headers + body) ────────────────────────────────────────
    # CRITICAL: every curl and grep must end with || true
    # grep returns exit 1 on no-match which kills main.sh under set -e
    local headers="" body=""
    headers=$(curl -s -I -L --max-time 12 --connect-timeout 8 \
        -A "Mozilla/5.0 (compatible; SentryCLI/2.7)" \
        "$target" 2>/dev/null) || true

    body=$(curl -s -L --max-time 15 --connect-timeout 8 \
        -A "Mozilla/5.0 (compatible; SentryCLI/2.7)" \
        "$target" 2>/dev/null) || true

    # Fallback to http if both empty
    if [[ -z "$headers" ]] && [[ -z "$body" ]] && [[ "$target" =~ ^https:// ]]; then
        local http_target="http://${target#https://}"
        print_warn "HTTPS unreachable — retrying with HTTP..."
        headers=$(curl -s -I -L --max-time 12 --connect-timeout 8 \
            -A "Mozilla/5.0 (compatible; SentryCLI/2.7)" \
            "$http_target" 2>/dev/null) || true
        body=$(curl -s -L --max-time 15 --connect-timeout 8 \
            -A "Mozilla/5.0 (compatible; SentryCLI/2.7)" \
            "$http_target" 2>/dev/null) || true
        target="$http_target"
        report_append "$report" "URL (fallback) : $target"
    fi

    if [[ -z "$headers" ]] && [[ -z "$body" ]]; then
        print_alert "No response from ${target}. Host may be down or unreachable."
        report_append "$report" "ERROR: No response received."
        report_finalize "$report"
        log_error "CMSDETECT" "No response from $target"
        return 1
    fi

    # ── CMS Detection Logic ────────────────────────────────────────────────
    # Every grep MUST have || true — no-match = exit 1 = kills main.sh
    local cms_found="Unknown / Static HTML"
    local version="Unknown"
    local confidence=0
    local cms_details=""

    # WordPress
    if echo "$body" | grep -qiE 'wp-content|wp-includes|wordpress' 2>/dev/null || false; then
        cms_found="WordPress"
        confidence=90
        version=$(echo "$body" | grep -oE 'wp-emoji-release\.min\.js\?ver=[0-9.]+' \
            | cut -d'=' -f2 | head -1 2>/dev/null) || true
        [[ -z "$version" ]] && version=$(echo "$body" \
            | grep -oE 'ver=[0-9]+\.[0-9]+(\.[0-9]+)?' \
            | head -1 | cut -d'=' -f2 2>/dev/null) || true
        cms_details="wp-content/wp-includes fingerprint matched"
    fi

    # Joomla
    if [[ "$cms_found" == "Unknown / Static HTML" ]]; then
        if echo "$headers $body" | grep -qiE 'joomla' 2>/dev/null || false; then
            cms_found="Joomla"
            confidence=85
            cms_details="Joomla keyword in headers/body"
        fi
    fi

    # Drupal
    if [[ "$cms_found" == "Unknown / Static HTML" ]]; then
        if echo "$headers $body" | grep -qiE 'drupal' 2>/dev/null || false; then
            cms_found="Drupal"
            confidence=80
            version=$(echo "$headers" | grep -i "X-Generator" \
                | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 2>/dev/null) || true
            cms_details="Drupal keyword in headers/body"
        fi
    fi

    # Shopify
    if [[ "$cms_found" == "Unknown / Static HTML" ]]; then
        if echo "$headers" | grep -qiE 'x-shopid|shopify' 2>/dev/null || false; then
            cms_found="Shopify"
            confidence=95
            cms_details="x-shopid / shopify header detected"
        fi
    fi

    # Magento
    if [[ "$cms_found" == "Unknown / Static HTML" ]]; then
        if echo "$body" | grep -qiE 'Mage\.Cookies|mage-|Magento' 2>/dev/null || false; then
            cms_found="Magento"
            confidence=80
            cms_details="Magento/Mage keyword in body"
        fi
    fi

    # Laravel
    if [[ "$cms_found" == "Unknown / Static HTML" ]]; then
        if echo "$headers" | grep -qiE 'laravel_session|laravel' 2>/dev/null || false; then
            cms_found="Laravel (PHP Framework)"
            confidence=75
            cms_details="laravel_session cookie / header detected"
        fi
    fi

    # Django
    if [[ "$cms_found" == "Unknown / Static HTML" ]]; then
        if echo "$headers" | grep -qiE 'csrftoken|django' 2>/dev/null || false; then
            cms_found="Django (Python Framework)"
            confidence=70
            cms_details="csrftoken cookie detected"
        fi
    fi

    # Ghost
    if [[ "$cms_found" == "Unknown / Static HTML" ]]; then
        if echo "$body" | grep -qiE 'ghost\.io|content=\"Ghost' 2>/dev/null || false; then
            cms_found="Ghost"
            confidence=85
            cms_details="Ghost CMS meta/link detected"
        fi
    fi

    # Wix
    if [[ "$cms_found" == "Unknown / Static HTML" ]]; then
        if echo "$body" | grep -qiE 'wix\.com|X-Wix' 2>/dev/null || false; then
            cms_found="Wix"
            confidence=90
            cms_details="wix.com reference in body"
        fi
    fi

    # Squarespace
    if [[ "$cms_found" == "Unknown / Static HTML" ]]; then
        if echo "$body" | grep -qiE 'squarespace' 2>/dev/null || false; then
            cms_found="Squarespace"
            confidence=90
            cms_details="squarespace reference in body"
        fi
    fi

    # Powered-By fallback
    if [[ "$cms_found" == "Unknown / Static HTML" ]]; then
        local powered_by
        powered_by=$(echo "$headers" | grep -i "^X-Powered-By:" \
            | cut -d':' -f2- | sed 's/^[[:space:]]*//' | tr -d '\r' 2>/dev/null) || true
        if [[ -n "$powered_by" ]]; then
            cms_found="Custom / Unknown"
            confidence=40
            cms_details="X-Powered-By: ${powered_by}"
        fi
    fi

    # ── Server & tech info ─────────────────────────────────────────────────
    local server_header status_line
    server_header=$(echo "$headers" | grep -i "^Server:" \
        | head -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//' | tr -d '\r' 2>/dev/null) || true
    status_line=$(echo "$headers" | grep -i "^HTTP/" \
        | tail -1 | tr -d '\r' 2>/dev/null) || true

    # ── Write to report ────────────────────────────────────────────────────
    report_section "$report" "Detection Results"
    report_append  "$report" "Status         : ${status_line:-Unknown}"
    report_append  "$report" "Server         : ${server_header:-Not disclosed}"
    report_append  "$report" "Detected CMS   : $cms_found"
    report_append  "$report" "Version        : ${version:-Unknown}"
    report_append  "$report" "Confidence     : ${confidence}%"
    report_append  "$report" "Evidence       : ${cms_details:-N/A}"

    # ── Display Results ────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}${WHITE}CMS DETECTION RESULTS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"        "$target"
    print_kv "Status"        "${status_line:-Unknown}"
    print_kv "Server"        "${server_header:-Not disclosed}"
    print_kv "Detected CMS"  "$cms_found"
    print_kv "Version"       "${version:-Unknown}"
    print_kv "Confidence"    "${confidence}%"
    print_kv "Evidence"      "${cms_details:-N/A}"
    echo ""

    if [[ "$cms_found" != "Unknown / Static HTML" && "$cms_found" != "Custom / Unknown" ]]; then
        print_success "CMS Identified: ${cms_found}"
    else
        print_warn "Could not identify a known CMS"
    fi

    # ── Risk notes per CMS ─────────────────────────────────────────────────
    report_section "$report" "Security Notes"

    echo ""
    echo -e "${BOLD}${WHITE}SECURITY NOTES${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    case "$cms_found" in
        WordPress*)
            print_warn "Keep WordPress core, themes & plugins updated"
            print_warn "Consider hiding /wp-login.php and /xmlrpc.php"
            print_warn "Use a WAF (e.g. Wordfence, Cloudflare)"
            report_append "$report" "NOTE: Keep WordPress core/plugins updated. Hide wp-login.php."
            ;;
        Joomla*)
            print_warn "Update Joomla to latest version"
            print_warn "Disable unused extensions & debug mode"
            report_append "$report" "NOTE: Update Joomla. Disable debug mode in production."
            ;;
        Drupal*)
            print_warn "Apply Drupal security advisories promptly (Drupalgeddon)"
            print_warn "Disable PHP execution in upload directories"
            report_append "$report" "NOTE: Apply Drupal advisories. Restrict upload directories."
            ;;
        Shopify*)
            print_info "Shopify is SaaS — security managed by platform"
            print_warn "Review installed apps and API token scopes"
            report_append "$report" "NOTE: Shopify SaaS. Review app permissions and API scopes."
            ;;
        Magento*)
            print_warn "Apply Magento security patches immediately"
            print_warn "Magento installs are frequent targets for skimmers"
            report_append "$report" "NOTE: Apply Magento patches. Check for payment skimmers."
            ;;
        Laravel*)
            print_warn "Ensure APP_DEBUG=false in production"
            print_warn "Check .env file is not publicly accessible"
            report_append "$report" "NOTE: Set APP_DEBUG=false. Protect .env file."
            ;;
        *)
            print_info "No specific CMS security notes available"
            report_append "$report" "NOTE: No CMS-specific notes. Follow general web hardening."
            ;;
    esac

    echo ""

    # ── Raw headers in report ──────────────────────────────────────────────
    report_section "$report" "Raw HTTP Headers"
    printf '%s\n' "$headers" >> "$report"

    # ── Finalize ───────────────────────────────────────────────────────────
    report_finalize "$report"
    log_success "CMSDETECT" "CMS detection complete for $target — $cms_found (${confidence}%)"

    # ── Summary ────────────────────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"       "$target"
    print_kv "CMS"          "$cms_found"
    print_kv "Confidence"   "${confidence}%"
    print_kv "Report Saved" "$report"
    echo ""

    print_success "CMS Detection completed successfully!"
    echo ""

    # ── Return to REPL ─────────────────────────────────────────────────────
    # NEVER touch CURRENT_MODULE or MODULE_OPTS here.
    # main.sh REPL owns that state. Modifying it here breaks the REPL loop.
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
    echo ""

    return 0
}
