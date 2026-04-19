#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Server Location & Hosting Detector [HOST-21]
# modules/hostinfo.sh
# Detects Server Location, City, ISP, Hosting Provider & Cloud Platform
# =============================================================================

run_hostinfo() {

    print_section "21. SERVER LOCATION & HOSTING DETECTOR [HOST-21]"

    # ── Resolve target ─────────────────────────────────────────────────────
    local target=""
    if [[ -n "${MODULE_OPTS[target]:-}" ]]; then
        target="${MODULE_OPTS[target]}"
    elif [[ -n "${MODULE_OPTS[host]:-}" ]]; then
        target="${MODULE_OPTS[host]}"
    elif [[ -n "${1:-}" ]]; then
        target="$1"
    fi

    if [[ -z "$target" ]]; then
        echo -ne "${CYAN}Enter Target Domain/IP (e.g. example.com): ${RESET}"
        read -r target
    fi

    [[ -z "$target" ]] && { print_alert "No target provided."; return 1; }

    # Normalize
    local domain
    domain=$(echo "$target" | sed -E 's|https?://||' | sed 's|/.*||' | tr -d '[:space:]' 2>/dev/null || true)

    # ── Initialize Report ──────────────────────────────────────────────────
    local report
    report=$(report_init "HostInfo_${domain//[^a-zA-Z0-9._-]/_}")

    report_section "$report" "Scan Target"
    report_append "$report" "Target : $domain"

    print_subsection "Analyzing Server Location & Hosting → ${domain}"
    echo ""

    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed."
        report_finalize "$report"
        return 1
    fi

    # Resolve IP first
    local ip
    ip=$(dig +short "$domain" 2>/dev/null | head -1 || true)
    if [[ -z "$ip" ]]; then
        ip=$(curl -s -m 8 "https://api.ipify.org?domain=$domain" 2>/dev/null || true)
    fi
    if [[ -z "$ip" ]]; then
        print_alert "Could not resolve IP address for ${domain}"
        report_append "$report" "ERROR: Could not resolve IP"
        report_finalize "$report"
        return 1
    fi

    print_info "Resolved IP → ${ip}"
    report_append "$report" "Resolved IP : ${ip}"

    # ── Get Hosting & Location Info ────────────────────────────────────────
    print_info "Querying IP intelligence..."

    local response
    response=$(curl -s -m 12 "http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,lat,lon,proxy,hosting" 2>/dev/null || true)

    local country city isp org as hosting proxy

    country=$(echo "$response" | grep -o '"country":"[^"]*' | cut -d'"' -f4 2>/dev/null || true)
    city=$(echo "$response" | grep -o '"city":"[^"]*' | cut -d'"' -f4 2>/dev/null || true)
    isp=$(echo "$response" | grep -o '"isp":"[^"]*' | cut -d'"' -f4 2>/dev/null || true)
    org=$(echo "$response" | grep -o '"org":"[^"]*' | cut -d'"' -f4 2>/dev/null || true)
    as=$(echo "$response" | grep -o '"as":"[^"]*' | cut -d'"' -f4 2>/dev/null || true)
    hosting=$(echo "$response" | grep -o '"hosting":[^,]*' | cut -d':' -f2 2>/dev/null || "false")
    proxy=$(echo "$response" | grep -o '"proxy":[^,]*' | cut -d':' -f2 2>/dev/null || "false")

    # Detect Cloud Provider
    local provider="Unknown"
    if echo "$isp $org" | grep -qiE 'cloudflare|cf'; then
        provider="Cloudflare"
    elif echo "$isp $org" | grep -qiE 'amazon|aws|ec2'; then
        provider="Amazon Web Services (AWS)"
    elif echo "$isp $org" | grep -qiE 'google'; then
        provider="Google Cloud"
    elif echo "$isp $org" | grep -qiE 'microsoft|azure'; then
        provider="Microsoft Azure"
    elif echo "$isp $org" | grep -qiE 'digitalocean|linode|vultr|hetzner|ovh'; then
        provider="VPS / Dedicated Hosting"
    fi

    # ── Display Results ────────────────────────────────────────────────────
    report_section "$report" "Server & Hosting Information"
    report_append "$report" "IP Address     : ${ip}"
    report_append "$report" "Country        : ${country:-Unknown}"
    report_append "$report" "City           : ${city:-Unknown}"
    report_append "$report" "ISP            : ${isp:-Unknown}"
    report_append "$report" "Organization   : ${org:-Unknown}"
    report_append "$report" "ASN            : ${as:-Unknown}"
    report_append "$report" "Hosting Provider : ${provider}"
    report_append "$report" "Is Hosting     : ${hosting}"
    report_append "$report" "Is Proxy/VPN   : ${proxy}"

    echo ""
    echo -e "${BOLD}${WHITE}SERVER LOCATION & HOSTING INFO${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Domain"           "$domain"
    print_kv "IP Address"       "$ip"
    print_kv "Location"         "${city}, ${country:-Unknown}"
    print_kv "ISP"              "${isp:-Unknown}"
    print_kv "Organization"     "${org:-Unknown}"
    print_kv "Hosting Provider" "${provider}"
    print_kv "ASN"              "${as:-Unknown}"
    echo ""

    if [[ "$hosting" == "true" ]]; then
        print_success "This IP belongs to a Hosting / Cloud Provider"
    fi
    if [[ "$proxy" == "true" ]]; then
        print_warn "This IP appears to be a Proxy / VPN / Anonymizer"
    fi

    # Security Notes
    report_section "$report" "Security Notes"
    echo ""
    echo -e "${BOLD}${WHITE}NOTES${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_warn "Knowing hosting provider helps in targeted attacks & reconnaissance"
    print_info  "Cloudflare, AWS, Azure are common targets for advanced attackers"
    echo ""

    report_finalize "$report"
    log_success "HOSTINFO" "Completed for $domain — Provider: ${provider}"

    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"         "$domain"
    print_kv "IP"             "$ip"
    print_kv "Hosting"        "${provider}"
    print_kv "Report Saved"   "$report"
    echo ""

    print_success "Server Location & Hosting analysis completed!"
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
    echo ""

    return 0
}
