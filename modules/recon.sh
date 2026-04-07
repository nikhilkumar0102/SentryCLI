#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Reconnaissance Module
# modules/recon.sh
#
# Target enumeration: nmap port scan, DNS, WHOIS, HTTP probe, subdomains.
# =============================================================================

run_recon() {
    local target="${1:-}"

    print_section "RECONNAISSANCE"
    log_info "RECON" "Module started"

    if [[ -z "$target" ]]; then
        echo -ne "  ${CYAN}${BOLD}Enter target (IP or domain):${RESET} "
        read -r target
    fi

    if [[ -z "$target" ]]; then
        print_alert "No target specified. Aborting."
        log_error "RECON" "No target specified"
        return 1
    fi

    # Sanitize
    target=$(echo "$target" | tr -d '[:space:]' | sed 's|https\?://||g' | cut -d'/' -f1)

    echo ""
    print_kv "Target"  "$target"
    print_kv "Started" "$(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    log_info "RECON" "Target: $target"

    local report
    report=$(report_init "recon_${target//[^a-zA-Z0-9._-]/_}")
    report_section "$report" "Reconnaissance: $target"
    report_append  "$report" "Target : $target"
    report_append  "$report" "Started: $(date)"

    _recon_check_tools
    _recon_dns         "$target" "$report"
    _recon_whois       "$target" "$report"
    _recon_portscan    "$target" "$report"
    _recon_http_probe  "$target" "$report"
    _recon_subdomain_hints "$target" "$report"

    echo ""
    report_finalize "$report"
    log_success "RECON" "Complete for $target. Report: $report"
}

# ── Tool Check ────────────────────────────────────────────────────────────────
_recon_check_tools() {
    print_subsection "Tool Availability"

    local tools=("nmap" "whois" "dig" "host" "curl" "traceroute")
    local missing=()

    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            printf "    ${GREEN}✔${RESET}  ${DIM}%-14s${RESET} available\n" "$tool"
        else
            printf "    ${YELLOW}⚠${RESET}  ${DIM}%-14s${RESET} ${YELLOW}not found${RESET}\n" "$tool"
            missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo ""
        print_info "Install missing: sudo apt install ${missing[*]}"
    fi
}

# ── DNS Enumeration ───────────────────────────────────────────────────────────
_recon_dns() {
    local target="$1"
    local report="$2"

    print_subsection "DNS Records"
    report_section "$report" "DNS Records"
    log_info "RECON" "DNS lookup: $target"

    if ! command -v dig &>/dev/null; then
        print_warn "dig not available — skipping DNS"
        return
    fi

    local record_types=("A" "AAAA" "MX" "NS" "TXT" "CNAME" "SOA")

    for rtype in "${record_types[@]}"; do
        local result
        result=$(dig +short "$rtype" "$target" 2>/dev/null)
        if [[ -n "$result" ]]; then
            print_kv "  $rtype" "$result"
            report_append "$report" "$rtype : $result"
        fi
    done

    local ip
    ip=$(dig +short A "$target" 2>/dev/null | head -1)
    if [[ -n "$ip" ]]; then
        local rdns
        rdns=$(dig +short -x "$ip" 2>/dev/null)
        print_kv "  PTR ($ip)" "${rdns:-no reverse DNS}"
        report_append "$report" "PTR ($ip) : ${rdns:-N/A}"
    fi
}

# ── WHOIS Lookup ──────────────────────────────────────────────────────────────
_recon_whois() {
    local target="$1"
    local report="$2"

    print_subsection "WHOIS"
    report_section "$report" "WHOIS Data"
    log_info "RECON" "WHOIS: $target"

    if ! command -v whois &>/dev/null; then
        print_warn "whois not available — skipping"
        return
    fi

    local whois_data
    whois_data=$(whois "$target" 2>/dev/null | grep -v "^%" | grep -v "^#" | grep -v "^$")

    if [[ -z "$whois_data" ]]; then
        print_warn "No WHOIS data returned"
        return
    fi

    local fields=(
        "Registrar:"
        "Registrant Organization:"
        "Registrant Country:"
        "Creation Date:"
        "Registry Expiry Date:"
        "Name Server:"
        "OrgName:"
        "NetRange:"
        "CIDR:"
        "Country:"
    )

    for field in "${fields[@]}"; do
        local value
        value=$(echo "$whois_data" | grep -i "^${field}" | head -1 | cut -d':' -f2- | sed 's/^ *//')
        if [[ -n "$value" ]]; then
            print_kv "  ${field%:}" "$value"
            report_append "$report" "${field%:} : $value"
        fi
    done

    echo "$whois_data" >> "$report"
}

# ── Port Scanning ─────────────────────────────────────────────────────────────
_recon_portscan() {
    local target="$1"
    local report="$2"

    print_subsection "Port Scan  (nmap -sV -sC --open -T4)"
    report_section "$report" "Port Scan Results"
    log_info "RECON" "Starting port scan: $target"

    if ! command -v nmap &>/dev/null; then
        print_warn "nmap not available — skipping port scan"
        report_append "$report" "nmap not available"
        return
    fi

    print_info "Scanning top 1000 ports with version & script detection..."
    echo ""

    local nmap_xml
    nmap_xml=$(mktemp /tmp/sentrycli_nmap_XXXX.xml)

    # Run nmap and capture both normal and XML output
    local nmap_out
    nmap_out=$(nmap -sV -sC --open -T4 \
        --script=banner,http-title,ssh-hostkey \
        -oX "$nmap_xml" \
        "$target" 2>/dev/null)

    # ── Parse & display open ports in a clean table ───────────────────────────
    # Extract port lines from nmap normal output:
    # Format: 22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu ...
    local found_ports=0
    local port_lines
    port_lines=$(echo "$nmap_out" | grep -E "^[0-9]+/(tcp|udp)[[:space:]]+open")

    if [[ -n "$port_lines" ]]; then
        print_port_header

        while IFS= read -r line; do
            local port proto state service version risk_color
            port=$(echo "$line"    | awk '{print $1}' | cut -d'/' -f1)
            proto=$(echo "$line"   | awk '{print $1}' | cut -d'/' -f2)
            state=$(echo "$line"   | awk '{print $2}')
            service=$(echo "$line" | awk '{print $3}')
            version=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf $i" "; print ""}' | sed 's/[[:space:]]*$//')

            # Truncate long version strings
            if [[ ${#version} -gt 42 ]]; then
                version="${version:0:42}…"
            fi

            # Color by risk
            risk_color="$WHITE"
            case "$port" in
                21|23)   risk_color="$RED" ;;
                22|3389) risk_color="$YELLOW" ;;
                80|443)  risk_color="$GREEN" ;;
                445|3306|1433|5432|6379|27017) risk_color="$RED" ;;
            esac

            print_port_row "${port}/${proto}" "$state" "$service" "$version" "$risk_color"
            report_append "$report" "$(printf '%-18s  %-8s  %-14s  %s' "${port}/${proto}" "$state" "$service" "$version")"
            log_info "RECON" "Open port: ${port}/${proto} $service $version"
            (( found_ports++ ))
        done <<< "$port_lines"

        echo ""
    fi

    # ── Summary ───────────────────────────────────────────────────────────────
    if [[ $found_ports -eq 0 ]]; then
        print_warn "No open ports detected — target may be filtered or down"
        report_append "$report" "No open ports found"
    else
        print_kv "  Open ports found" "$found_ports"
        report_append "$report" "TOTAL OPEN PORTS: $found_ports"
    fi

    # ── HTTP titles from nmap scripts ─────────────────────────────────────────
    local http_titles
    http_titles=$(echo "$nmap_out" | grep -i "http-title" | sed 's/.*http-title: //')
    if [[ -n "$http_titles" ]]; then
        echo ""
        print_kv "  HTTP Title(s)" "$http_titles"
        report_append "$report" "HTTP Title: $http_titles"
    fi

    # ── SSH host key fingerprints ─────────────────────────────────────────────
    local ssh_keys
    ssh_keys=$(echo "$nmap_out" | grep -A2 "ssh-hostkey" | grep -E "[0-9a-f]{2}:" | head -2 | sed 's/^[[:space:]]*//')
    if [[ -n "$ssh_keys" ]]; then
        echo ""
        print_info "SSH Host Key Fingerprints:"
        while IFS= read -r key; do
            print_kv "  " "$key"
        done <<< "$ssh_keys"
    fi

    # ── Banner grabs ──────────────────────────────────────────────────────────
    local banners
    banners=$(echo "$nmap_out" | grep -E "^\|.*banner" | head -5 | sed 's/^|[[:space:]]*//')
    if [[ -n "$banners" ]]; then
        echo ""
        print_info "Service Banners:"
        while IFS= read -r banner; do
            print_kv "  " "$banner"
        done <<< "$banners"
    fi

    # ── Flag risky ports ──────────────────────────────────────────────────────
    _recon_flag_risky_ports "$nmap_out" "$report"

    # Save nmap XML
    if [[ -f "$nmap_xml" ]]; then
        local xml_dest="${SENTRYCLI_ROOT}/reports/nmap_${target//[^a-zA-Z0-9._-]/_}_$(date +%Y%m%d_%H%M%S).xml"
        cp "$nmap_xml" "$xml_dest"
        rm -f "$nmap_xml"
        print_kv "  Raw XML saved" "$xml_dest"
        report_append "$report" "nmap XML: $xml_dest"
    fi
}

# ── Flag Risky Ports ──────────────────────────────────────────────────────────
_recon_flag_risky_ports() {
    local nmap_out="$1"
    local report="$2"

    local risky_ports=(
        "21:FTP — cleartext credentials, anon login risk"
        "23:Telnet — cleartext session, CRITICAL"
        "445:SMB — EternalBlue / ransomware vector"
        "1433:MSSQL — database exposed to network"
        "3306:MySQL — database exposed to network"
        "5432:PostgreSQL — database exposed to network"
        "3389:RDP — brute-force / BlueKeep risk"
        "5900:VNC — remote access, often unencrypted"
        "6379:Redis — frequently unauthenticated"
        "27017:MongoDB — frequently unauthenticated"
        "9200:Elasticsearch — data exposure risk"
    )

    local found_risky=0
    for entry in "${risky_ports[@]}"; do
        local port="${entry%%:*}"
        local note="${entry#*:}"
        if echo "$nmap_out" | grep -qE "^${port}/(tcp|udp)[[:space:]]+open"; then
            if [[ $found_risky -eq 0 ]]; then
                echo ""
                echo -e "  ${RED}${BOLD}⚠  HIGH-RISK PORTS DETECTED${RESET}"
                echo -e "  ${DIM}$(printf '%.0s─' {1..50})${RESET}"
                report_section "$report" "Risky Ports Flagged"
            fi
            print_critical "Port ${port} — ${note}"
            report_append "$report" "RISK: Port $port - $note"
            log_alert "RECON" "Risky port open: $port - $note"
            (( found_risky++ ))
        fi
    done
}

# ── HTTP/HTTPS Probe ──────────────────────────────────────────────────────────
_recon_http_probe() {
    local target="$1"
    local report="$2"

    print_subsection "HTTP/HTTPS Probe"
    report_section "$report" "HTTP Probe"
    log_info "RECON" "HTTP probing: $target"

    if ! command -v curl &>/dev/null; then
        print_warn "curl not available — skipping"
        return
    fi

    for scheme in "https" "http"; do
        local url="${scheme}://${target}"
        print_info "Probing ${url}..."

        local headers
        headers=$(curl -s -I -L --max-time 10 --connect-timeout 5 \
            -A "Mozilla/5.0 (compatible; SentryCLI/1.0)" \
            "$url" 2>/dev/null)

        if [[ -z "$headers" ]]; then
            print_warn "  No response from ${url}"
            continue
        fi

        local status server powered_by x_frame hsts csp
        status=$(echo "$headers"     | grep -i "^HTTP/"              | tail -1 | tr -d '\r')
        server=$(echo "$headers"     | grep -i "^Server:"            | head -1 | cut -d':' -f2- | tr -d '\r ')
        powered_by=$(echo "$headers" | grep -i "^X-Powered-By:"      | head -1 | cut -d':' -f2- | tr -d '\r ')
        x_frame=$(echo "$headers"    | grep -i "^X-Frame-Options:"   | head -1 | cut -d':' -f2- | tr -d '\r ')
        hsts=$(echo "$headers"       | grep -i "^Strict-Transport-Security:" | head -1 | cut -d':' -f2- | tr -d '\r ')
        csp=$(echo "$headers"        | grep -i "^Content-Security-Policy:"   | head -1 | cut -d':' -f2- | tr -d '\r ')

        echo ""
        print_kv "  Status"          "$status"
        print_kv "  Server"          "${server:-unknown}"
        [[ -n "$powered_by" ]] && print_kv "  X-Powered-By"  "$powered_by"
        print_kv "  X-Frame-Options" "${x_frame:-${YELLOW}MISSING ⚠${RESET}}"
        print_kv "  HSTS"            "${hsts:-${YELLOW}NOT SET ⚠${RESET}}"
        [[ -n "$csp" ]] && print_kv "  CSP" "${csp:0:60}"

        echo ""
        # Security header warnings — consolidated, not repeated
        local issues=()
        [[ -z "$x_frame" ]] && issues+=("Missing X-Frame-Options (clickjacking risk)")
        [[ -z "$hsts" ]]    && issues+=("Missing HSTS (SSL downgrade risk)")
        [[ -z "$csp" ]]     && issues+=("Missing Content-Security-Policy (XSS risk)")

        for issue in "${issues[@]}"; do
            print_warn "  $issue"
        done

        report_append "$report" "$scheme Status     : $status"
        report_append "$report" "$scheme Server     : ${server:-unknown}"
        report_append "$report" "$scheme Powered-By : ${powered_by:-N/A}"
        report_append "$report" "$scheme HSTS       : ${hsts:-NOT SET}"
        report_append "$report" "$scheme X-Frame    : ${x_frame:-MISSING}"
        break   # probe the first responsive scheme only
    done
}

# ── Subdomain Discovery ───────────────────────────────────────────────────────
_recon_subdomain_hints() {
    local target="$1"
    local report="$2"

    # Skip for IPs
    if echo "$target" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        return
    fi

    print_subsection "Subdomain Discovery"
    report_section "$report" "Subdomain Discovery"
    log_info "RECON" "Subdomain probing: $target"

    local common_subs=(
        "www" "mail" "remote" "blog" "webmail" "server"
        "ns1" "ns2" "smtp" "secure" "vpn" "m" "shop"
        "ftp" "admin" "api" "dev" "staging" "test"
        "portal" "cloud" "cdn" "app" "auth" "git"
    )

    local found=0
    print_info "Probing ${#common_subs[@]} common subdomains..."
    echo ""

    for sub in "${common_subs[@]}"; do
        local fqdn="${sub}.${target}"
        local ip
        ip=$(dig +short A "$fqdn" 2>/dev/null | head -1)
        if [[ -n "$ip" ]]; then
            printf "    ${GREEN}✔${RESET}  ${WHITE}%-32s${RESET}  ${CYAN}%s${RESET}\n" "$fqdn" "$ip"
            report_append "$report" "  $fqdn -> $ip"
            log_info "RECON" "Subdomain: $fqdn -> $ip"
            (( found++ ))
        fi
    done

    echo ""
    if [[ $found -eq 0 ]]; then
        print_info "No common subdomains resolved"
    else
        print_kv "  Subdomains found" "$found"
    fi
}
