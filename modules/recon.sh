#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Reconnaissance Module (Clean & Professional Output)
# modules/recon.sh
# =============================================================================

run_recon() {
    local target="${1:-}"
    print_section "RECONNAISSANCE MODULE"
    log_info "RECON" "Module started"

    if [[ -z "$target" ]]; then
        echo -ne " ${CYAN}${BOLD}Enter target (IP or domain): ${RESET}"
        read -r target
    fi

    [[ -z "$target" ]] && { print_alert "No target specified. Aborting."; return 1; }

    # Sanitize target
    target=$(echo "$target" | tr -d '[:space:]' | sed 's|https\?://||g' | cut -d'/' -f1)

    echo ""
    print_kv "Target" "$target"
    print_kv "Started" "$(date '+%Y-%m-%d %H:%M:%S')"
    echo "────────────────────────────────────────────────────────────"

    local report
    report=$(report_init "recon_${target//[^a-zA-Z0-9._-]/_}")
    report_section "$report" "Reconnaissance: $target"
    report_append "$report" "Target : $target"
    report_append "$report" "Started: $(date)"

    _recon_check_tools
    _recon_dns "$target" "$report"
    _recon_whois "$target" "$report"
    _recon_portscan "$target" "$report"
    _recon_http_probe "$target" "$report"
    _recon_subdomain_hints "$target" "$report"

    report_finalize "$report"
    log_success "RECON" "Reconnaissance complete for $target"
}

# ── Tool Availability ───────────────────────────────────────────────────────
_recon_check_tools() {
    print_subsection "Tool Availability"
    local tools=("nmap" "whois" "dig" "curl")
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            printf " ${GREEN}✔${RESET} %-12s ${GREEN}available${RESET}\n" "$tool"
        else
            printf " ${YELLOW}⚠${RESET} %-12s ${YELLOW}missing${RESET}\n" "$tool"
        fi
    done
    echo ""
}

# ── DNS Records - Clean Tabular Output ──────────────────────────────────────
_recon_dns() {
    local target="$1"
    local report="$2"

    print_subsection "DNS Records"
    report_section "$report" "DNS Records"

    if ! command -v dig &>/dev/null; then
        print_warn "dig not available — skipping DNS enumeration"
        return
    fi

    echo ""
    printf "${BOLD}%-8s  %s${RESET}\n" "TYPE" "VALUE"
    echo "────────────────────────────────────────────────────────────"

    local record_types=("A" "AAAA" "MX" "NS" "TXT" "CNAME" "SOA")
    local has_records=0

    for rtype in "${record_types[@]}"; do
        local result
        result=$(dig +short "$rtype" "$target" 2>/dev/null)

        if [[ -n "$result" ]]; then
            has_records=1
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                # Clean dig noise and extra spaces
                line=$(echo "$line" | sed 's/;;.*//g' | sed 's/^[[:space:]]*//' | tr -d '\r')
                [[ -z "$line" ]] && continue

                printf "%-8s  %s\n" "$rtype" "$line"
                report_append "$report" "${rtype} : $line"
            done <<< "$result"
        fi
    done

    # PTR (Reverse DNS)
    local ip
    ip=$(dig +short A "$target" 2>/dev/null | head -1)
    if [[ -n "$ip" ]]; then
        local rdns
        rdns=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//' | head -1)
        if [[ -n "$rdns" ]]; then
            printf "%-8s  %s (%s)\n" "PTR" "$rdns" "$ip"
            report_append "$report" "PTR : $rdns ($ip)"
        else
            printf "%-8s  %s (%s)\n" "PTR" "No reverse DNS" "$ip"
            report_append "$report" "PTR : No reverse DNS ($ip)"
        fi
        has_records=1
    fi

    if [[ $has_records -eq 0 ]]; then
        print_warn "No DNS records found for this target"
    fi

    echo ""
}

# ── WHOIS Information ───────────────────────────────────────────────────────
_recon_whois() {
    local target="$1"
    local report="$2"

    print_subsection "WHOIS Information"
    report_section "$report" "WHOIS Data"

    if ! command -v whois &>/dev/null; then
        print_warn "whois command not available"
        return
    fi

    print_info "Fetching WHOIS data..."
    local whois_data=$(whois "$target" 2>/dev/null | grep -Ev '^(%|#|^$|^\s*$)' | head -40)

    if [[ -z "$whois_data" ]]; then
        print_warn "No WHOIS data returned or query limited"
        return
    fi

    echo "$whois_data" | while IFS= read -r line; do
        echo -e "   ${DIM}$line${RESET}"
    done
    echo ""

    echo "$whois_data" >> "$report"
}

# ── Clean Tabular Port Scan ─────────────────────────────────────────────────
_recon_portscan() {
    local target="$1"
    local report="$2"

    print_subsection "Port Scan + Service & OS Detection"
    report_section "$report" "Port Scan Results"

    if ! command -v nmap &>/dev/null; then
        print_warn "nmap not found — skipping port scan"
        return
    fi

    print_info "Running nmap scan (may take 30-60 seconds)..."
    echo ""

    local nmap_out xml_file="/tmp/sentry_nmap_$$.xml"

    nmap_out=$(nmap -sV -sC -O -T4 --open --script=banner,http-title \
                -oX "$xml_file" "$target" 2>&1)

    local port_lines
    port_lines=$(echo "$nmap_out" | grep -E "^[0-9]+/(tcp|udp)[[:space:]]+open" | sort -V)

    if [[ -n "$port_lines" ]]; then
        printf "${BOLD}%-12s %-8s %-20s %-35s${RESET}\n" "PORT" "STATE" "SERVICE" "VERSION"
        echo "──────────────────────────────────────────────────────────────────────────────"

        while IFS= read -r line; do
            local port proto service version
            port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
            proto=$(echo "$line" | awk '{print $1}' | cut -d'/' -f2)
            service=$(echo "$line" | awk '{print $3}')
            version=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf $i" "; print ""}' | sed 's/[[:space:]]*$//')

            [[ ${#version} -gt 32 ]] && version="${version:0:29}..."

            local color="$WHITE"
            case "$port" in
                21|23|445|1433|3306|5432|3389|5900|6379|27017|9200) color="$RED" ;;
                22|80|443|8080|8443) color="$GREEN" ;;
                *) color="$YELLOW" ;;
            esac

            printf "${color}%-12s${RESET} open     %-20s %-35s\n" "${port}/${proto}" "$service" "${version:-N/A}"
            report_append "$report" "${port}/${proto} open ${service} ${version}"
        done <<< "$port_lines"
        echo ""
    else
        print_warn "No open ports detected (firewall may be active or host is down)"
        report_append "$report" "No open ports found"
    fi

    # OS Fingerprint
    local os_info=$(echo "$nmap_out" | grep -oE 'OS details: .*' | sed 's/OS details: //' | head -1)
    if [[ -n "$os_info" ]]; then
        print_kv "OS Fingerprint" "$os_info"
        report_append "$report" "OS Fingerprint: $os_info"
    fi

    # Save XML report
    if [[ -f "$xml_file" ]]; then
        local xml_dest="${SENTRYCLI_ROOT}/reports/nmap_${target//[^a-zA-Z0-9._-]/_}_$(date +%Y%m%d_%H%M%S).xml"
        mv "$xml_file" "$xml_dest" 2>/dev/null
        print_kv "nmap XML Saved" "$xml_dest"
        report_append "$report" "nmap XML: $xml_dest"
    fi

    _recon_flag_risky_ports "$nmap_out" "$report"
    echo ""
}

# ── High Risk Ports Alert ───────────────────────────────────────────────────
_recon_flag_risky_ports() {
    local nmap_out="$1"
    local report="$2"

    local risky=(
        "21:FTP — cleartext risk"
        "23:Telnet — cleartext, CRITICAL"
        "445:SMB — ransomware vector"
        "1433:MSSQL exposed"
        "3306:MySQL exposed"
        "5432:PostgreSQL exposed"
        "3389:RDP — brute force risk"
        "6379:Redis often unauthenticated"
        "27017:MongoDB often unauthenticated"
    )

    local found=0
    for entry in "${risky[@]}"; do
        local port="${entry%%:*}"
        local note="${entry#*:}"
        if echo "$nmap_out" | grep -qE "^${port}/(tcp|udp)[[:space:]]+open"; then
            [[ $found -eq 0 ]] && { echo ""; print_critical "HIGH-RISK PORTS DETECTED:"; }
            print_critical "   • Port ${port} — ${note}"
            report_append "$report" "RISK: Port $port - $note"
            (( found++ ))
        fi
    done
}

# ── HTTP/HTTPS Probe ────────────────────────────────────────────────────────
_recon_http_probe() {
    local target="$1"
    local report="$2"

    print_subsection "HTTP/HTTPS Security Headers"
    report_section "$report" "HTTP Probe"

    if ! command -v curl &>/dev/null; then
        print_warn "curl not available"
        return
    fi

    for scheme in https http; do
        local url="${scheme}://${target}"
        print_info "Probing ${url}..."

        local headers
        headers=$(curl -s -I -L --max-time 10 --connect-timeout 6 \
            -A "Mozilla/5.0 (compatible; SentryCLI/1.0)" "$url" 2>/dev/null)

        if [[ -z "$headers" ]]; then
            print_warn " No response from ${url}"
            continue
        fi

        local status server xframe hsts csp
        status=$(echo "$headers" | grep -i "^HTTP/" | tail -1 | tr -d '\r')
        server=$(echo "$headers" | grep -i "^Server:" | head -1 | cut -d':' -f2- | tr -d '\r ')
        xframe=$(echo "$headers" | grep -i "^X-Frame-Options:" | head -1 | cut -d':' -f2- | tr -d '\r ')
        hsts=$(echo "$headers" | grep -i "^Strict-Transport-Security:" | head -1 | cut -d':' -f2- | tr -d '\r ')
        csp=$(echo "$headers" | grep -i "^Content-Security-Policy:" | head -1 | cut -d':' -f2- | tr -d '\r ')

        print_kv " Status" "$status"
        print_kv " Server" "${server:-unknown}"
        print_kv " X-Frame-Options" "${xframe:-${YELLOW}MISSING${RESET}}"
        print_kv " HSTS" "${hsts:-${YELLOW}NOT SET${RESET}}"
        [[ -n "$csp" ]] && print_kv " CSP" "${csp:0:65}..."

        report_append "$report" "$scheme: $status | Server: ${server:-unknown} | HSTS: ${hsts:-MISSING}"
        break
    done
    echo ""
}

# ── Subdomain Hints ─────────────────────────────────────────────────────────
_recon_subdomain_hints() {
    local target="$1"
    local report="$2"

    if echo "$target" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        return
    fi

    print_subsection "Common Subdomain Check"
    report_section "$report" "Subdomain Discovery"

    local common_subs=("www" "mail" "remote" "admin" "api" "dev" "test" "staging" "portal" "vpn" "ftp" "login")
    print_info "Checking ${#common_subs[@]} common subdomains..."

    local found=0
    for sub in "${common_subs[@]}"; do
        local fqdn="${sub}.${target}"
        local ip=$(dig +short A "$fqdn" 2>/dev/null | head -1)
        if [[ -n "$ip" ]]; then
            printf " ${GREEN}✔${RESET} %-35s → %s\n" "$fqdn" "$ip"
            report_append "$report" "Subdomain: $fqdn → $ip"
            (( found++ ))
        fi
    done

    [[ $found -eq 0 ]] && print_info "No common subdomains resolved"
    echo ""
}
