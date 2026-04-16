#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Advanced Port Scanner Module
# modules/portscan.sh
# Professional nmap-based port scanner with clean SOC-style output
# =============================================================================

run_portscan() {
    print_section "7. ADVANCED PORT SCANNER [PORT-7]"

    local target=""

    # Parse arguments / REPL support
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --target|--host)
                target="$2"
                shift 2
                ;;
            --clear|--unset)
                unset TARGET 2>/dev/null || true
                print_success "Target cleared"
                return 0
                ;;
            *)
                print_alert "Unknown option: $1"
                echo "Usage: --target <IP or Domain>"
                return 1
                ;;
        esac
    done

    # REPL set support
    if [[ -z "$target" && -n "${TARGET:-}" ]]; then
        target="${TARGET}"
        print_info "Using REPL-set target → ${target}"
    fi

    # Interactive input
    if [[ -z "$target" ]]; then
        echo -ne "${CYAN}Enter Target (IP or Domain): ${RESET}"
        read -r target
    fi

    [[ -z "$target" ]] && { print_alert "No target provided."; return 1; }

    local report
    report=$(report_init "portscan")

    print_subsection "Scanning Target → ${target}"
    echo ""

    # Check if nmap is installed
    if ! command -v nmap &>/dev/null; then
        print_alert "nmap is not installed. Please install it first."
        echo "   sudo apt install nmap -y   (Debian/Ubuntu)"
        echo "   sudo dnf install nmap -y   (Fedora)"
        return 1
    fi

    # Perform advanced scan
    print_info "Starting Advanced Port Scan (Top 1000 ports + Service Detection + OS Detection)..."
    echo ""

    # Run nmap with good flags and capture output
    local scan_output
    scan_output=$(nmap -Pn -sV -sC -O --top-ports 1000 --reason --open -T3 "$target" 2>&1)

    # Save raw output to report
    _report_add "$report" "# Advanced Port Scan Report - ${target}"
    _report_add "$report" "**Scan Date:** $(date '+%Y-%m-%d %H:%M:%S %Z')"
    _report_add "$report" "**Target:** ${target}"
    _report_add "$report" ""
    _report_add "$report" '```'
    echo "$scan_output" >> "$report"
    _report_add "$report" '```'

    # Pretty CLI Output
    echo -e "${BOLD}${WHITE}PORT SCAN RESULTS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    # Extract and show open ports nicely
    echo "$scan_output" | grep -E '^[0-9]+/' | while read -r line; do
        port=$(echo "$line" | awk '{print $1}')
        state=$(echo "$line" | awk '{print $2}')
        service=$(echo "$line" | awk '{print $3}')
        version=$(echo "$line" | cut -d' ' -f4- | sed 's/^[[:space:]]*//')
        
        if [[ "$state" == "open" ]]; then
            print_critical " ${port} → ${service}  ${version}"
        else
            echo -e " ${DIM}${port} → ${service}  ${version}${RESET}"
        fi
    done

    # OS Detection
    local os_info
    os_info=$(echo "$scan_output" | grep -E 'OS details|Running:|Aggressive OS guesses' | head -n 3)
    if [[ -n "$os_info" ]]; then
        echo ""
        echo -e "${BOLD}${WHITE}Operating System Detection${RESET}"
        echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
        echo "$os_info"
    fi

    # Summary
    local open_ports
    open_ports=$(echo "$scan_output" | grep -cE '^[0-9]+/tcp.*open')
    
    echo ""
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target" "$target"
    print_kv "Open Ports" "${open_ports}"
    print_kv "Scan Type" "SYN + Service Version + Script + OS Detection"
    print_kv "Report Saved" "${report}"

    if [[ $open_ports -ge 5 ]]; then
        print_alert "   ⚠ High number of open ports detected"
    elif [[ $open_ports -ge 1 ]]; then
        print_success "   ✓ Ports discovered"
    else
        print_warn "   No open ports found"
    fi

    report_finalize "$report"
    log_success "PORTSCAN" "Scan completed on ${target} (${open_ports} open ports)"

    echo ""
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
}
                                                       
