#!/usr/bin/env bash

# =============================================================================
# SentryCLI — Modular Security Operations & Penetration Testing Toolkit
# main.sh — Central CLI Controller
# =============================================================================

set -euo pipefail

SENTRYCLI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SENTRYCLI_ROOT

source "${SENTRYCLI_ROOT}/utils/colors.sh"
source "${SENTRYCLI_ROOT}/utils/logger.sh"
source "${SENTRYCLI_ROOT}/modules/logintel.sh"
source "${SENTRYCLI_ROOT}/modules/recon.sh"
source "${SENTRYCLI_ROOT}/modules/incident.sh"
source "${SENTRYCLI_ROOT}/modules/ipcheck.sh"

VERSION="1.0.0"
MALICIOUS_IPS=()
SUSPICIOUS_IPS_FILE=""

cleanup() {
    spinner_stop 2>/dev/null || true
    log_session_end "MAIN"
    [[ -n "$SUSPICIOUS_IPS_FILE" && -f "$SUSPICIOUS_IPS_FILE" ]] && rm -f "$SUSPICIOUS_IPS_FILE"
}

trap cleanup EXIT INT TERM

# ── Beautiful & Complete Help ────────────────────────────────────────────────
show_help() {
    echo -e "${BOLD}${WHITE}SentryCLI v${VERSION}${RESET}"
    echo -e "${DIM}Modular Security Operations & Penetration Testing Toolkit${RESET}"
    echo ""
    echo -e "${BOLD}${WHITE}USAGE${RESET}"
    echo -e " ${CYAN}./main.sh${RESET} [OPTIONS]"
    echo ""

    echo -e "${BOLD}${WHITE}AVAILABLE MODULES${RESET}"
    print_kv " --module log"        "Log Intelligence — Brute-force & attack detection from logs"
    print_kv " --module recon"      "Reconnaissance — DNS, ports, WHOIS, subdomains"
    print_kv " --module ir"         "Incident Response — Live forensic triage"
    print_kv " --module ipcheck"    "IP & Hash Threat Intelligence"
    print_kv " --module all"        "Run all modules in sequence"
    echo ""

    echo -e "${BOLD}${WHITE}IPCHECK MODULE FLAGS${RESET}"
    print_kv " --ip   <IP>"         "Analyze one or more IPv4 addresses"
    print_kv " --hash <HASH>"       "Analyze file hash (MD5, SHA1, SHA256) using VirusTotal only"
    echo ""

    echo -e "${BOLD}${WHITE}LOG ANALYSIS FLAGS${RESET}"
    print_kv " --log-file PATH"     "Specify custom log file for logintel module"
    echo ""

    echo -e "${BOLD}${WHITE}OTHER FLAGS${RESET}"
    print_kv " --target HOST"       "Target IP/domain for recon module"
    print_kv " --correlate"         "Run full correlation pipeline (logs → threat intel)"
    print_kv " --menu"              "Launch interactive menu"
    print_kv " --version, -v"       "Show version"
    print_kv " --help, -h"          "Show this help"
    echo ""

    echo -e "${BOLD}${WHITE}EXAMPLES${RESET}"
    echo -e "${CYAN}1. Log Analysis${RESET}"
    echo -e "   ${DIM}./main.sh --module log --log-file /var/log/auth.log${RESET}"
    echo -e "   ${DIM}./main.sh --module log${RESET}                    ${DIM}# auto-detect logs${RESET}"
    echo ""
    echo -e "${CYAN}2. Reconnaissance${RESET}"
    echo -e "   ${DIM}./main.sh --module recon --target scanme.nmap.org${RESET}"
    echo ""
    echo -e "${CYAN}3. Incident Response${RESET}"
    echo -e "   ${DIM}./main.sh --module ir${RESET}"
    echo ""
    echo -e "${CYAN}4. IP Threat Intelligence${RESET}"
    echo -e "   ${DIM}./main.sh --module ipcheck --ip \"8.8.8.8,1.1.1.1\"${RESET}"
    echo -e "   ${DIM}./main.sh --module ipcheck --ip 2.57.121.69${RESET}"
    echo ""
    echo -e "${CYAN}5. Hash Analysis (VirusTotal Only)${RESET}"
    echo -e "   ${DIM}./main.sh --module ipcheck --hash \"d41d8cd98f00b204e9800998ecf8427e\"${RESET}"
    echo -e "   ${DIM}./main.sh --module ipcheck --hash \"a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3\"${RESET}"
    echo ""
    echo -e "${CYAN}6. Full Correlation Pipeline${RESET}"
    echo -e "   ${DIM}./main.sh --correlate${RESET}"
    echo ""
    echo -e "${CYAN}7. Interactive Menu${RESET}"
    echo -e "   ${DIM}./main.sh --menu${RESET}"
    echo ""
    echo -e "${CYAN}8. Run Everything${RESET}"
    echo -e "   ${DIM}./main.sh --module all${RESET}"
    echo ""
}

show_menu() {
    echo -e " ${BOLD}${WHITE}MAIN MENU${RESET}"
    echo ""
    echo -e " ${CYAN}[1]${RESET} Log Intelligence"
    echo -e " ${CYAN}[2]${RESET} Reconnaissance"
    echo -e " ${CYAN}[3]${RESET} Incident Response"
    echo -e " ${CYAN}[4]${RESET} IP / Hash Intelligence"
    echo -e " ${CYAN}[5]${RESET} SIEM Correlation"
    echo -e " ${CYAN}[6]${RESET} Run All Modules"
    echo -e " ${CYAN}[0]${RESET} Exit"
    echo ""
    echo -ne " ${CYAN}${BOLD}Select option: ${RESET}"
    read -r choice

    case "$choice" in
        1)
            echo -ne " ${CYAN}Log file path (optional): ${RESET}"
            read -r log_file
            run_logintel "$log_file"
            ;;
        2)
            echo -ne " ${CYAN}Target IP or domain: ${RESET}"
            read -r target
            run_recon "$target"
            ;;
        3)
            run_incident
            ;;
        4)
            echo -ne " ${CYAN}Choose: (1) IP Address   (2) File Hash → "
            read -r sub
            if [[ "$sub" == "2" ]]; then
                echo -ne " ${CYAN}Enter Hash: ${RESET}"
                read -r hash_input
                run_ipcheck --hash "$hash_input"
            else
                echo -ne " ${CYAN}Enter IP(s): ${RESET}"
                read -r ip_input
                run_ipcheck --ip "$ip_input"
            fi
            ;;
        5)
            run_correlation
            ;;
        6)
            run_all_modules
            ;;
        0)
            print_info "Exiting SentryCLI. Goodbye."
            exit 0
            ;;
        *)
            print_warn "Invalid option"
            ;;
    esac

    echo ""
    echo -ne " ${DIM}Press ENTER to return to menu...${RESET}"
    read -r
    clear
    print_banner
    show_menu
}

run_correlation() {
    print_section "SIEM CORRELATION ENGINE"
    print_info "Pipeline: Log Intelligence → IP Threat Intelligence"
    run_logintel

    if [[ -z "${SUSPICIOUS_IPS_FILE:-}" || ! -s "$SUSPICIOUS_IPS_FILE" ]]; then
        print_warn "No suspicious IPs extracted from logs."
        return
    fi

    local ip_list=()
    while IFS= read -r ip; do
        [[ -n "$ip" ]] && ip_list+=("$ip")
    done < "$SUSPICIOUS_IPS_FILE"

    echo ""
    print_info "Analyzing ${#ip_list[@]} suspicious IPs..."
    run_ipcheck --ip "${ip_list[*]}"
}

run_all_modules() {
    print_section "FULL SECURITY SWEEP"
    run_logintel
    echo ""
    run_incident
    echo ""
    run_recon
    echo ""
    if [[ -n "${SUSPICIOUS_IPS_FILE:-}" && -s "$SUSPICIOUS_IPS_FILE" ]]; then
        local ip_list=()
        while IFS= read -r ip; do
            [[ -n "$ip" ]] && ip_list+=("$ip")
        done < "$SUSPICIOUS_IPS_FILE"
        run_ipcheck --ip "${ip_list[*]}"
    fi
    log_success "MAIN" "Full sweep completed"
}

parse_args() {
    local module=""
    local target=""
    local log_file=""
    local ip_input=""
    local hash_input=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --module|-m)    module="${2:-}"; shift 2 ;;
            --target|-t)    target="${2:-}"; shift 2 ;;
            --log-file|-l)  log_file="${2:-}"; shift 2 ;;
            --ip)           ip_input="${2:-}"; shift 2 ;;
            --hash)         hash_input="${2:-}"; shift 2 ;;
            --correlate|-c) run_correlation; exit 0 ;;
            --menu)         show_menu; exit 0 ;;
            --version|-v)   echo -e "SentryCLI v${VERSION}"; exit 0 ;;
            --help|-h)      show_help; exit 0 ;;
            *) 
                print_warn "Unknown argument: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Direct IP/Hash handling
    if [[ -n "$hash_input" ]]; then
        run_ipcheck --hash "$hash_input"
        exit 0
    fi
    if [[ -n "$ip_input" ]]; then
        run_ipcheck --ip "$ip_input"
        exit 0
    fi

    # Module execution
    case "$module" in
        log|logintel)   run_logintel "$log_file" ;;
        recon|reconnaissance) run_recon "$target" ;;
        ir|incident)    run_incident ;;
        ipcheck|ip)     run_ipcheck ;;
        all)            run_all_modules ;;
        "")             show_help ;;
        *)
            print_alert "Unknown module: ${module}"
            echo "Valid modules: log, recon, ir, ipcheck, all"
            exit 1
            ;;
    esac
}

# ── Entry Point ──────────────────────────────────────────────────────────────
main() {
    print_banner

    mkdir -p "${SENTRYCLI_ROOT}/reports"
    chmod 600 "${SENTRYCLI_ROOT}/config/api_keys.conf" 2>/dev/null || true

    log_session_start "MAIN"
    log_info "MAIN" "SentryCLI v${VERSION} started by $(whoami) on $(hostname)"

    parse_args "$@"
}

main "$@"
