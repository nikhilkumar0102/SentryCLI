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

show_help() {
    # Banner already shown by main() — NOT called again here
    echo -e "${BOLD}${WHITE}USAGE${RESET}"
    echo -e "  ${CYAN}./main.sh${RESET} [OPTIONS]"
    echo ""
    echo -e "${BOLD}${WHITE}MODULE OPTIONS${RESET}"
    print_kv "  --module log"     "Log Intelligence — brute force & IP extraction"
    print_kv "  --module recon"   "Reconnaissance — ports, DNS, WHOIS, tech stack"
    print_kv "  --module ir"      "Incident Response — forensic system triage"
    print_kv "  --module ipcheck" "IP Threat Intel — AbuseIPDB + VirusTotal lookup"
    print_kv "  --module all"     "Run all modules sequentially"
    echo ""
    echo -e "${BOLD}${WHITE}MODULE FLAGS${RESET}"
    print_kv "  --log-file PATH" "Specify log file for logintel (default: auto-detect)"
    print_kv "  --target HOST"   "Target IP or domain for recon"
    print_kv "  --ip LIST"       "Space/comma separated IPs for ipcheck"
    echo ""
    echo -e "${BOLD}${WHITE}ADVANCED OPTIONS${RESET}"
    print_kv "  --correlate"  "Pipeline: logintel → ipcheck (SIEM-like correlation)"
    print_kv "  --menu"       "Interactive menu mode"
    print_kv "  --version"    "Show version"
    print_kv "  --help, -h"   "Show this help"
    echo ""
    echo -e "${BOLD}${WHITE}EXAMPLES${RESET}"
    echo -e "  ${DIM}./main.sh --module log --log-file /var/log/auth.log${RESET}"
    echo -e "  ${DIM}./main.sh --module recon --target scanme.nmap.org${RESET}"
    echo -e "  ${DIM}./main.sh --module ir${RESET}"
    echo -e "  ${DIM}./main.sh --module ipcheck --ip \"8.8.8.8,1.1.1.1\"${RESET}"
    echo -e "  ${DIM}./main.sh --correlate${RESET}"
    echo ""
}

show_menu() {
    # Banner already shown by main() — NOT called again here
    echo -e "  ${BOLD}${WHITE}MAIN MENU${RESET}"
    echo ""
    echo -e "  ${CYAN}[1]${RESET}  Log Intelligence       ${DIM}— Analyze auth logs for attacks${RESET}"
    echo -e "  ${CYAN}[2]${RESET}  Reconnaissance         ${DIM}— Enumerate a target host${RESET}"
    echo -e "  ${CYAN}[3]${RESET}  Incident Response      ${DIM}— Live forensic triage${RESET}"
    echo -e "  ${CYAN}[4]${RESET}  IP Threat Intelligence ${DIM}— Check IPs against threat feeds${RESET}"
    echo -e "  ${CYAN}[5]${RESET}  SIEM Correlation       ${DIM}— Log → IP threat pipeline${RESET}"
    echo -e "  ${CYAN}[6]${RESET}  Run All Modules        ${DIM}— Full security sweep${RESET}"
    echo -e "  ${CYAN}[7]${RESET}  View Audit Log         ${DIM}— Review session history${RESET}"
    echo -e "  ${CYAN}[0]${RESET}  Exit"
    echo ""
    echo -ne "  ${CYAN}${BOLD}Select option: ${RESET}"
    read -r choice

    case "$choice" in
        1)
            echo -ne "  ${CYAN}Log file path (leave blank to auto-detect): ${RESET}"
            read -r log_file
            run_logintel "$log_file"
            ;;
        2)
            echo -ne "  ${CYAN}Target IP or domain: ${RESET}"
            read -r target
            run_recon "$target"
            ;;
        3)  run_incident ;;
        4)
            echo -ne "  ${CYAN}IP address(es) (space/comma separated): ${RESET}"
            read -r ip_input
            IFS=', ' read -ra ip_array <<< "$ip_input"
            run_ipcheck "${ip_array[@]}"
            ;;
        5)  run_correlation ;;
        6)  run_all_modules ;;
        7)  view_audit_log ;;
        0)
            print_info "Exiting SentryCLI. Goodbye."
            exit 0
            ;;
        *)  print_warn "Invalid option: $choice" ;;
    esac

    echo ""
    echo -ne "  ${DIM}Press ENTER to return to menu...${RESET}"
    read -r
    clear
    print_banner
    show_menu
}

run_correlation() {
    local log_file="${1:-}"
    print_section "SIEM CORRELATION ENGINE"
    print_info "Pipeline: Log Intelligence → IP Threat Intelligence"
    echo ""
    log_info "CORRELATE" "Correlation engine started"

    print_info "Phase 1/2 — Running Log Intelligence Module..."
    run_logintel "$log_file"

    if [[ -z "$SUSPICIOUS_IPS_FILE" || ! -s "$SUSPICIOUS_IPS_FILE" ]]; then
        print_warn "No suspicious IPs extracted from logs — correlation skipped"
        log_warn "CORRELATE" "No IPs to correlate"
        return
    fi

    local ip_count
    ip_count=$(wc -l < "$SUSPICIOUS_IPS_FILE")
    echo ""
    print_info "Phase 2/2 — Running IP Threat Intelligence on ${ip_count} extracted IPs..."

    local ip_list=()
    while IFS= read -r ip; do
        [[ -n "$ip" ]] && ip_list+=("$ip")
    done < "$SUSPICIOUS_IPS_FILE"

    run_ipcheck "${ip_list[@]}"
    _correlation_final_report
    log_success "CORRELATE" "Correlation complete. Malicious IPs: ${#MALICIOUS_IPS[@]}"
}

_correlation_final_report() {
    print_section "CORRELATION FINDINGS"
    local corr_report
    corr_report=$(report_init "siem_correlation")
    report_section "$corr_report" "SIEM Correlation Results"

    if [[ ${#MALICIOUS_IPS[@]} -gt 0 ]]; then
        print_critical "CONFIRMED MALICIOUS IPs ATTACKING YOUR SYSTEM:"
        report_append "$corr_report" "CONFIRMED MALICIOUS ATTACKERS:"
        for ip in "${MALICIOUS_IPS[@]}"; do
            print_critical "  ✘ ${ip}"
            report_append "$corr_report" "  $ip — MALICIOUS"
            log_critical "CORRELATE" "Confirmed malicious attacker IP: $ip"
        done
        echo ""
        print_warn "RECOMMENDED ACTIONS:"
        print_kv "  iptables"  "sudo iptables -A INPUT -s <IP> -j DROP"
        print_kv "  ufw"       "sudo ufw deny from <IP>"
        report_section "$corr_report" "iptables Block Commands"
        for ip in "${MALICIOUS_IPS[@]}"; do
            report_append "$corr_report" "sudo iptables -A INPUT -s ${ip} -j DROP"
        done
    else
        print_success "No confirmed malicious IPs found in correlation sweep"
        report_append "$corr_report" "No confirmed malicious IPs found"
    fi
    report_finalize "$corr_report"
}

run_all_modules() {
    local target="${1:-}"
    local log_file="${2:-}"
    print_section "FULL SECURITY SWEEP"
    print_warn "Running all modules sequentially..."
    log_info "MAIN" "Full sweep initiated"
    run_logintel   "$log_file"
    echo ""
    run_incident
    echo ""
    [[ -n "$target" ]] && run_recon "$target"
    if [[ -n "$SUSPICIOUS_IPS_FILE" && -s "$SUSPICIOUS_IPS_FILE" ]]; then
        local ip_list=()
        while IFS= read -r ip; do
            [[ -n "$ip" ]] && ip_list+=("$ip")
        done < "$SUSPICIOUS_IPS_FILE"
        run_ipcheck "${ip_list[@]}"
    fi
    log_success "MAIN" "Full sweep completed"
}

view_audit_log() {
    print_section "SESSION AUDIT LOG"
    if [[ -f "$SENTRYCLI_LOG_FILE" ]]; then
        print_info "Log: ${SENTRYCLI_LOG_FILE}"
        echo ""
        tail -50 "$SENTRYCLI_LOG_FILE" | while IFS= read -r line; do
            if echo "$line" | grep -q "CRITICAL\|ALERT"; then
                echo -e "  ${RED}$line${RESET}"
            elif echo "$line" | grep -q "WARNING"; then
                echo -e "  ${YELLOW}$line${RESET}"
            elif echo "$line" | grep -q "SUCCESS"; then
                echo -e "  ${GREEN}$line${RESET}"
            else
                echo -e "  ${DIM}$line${RESET}"
            fi
        done
    else
        print_info "No audit log found yet"
    fi
}

startup_checks() {
    mkdir -p "${SENTRYCLI_ROOT}/reports"
    chmod 600 "${SENTRYCLI_ROOT}/config/api_keys.conf" 2>/dev/null || true
    log_session_start "MAIN"
    log_info "MAIN" "SentryCLI v${VERSION} started. User: $(whoami) | Host: $(hostname)"
}

parse_args() {
    local module=""
    local target=""
    local log_file=""
    local ip_list=()
    local mode="cli"

    if [[ $# -eq 0 ]]; then
        mode="menu"
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --module|-m)   module="${2:-}";                            shift 2 ;;
            --target|-t)   target="${2:-}";                            shift 2 ;;
            --log-file|-l) log_file="${2:-}";                          shift 2 ;;
            --ip|-i)       IFS=', ' read -ra ip_list <<< "${2:-}";    shift 2 ;;
            --correlate|-c) mode="correlate";                          shift   ;;
            --menu)        mode="menu";                                shift   ;;
            --version|-v)  echo -e "  SentryCLI v${VERSION}";         exit 0  ;;
            --help|-h)     show_help;                                  exit 0  ;;
            *)             print_warn "Unknown argument: $1";          shift   ;;
        esac
    done

    case "$mode" in
        menu)      show_menu ;;
        correlate) run_correlation "$log_file" ;;
        cli)
            case "$module" in
                log|logintel)        run_logintel "$log_file" ;;
                recon|reconnaissance) run_recon "$target" ;;
                ir|incident)         run_incident ;;
                ipcheck|ip)
                    if [[ ${#ip_list[@]} -gt 0 ]]; then
                        run_ipcheck "${ip_list[@]}"
                    else
                        run_ipcheck
                    fi ;;
                all) run_all_modules "$target" "$log_file" ;;
                "")  show_help ;;
                *)
                    print_alert "Unknown module: ${module}"
                    print_info "Valid modules: log, recon, ir, ipcheck, all"
                    exit 1
                    ;;
            esac ;;
    esac
}

# ── Entry Point — Banner printed ONCE, here only ──────────────────────────────
main() {
    print_banner
    startup_checks
    parse_args "$@"
}

main "$@"
