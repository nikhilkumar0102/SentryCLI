#!/usr/bin/env bash
# =============================================================================
# SentryCLI — Modular Security Operations & Penetration Testing Toolkit
# main.sh — Professional Categorized REPL v2.7
# =============================================================================

set -euo pipefail

SENTRYCLI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SENTRYCLI_ROOT

source "${SENTRYCLI_ROOT}/utils/colors.sh"
source "${SENTRYCLI_ROOT}/utils/logger.sh"

# Source all modules
source "${SENTRYCLI_ROOT}/modules/logintel.sh"
source "${SENTRYCLI_ROOT}/modules/recon.sh"
source "${SENTRYCLI_ROOT}/modules/incident.sh"
source "${SENTRYCLI_ROOT}/modules/ipcheck.sh"
source "${SENTRYCLI_ROOT}/modules/hashcheck.sh"
source "${SENTRYCLI_ROOT}/modules/asnlookup.sh"
source "${SENTRYCLI_ROOT}/modules/portscan.sh"
source "${SENTRYCLI_ROOT}/modules/censys.sh"

VERSION="2.7"
CURRENT_MODULE=""
declare -A MODULE_OPTS

cleanup() {
    spinner_stop 2>/dev/null || true
    log_session_end "MAIN"
}

trap cleanup EXIT INT TERM

print_banner

# ── Module Registry ─────────────────────────────────────────────────────────
declare -A MODULE_MAP
MODULE_MAP[1]="incident"
MODULE_MAP[2]="recon"
MODULE_MAP[3]="log"
MODULE_MAP[4]="ipcheck"
MODULE_MAP[5]="hashcheck"
MODULE_MAP[6]="asnlookup"
MODULE_MAP[7]="portscan"
MODULE_MAP[8]="censys"

declare -A MODULE_NAMES
MODULE_NAMES[incident]="Incident Response"
MODULE_NAMES[recon]="Reconnaissance"
MODULE_NAMES[log]="Log Intelligence"
MODULE_NAMES[ipcheck]="IP Threat Intelligence"
MODULE_NAMES[hashcheck]="Hash Threat Intelligence"
MODULE_NAMES[asnlookup]="ASN Lookup"
MODULE_NAMES[portscan]="Advanced Port Scanner"
MODULE_NAMES[censys]="Censys Reconnaissance"

# ── Professional Modules List ───────────────────────────────────────────────
show_modules() {
    echo ""
    echo -e "${BOLD}${WHITE}Available Modules${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────────${RESET}"
    echo ""

    echo -e "${WHITE}Network & Infrastructure${RESET}"
    echo -e "${DIM}────────────────────────────────────────────${RESET}"
    echo -e " ${CYAN}1.${RESET}  ${WHITE}Incident Response${RESET}          ${DIM}Live forensic triage${RESET}"
    echo -e " ${CYAN}2.${RESET}  ${WHITE}Reconnaissance${RESET}             ${DIM}DNS, WHOIS, subdomains${RESET}"
    echo -e " ${CYAN}6.${RESET}  ${WHITE}ASN Lookup${RESET}                  ${DIM}BGP & ASN intelligence${RESET}"
    echo -e " ${CYAN}7.${RESET}  ${WHITE}Advanced Port Scanner${RESET}      ${DIM}Service & version detection${RESET}"
    echo ""

    echo -e "${WHITE}Security & Threat Intelligence${RESET}"
    echo -e "${DIM}────────────────────────────────────────────${RESET}"
    echo -e " ${CYAN}3.${RESET}  ${WHITE}Log Intelligence${RESET}           ${DIM}Brute-force & anomaly detection${RESET}"
    echo -e " ${CYAN}4.${RESET}  ${WHITE}IP Threat Intelligence${RESET}     ${DIM}AbuseIPDB + GeoIP${RESET}"
    echo -e " ${CYAN}5.${RESET}  ${WHITE}Hash Threat Intelligence${RESET}   ${DIM}VirusTotal deep analysis${RESET}"
    echo -e " ${CYAN}8.${RESET}  ${WHITE}Censys Reconnaissance${RESET}      ${DIM}Internet-wide exposure search${RESET}"
    echo ""

    echo -e "${DIM}Tip:${RESET} Use ${CYAN}use <number>${RESET} or ${CYAN}use <name>${RESET} | Type ${CYAN}modules${RESET} to see this list again"
    echo ""
}

# ── Module Help ─────────────────────────────────────────────────────────────
show_module_help() {
    case "$CURRENT_MODULE" in
        incident|ir)
            echo -e "${YELLOW}Incident Response${RESET}"
            echo -e "${DIM}Live system forensic triage and investigation.${RESET}"
            ;;
        recon)
            echo -e "${YELLOW}Reconnaissance${RESET}"
            echo -e "${DIM}DNS, WHOIS, subdomain enumeration and HTTP probing.${RESET}"
            print_kv " target" "Target domain or IP (required)"
            ;;
        log|logintel)
            echo -e "${YELLOW}Log Intelligence${RESET}"
            print_kv " log-file" "Path to log file (optional)"
            ;;
        ipcheck)
            echo -e "${YELLOW}IP Threat Intelligence${RESET}"
            print_kv " ip" "IPv4 address to analyze"
            ;;
        hashcheck)
            echo -e "${YELLOW}Hash Threat Intelligence${RESET}"
            print_kv " hash" "File hash (MD5/SHA1/SHA256/SHA512)"
            ;;
        asnlookup)
            echo -e "${YELLOW}ASN Lookup${RESET}"
            print_kv " asn" "ASN number or IP address"
            ;;
        portscan)
            echo -e "${YELLOW}Advanced Port Scanner${RESET}"
            print_kv " target" "Target IP or domain"
            ;;
        censys)
            echo -e "${YELLOW}Censys Reconnaissance${RESET}"
            print_kv " query" "Search query (IP, domain, certificate, etc.)"
            ;;
        *)
            echo -e "${DIM}No detailed help available yet.${RESET}"
            ;;
    esac
}

# ── REPL Core ───────────────────────────────────────────────────────────────
start_repl() {
    print_info "Interactive REPL ready. Type 'modules' to list available modules."
    echo ""

    while true; do
        if [[ -n "$CURRENT_MODULE" ]]; then
            echo -ne "${CYAN}sentry(${CURRENT_MODULE})>${RESET} "
        else
            echo -ne "${CYAN}sentry>${RESET} "
        fi

        read -r cmd arg1 arg2 rest

        case "$cmd" in
            modules|list)
                show_modules
                ;;

            use)
                local mod_key=""
                if [[ "$arg1" =~ ^[0-9]+$ ]]; then
                    mod_key="${MODULE_MAP[$arg1]}"
                else
                    case "$arg1" in
                        incident|ir)          mod_key="incident" ;;
                        recon)                mod_key="recon" ;;
                        log|logintel)         mod_key="log" ;;
                        ipcheck|ip)           mod_key="ipcheck" ;;
                        hashcheck|hash)       mod_key="hashcheck" ;;
                        asnlookup|asn)        mod_key="asnlookup" ;;
                        portscan|port|scan)   mod_key="portscan" ;;
                        censys)               mod_key="censys" ;;
                    esac
                fi

                if [[ -n "$mod_key" && -n "${MODULE_NAMES[$mod_key]}" ]]; then
                    CURRENT_MODULE="$mod_key"
                    MODULE_OPTS=()
                    print_success "Module loaded: ${MODULE_NAMES[$mod_key]}"
                    echo -e "${DIM}Type 'opts' or 'helpmod' to view configuration${RESET}"
                else
                    print_warn "Invalid module. Type 'modules' to see list."
                fi
                ;;

            set)
                if [[ -n "$CURRENT_MODULE" && -n "$arg1" ]]; then
                    MODULE_OPTS["$arg1"]="${arg2}${rest:+ $rest}"
                    print_success "Configured: ${arg1} = ${MODULE_OPTS[$arg1]}"
                else
                    print_warn "Load a module first using 'use <number or name>'"
                fi
                ;;

            opts|options|"show options")
                if [[ -n "$CURRENT_MODULE" ]]; then
                    echo -e "${YELLOW}Current Configuration — ${MODULE_NAMES[$CURRENT_MODULE]}${RESET}"
                    echo -e "${DIM}────────────────────────────────────────${RESET}"
                    if [[ ${#MODULE_OPTS[@]} -eq 0 ]]; then
                        echo -e "  ${DIM}No options configured yet${RESET}"
                    else
                        for k in "${!MODULE_OPTS[@]}"; do
                            printf "  ${GREEN}%-12s${RESET} = %s\n" "$k" "${MODULE_OPTS[$k]}"
                        done
                    fi
                    echo ""
                    show_module_help
                else
                    print_warn "No module loaded. Use 'use <number>' first."
                fi
                ;;

            run)
                if [[ -z "$CURRENT_MODULE" ]]; then
                    print_warn "No module loaded. Use 'use <number or name>' first."
                    continue
                fi

                print_section "Running ${MODULE_NAMES[$CURRENT_MODULE]}"

                case "$CURRENT_MODULE" in
                    recon)      run_recon "${MODULE_OPTS[target]:-}" ;;
                    ipcheck)    run_ipcheck --ip "${MODULE_OPTS[ip]:-}" ;;
                    hashcheck)  run_hashcheck --hash "${MODULE_OPTS[hash]:-}" ;;
                    asnlookup)  run_asnlookup "${MODULE_OPTS[asn]:-${MODULE_OPTS[target]:-}}" ;;
                    portscan)   run_portscan "${MODULE_OPTS[target]:-}" ;;
                    censys)     run_censys --query "${MODULE_OPTS[query]:-}" ;;
                    log|logintel) run_logintel "${MODULE_OPTS[log-file]:-}" ;;
                    incident|ir)  run_incident ;;
                    *) print_alert "Handler not implemented for this module yet." ;;
                esac

                echo ""
                print_success "Execution completed."
                echo -e "${DIM}Returned to main prompt.${RESET}"
                ;;

            runall)
                print_section "FULL SECURITY SWEEP"
                run_all_modules
                ;;

            correlate)
                print_section "SIEM CORRELATION ENGINE"
                run_correlation
                ;;

            helpmod|help\ module)
                show_module_help
                ;;

            help)
                show_help
                ;;

            clear|cls)
                clear
                print_banner
                ;;

            back|unload)
                CURRENT_MODULE=""
                MODULE_OPTS=()
                print_info "Module unloaded."
                ;;

            exit|quit)
                print_info "Exiting SentryCLI. Goodbye."
                exit 0
                ;;

            "") ;;
            *)
                print_warn "Unknown command. Type 'modules' or 'help'."
                ;;
        esac
    done
}

# ── General Help ────────────────────────────────────────────────────────────
show_help() {
    echo -e "${BOLD}${WHITE}SentryCLI v${VERSION}${RESET}"
    echo -e "${DIM}Modular Security Operations & Penetration Testing Toolkit${RESET}"
    echo ""
    echo -e "${BOLD}${WHITE}Core Commands${RESET}"
    print_kv " modules"           "Show all available modules"
    print_kv " use <num/name>"    "Load a module"
    print_kv " set <key> <value>" "Set module option"
    print_kv " opts"              "Show current configuration"
    print_kv " run"               "Execute current module"
    print_kv " runall"            "Run full security sweep"
    print_kv " help"              "Show this help"
    print_kv " exit"              "Exit SentryCLI"
    echo ""
}

# ── Legacy Functions (kept for compatibility) ───────────────────────────────
show_menu() {
    echo -e " ${BOLD}${WHITE}MAIN MENU${RESET}"
    echo ""
    echo -e " ${CYAN}[1]${RESET} Incident Response"
    echo -e " ${CYAN}[2]${RESET} Reconnaissance"
    echo -e " ${CYAN}[3]${RESET} Log Intelligence"
    echo -e " ${CYAN}[4]${RESET} IP Threat Intelligence"
    echo -e " ${CYAN}[5]${RESET} Hash Threat Intelligence"
    echo -e " ${CYAN}[6]${RESET} ASN Lookup"
    echo -e " ${CYAN}[7]${RESET} Advanced Port Scanner"
    echo -e " ${CYAN}[8]${RESET} Censys Reconnaissance"
    echo -e " ${CYAN}[0]${RESET} Exit"
    echo ""
    echo -ne " ${CYAN}${BOLD}Select option: ${RESET}"
    read -r choice
    # ... (You can keep your old menu logic here if needed)
}

run_all_modules() {
    print_section "FULL SECURITY SWEEP"
    run_logintel
    run_incident
    run_recon
    # Add others as needed
    log_success "MAIN" "Full sweep completed"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --menu) show_menu; exit 0 ;;
            --version|-v) echo "SentryCLI v${VERSION}"; exit 0 ;;
            --help|-h) show_help; exit 0 ;;
            *) print_warn "Unknown argument. Starting REPL..." ;;
        esac
        shift
    done
    start_repl
}

# ── Entry Point ─────────────────────────────────────────────────────────────
main() {
    mkdir -p "${SENTRYCLI_ROOT}/reports"
    chmod 600 "${SENTRYCLI_ROOT}/config/api_keys.conf" 2>/dev/null || true
    log_session_start "MAIN"
    log_info "MAIN" "SentryCLI v${VERSION} started"
    parse_args "$@"
}

main "$@"
