#!/usr/bin/env bash
# =============================================================================
# SentryCLI — Modular Security Operations & Penetration Testing Toolkit
# main.sh — Professional Categorized REPL v2.8
# =============================================================================

set -euo pipefail

SENTRYCLI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SENTRYCLI_ROOT

# Source utilities
source "${SENTRYCLI_ROOT}/utils/colors.sh"
source "${SENTRYCLI_ROOT}/utils/logger.sh"

# ── Source All Modules ─────────────────────────────────────────────────────
source "${SENTRYCLI_ROOT}/modules/logintel.sh"
source "${SENTRYCLI_ROOT}/modules/recon.sh"
source "${SENTRYCLI_ROOT}/modules/incident.sh"
source "${SENTRYCLI_ROOT}/modules/ipcheck.sh"
source "${SENTRYCLI_ROOT}/modules/hashcheck.sh"
source "${SENTRYCLI_ROOT}/modules/asnlookup.sh"
source "${SENTRYCLI_ROOT}/modules/portscan.sh"
source "${SENTRYCLI_ROOT}/modules/censys.sh"
source "${SENTRYCLI_ROOT}/modules/webheaders.sh"
source "${SENTRYCLI_ROOT}/modules/cmsdetect.sh"
source "${SENTRYCLI_ROOT}/modules/techstack.sh"
source "${SENTRYCLI_ROOT}/modules/dirbrute.sh"
source "${SENTRYCLI_ROOT}/modules/robotsanalyzer.sh"

# New Modules (14-20)
source "${SENTRYCLI_ROOT}/modules/wafdetect.sh"
source "${SENTRYCLI_ROOT}/modules/sslanalyze.sh"
source "${SENTRYCLI_ROOT}/modules/jsvulnscan.sh"
source "${SENTRYCLI_ROOT}/modules/subtakeover.sh"
source "${SENTRYCLI_ROOT}/modules/apidiscover.sh"
source "${SENTRYCLI_ROOT}/modules/wayback.sh"
source "${SENTRYCLI_ROOT}/modules/corscheck.sh"

VERSION="2.8"
CURRENT_MODULE=""
declare -A MODULE_OPTS

cleanup() {
    spinner_stop 2>/dev/null || true
    log_session_end "MAIN"
}
trap cleanup EXIT INT TERM

print_banner

# ── Module Registry ────────────────────────────────────────────────────────
declare -A MODULE_MAP
MODULE_MAP[1]="incident"
MODULE_MAP[2]="recon"
MODULE_MAP[3]="log"
MODULE_MAP[4]="ipcheck"
MODULE_MAP[5]="hashcheck"
MODULE_MAP[6]="asnlookup"
MODULE_MAP[7]="portscan"
MODULE_MAP[8]="censys"
MODULE_MAP[9]="webheaders"
MODULE_MAP[10]="cmsdetect"
MODULE_MAP[11]="techstack"
MODULE_MAP[12]="dirbrute"
MODULE_MAP[13]="robotsanalyzer"
MODULE_MAP[14]="wafdetect"
MODULE_MAP[15]="sslanalyze"
MODULE_MAP[16]="jsvulnscan"
MODULE_MAP[17]="subtakeover"
MODULE_MAP[18]="apidiscover"
MODULE_MAP[19]="wayback"
MODULE_MAP[20]="corscheck"

declare -A MODULE_NAMES
MODULE_NAMES[incident]="Incident Response"
MODULE_NAMES[recon]="Reconnaissance"
MODULE_NAMES[log]="Log Intelligence"
MODULE_NAMES[ipcheck]="IP Threat Intelligence"
MODULE_NAMES[hashcheck]="Hash Threat Intelligence"
MODULE_NAMES[asnlookup]="ASN Lookup"
MODULE_NAMES[portscan]="Advanced Port Scanner"
MODULE_NAMES[censys]="Censys Reconnaissance"
MODULE_NAMES[webheaders]="HTTP Security Headers"
MODULE_NAMES[cmsdetect]="CMS Detection"
MODULE_NAMES[techstack]="Technology Stack Detector"
MODULE_NAMES[dirbrute]="Directory Brute Forcer"
MODULE_NAMES[robotsanalyzer]="Robots.txt Analyzer"
MODULE_NAMES[wafdetect]="WAF Detector"
MODULE_NAMES[sslanalyze]="SSL/TLS Security Analyzer"
MODULE_NAMES[jsvulnscan]="JS Library Vulnerability Scanner"
MODULE_NAMES[subtakeover]="Subdomain Takeover Checker"
MODULE_NAMES[apidiscover]="API Endpoint Discovery"
MODULE_NAMES[wayback]="Wayback Machine Analyzer"
MODULE_NAMES[corscheck]="CORS Misconfiguration Checker"

# ── Show Modules Menu ──────────────────────────────────────────────────────
show_modules() {
    echo ""
    echo -e "${BOLD}${WHITE}Available Modules${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────────${RESET}"
    echo ""

    echo -e "${WHITE}Network & Infrastructure${RESET}"
    echo -e "${DIM}────────────────────────────────────────────${RESET}"
    echo -e " ${CYAN}1.${RESET} ${WHITE}Incident Response${RESET}          ${DIM}Live forensic triage${RESET}"
    echo -e " ${CYAN}2.${RESET} ${WHITE}Reconnaissance${RESET}            ${DIM}DNS, WHOIS, subdomains${RESET}"
    echo -e " ${CYAN}6.${RESET} ${WHITE}ASN Lookup${RESET}                 ${DIM}BGP & ASN intelligence${RESET}"
    echo -e " ${CYAN}7.${RESET} ${WHITE}Advanced Port Scanner${RESET}     ${DIM}Service & version detection${RESET}"
    echo ""

    echo -e "${WHITE}Security & Threat Intelligence${RESET}"
    echo -e "${DIM}────────────────────────────────────────────${RESET}"
    echo -e " ${CYAN}3.${RESET} ${WHITE}Log Intelligence${RESET}          ${DIM}Brute-force & anomaly detection${RESET}"
    echo -e " ${CYAN}4.${RESET} ${WHITE}IP Threat Intelligence${RESET}     ${DIM}AbuseIPDB + GeoIP${RESET}"
    echo -e " ${CYAN}5.${RESET} ${WHITE}Hash Threat Intelligence${RESET}   ${DIM}VirusTotal deep analysis${RESET}"
    echo -e " ${CYAN}8.${RESET} ${WHITE}Censys Reconnaissance${RESET}     ${DIM}Internet-wide exposure search${RESET}"
    echo ""

    echo -e "${WHITE}Web Application Analysis${RESET}"
    echo -e "${DIM}────────────────────────────────────────────${RESET}"
    echo -e " ${CYAN}9.${RESET} ${WHITE}HTTP Security Headers${RESET}      ${DIM}Security headers analysis${RESET}"
    echo -e " ${CYAN}10.${RESET} ${WHITE}CMS Detection${RESET}             ${DIM}WordPress, Joomla, Drupal etc.${RESET}"
    echo -e " ${CYAN}11.${RESET} ${WHITE}Technology Stack Detector${RESET} ${DIM}Server, frameworks, CMS${RESET}"
    echo -e " ${CYAN}12.${RESET} ${WHITE}Directory Brute Forcer${RESET}    ${DIM}Hidden directories & files${RESET}"
    echo -e " ${CYAN}13.${RESET} ${WHITE}Robots.txt Analyzer${RESET}       ${DIM}Sensitive paths & files${RESET}"
    echo -e " ${CYAN}14.${RESET} ${WHITE}WAF Detector${RESET}              ${DIM}Cloudflare, Sucuri, ModSecurity${RESET}"
    echo -e " ${CYAN}15.${RESET} ${WHITE}SSL/TLS Security Analyzer${RESET} ${DIM}Certificate & cipher analysis${RESET}"
    echo -e " ${CYAN}16.${RESET} ${WHITE}JS Library Vulnerability Scanner${RESET} ${DIM}Outdated JS libs${RESET}"
    echo -e " ${CYAN}17.${RESET} ${WHITE}Subdomain Takeover Checker${RESET} ${DIM}Dangling DNS records${RESET}"
    echo -e " ${CYAN}18.${RESET} ${WHITE}API Endpoint Discovery${RESET}    ${DIM}Swagger, GraphQL, APIs${RESET}"
    echo -e " ${CYAN}19.${RESET} ${WHITE}Wayback Machine Analyzer${RESET}  ${DIM}Archive exposure check${RESET}"
    echo -e " ${CYAN}20.${RESET} ${WHITE}CORS Misconfiguration Checker${RESET} ${DIM}Dangerous CORS settings${RESET}"
    echo ""

    echo -e "${DIM}Tip:${RESET} Use ${CYAN}use <number>${RESET} or ${CYAN}use <name>${RESET} | Type ${CYAN}modules${RESET} to see this list again"
    echo ""
}

# ── REPL Core ──────────────────────────────────────────────────────────────
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
                        incident|ir) mod_key="incident" ;;
                        recon) mod_key="recon" ;;
                        log|logintel) mod_key="log" ;;
                        ipcheck|ip) mod_key="ipcheck" ;;
                        hashcheck|hash) mod_key="hashcheck" ;;
                        asnlookup|asn) mod_key="asnlookup" ;;
                        portscan|port|scan) mod_key="portscan" ;;
                        censys) mod_key="censys" ;;
                        webheaders) mod_key="webheaders" ;;
                        cmsdetect) mod_key="cmsdetect" ;;
                        techstack) mod_key="techstack" ;;
                        dirbrute) mod_key="dirbrute" ;;
                        robotsanalyzer) mod_key="robotsanalyzer" ;;
                        wafdetect) mod_key="wafdetect" ;;
                        sslanalyze|ssl) mod_key="sslanalyze" ;;
                        jsvulnscan|js) mod_key="jsvulnscan" ;;
                        subtakeover|sub) mod_key="subtakeover" ;;
                        apidiscover|api) mod_key="apidiscover" ;;
                        wayback) mod_key="wayback" ;;
                        corscheck|cors) mod_key="corscheck" ;;
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
                        echo -e " ${DIM}No options configured yet${RESET}"
                    else
                        for k in "${!MODULE_OPTS[@]}"; do
                            printf " ${GREEN}%-12s${RESET} = %s\n" "$k" "${MODULE_OPTS[$k]}"
                        done
                    fi
                    echo ""
                else
                    print_warn "No module loaded. Use 'use <number>' first."
                fi
                ;;
            run)
                if [[ -z "$CURRENT_MODULE" ]]; then
                    print_warn "No module loaded. Use 'use <number or name>' first."
                    continue
                fi

                case "$CURRENT_MODULE" in
                    webheaders)     run_webheaders "${MODULE_OPTS[target]:-}" ;;
                    cmsdetect)      run_cmsdetect "${MODULE_OPTS[target]:-}" ;;
                    techstack)      run_techstack "${MODULE_OPTS[target]:-}" ;;
                    dirbrute)       run_dirbrute "${MODULE_OPTS[target]:-}" ;;
                    robotsanalyzer) run_robotsanalyzer "${MODULE_OPTS[target]:-}" ;;
                    wafdetect)      run_wafdetect "${MODULE_OPTS[target]:-}" ;;
                    sslanalyze)     run_sslanalyze "${MODULE_OPTS[target]:-}" ;;
                    jsvulnscan)     run_jsvulnscan "${MODULE_OPTS[target]:-}" ;;
                    subtakeover)    run_subtakeover "${MODULE_OPTS[target]:-}" ;;
                    apidiscover)    run_apidiscover "${MODULE_OPTS[target]:-}" ;;
                    wayback)        run_wayback "${MODULE_OPTS[target]:-}" ;;
                    corscheck)      run_corscheck "${MODULE_OPTS[target]:-}" ;;
                    *) 
                        print_alert "Handler not implemented for module: ${CURRENT_MODULE}"
                        ;;
                esac
                ;;
            helpmod|help\ module)
                echo -e "${YELLOW}${MODULE_NAMES[$CURRENT_MODULE]:-Unknown Module}${RESET}"
                print_kv " target" "Domain or URL"
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

show_help() {
    echo -e "${BOLD}${WHITE}SentryCLI v${VERSION}${RESET}"
    echo -e "${DIM}Modular Security Operations & Penetration Testing Toolkit${RESET}"
    echo ""
    echo -e "${BOLD}${WHITE}Core Commands${RESET}"
    print_kv " modules" "Show all available modules"
    print_kv " use <num/name>" "Load a module"
    print_kv " set <key> <value>" "Set module option"
    print_kv " opts" "Show current configuration"
    print_kv " run" "Execute current module"
    print_kv " help" "Show this help"
    print_kv " exit" "Exit SentryCLI"
    echo ""
}

# ── Entry Point ────────────────────────────────────────────────────────────
main() {
    mkdir -p "${SENTRYCLI_ROOT}/reports"
    log_session_start "MAIN"
    log_info "MAIN" "SentryCLI v${VERSION} started"
    start_repl
}

main "$@"
