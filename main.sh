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
source "${SENTRYCLI_ROOT}/modules/webheaders.sh"
source "${SENTRYCLI_ROOT}/modules/cmsdetect.sh"
source "${SENTRYCLI_ROOT}/modules/techstack.sh"
source "${SENTRYCLI_ROOT}/modules/dirbrute.sh"
source "${SENTRYCLI_ROOT}/modules/robotsanalyzer.sh"
source "${SENTRYCLI_ROOT}/modules/wafdetect.sh"
source "${SENTRYCLI_ROOT}/modules/sslanalyze.sh"
source "${SENTRYCLI_ROOT}/modules/jsvulnscan.sh"
source "${SENTRYCLI_ROOT}/modules/subtakeover.sh"
source "${SENTRYCLI_ROOT}/modules/apidiscover.sh"
source "${SENTRYCLI_ROOT}/modules/wayback.sh"
source "${SENTRYCLI_ROOT}/modules/corscheck.sh"
source "${SENTRYCLI_ROOT}/modules/hostinfo.sh"
source "${SENTRYCLI_ROOT}/modules/reputation.sh"
source "${SENTRYCLI_ROOT}/modules/emailbreach.sh"

VERSION="2.7"
CURRENT_MODULE=""
declare -A MODULE_OPTS

# ── Helper: safely clear MODULE_OPTS ────────────────────────────────────────
# THREE patterns that all fail under set -euo pipefail:
#   MODULE_OPTS=()          → "cannot convert associative to indexed array"
#   unset MODULE_OPTS       → then any ${MODULE_OPTS[*]} = "unbound variable"
#   unset + declare -gA     → declare -g inside a function doesn't propagate
#                              reliably in all bash versions, leaving it unbound
#
# CORRECT fix: never unset — just delete all existing keys by iterating.
# The array stays declared so set -u never triggers on any subsequent access.
_reset_opts() {
    local key
    for key in "${!MODULE_OPTS[@]}"; do
        unset "MODULE_OPTS[$key]"
    done 2>/dev/null || true
}

cleanup() {
    spinner_stop 2>/dev/null || true
    log_session_end "MAIN"
}

trap cleanup EXIT INT TERM

print_banner

# ── Module Registry ──────────────────────────────────────────────────────────
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
MODULE_MAP[21]="hostinfo"
MODULE_MAP[22]="reputation"
MODULE_MAP[23]="emailbreach"

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
MODULE_NAMES[robotsanalyzer]="Robots.txt & Sensitive Files Analyzer"
MODULE_NAMES[wafdetect]="WAF Detector"
MODULE_NAMES[sslanalyze]="SSL/TLS Security Analyzer"
MODULE_NAMES[jsvulnscan]="JS Library Vulnerability Scanner"
MODULE_NAMES[subtakeover]="Subdomain Takeover Checker"
MODULE_NAMES[apidiscover]="API Endpoint Discovery"
MODULE_NAMES[wayback]="Wayback Machine Analyzer"
MODULE_NAMES[corscheck]="CORS Misconfiguration Checker"
MODULE_NAMES[hostinfo]="Server Location & Hosting Detector"
MODULE_NAMES[reputation]="Domain Reputation & Blacklist Checker"
MODULE_NAMES[emailbreach]="Email Harvester & Breach Checker"

# ── Module List ──────────────────────────────────────────────────────────────
show_modules() {
    echo ""
    echo -e "${BOLD}${WHITE}Available Modules${RESET}"
    echo -e "${CYAN}$(printf '%.0s─' {1..80})${RESET}"
    echo ""

    echo -e "${BOLD}${WHITE}  Network & Infrastructure${RESET}"
    echo -e "${DIM}  $(printf '%.0s─' {1..60})${RESET}"
    echo -e "  ${CYAN} 1.${RESET}  ${WHITE}Incident Response${RESET}               ${DIM}Live forensic triage${RESET}"
    echo -e "  ${CYAN} 2.${RESET}  ${WHITE}Reconnaissance${RESET}                  ${DIM}DNS, WHOIS, subdomains${RESET}"
    echo -e "  ${CYAN} 6.${RESET}  ${WHITE}ASN Lookup${RESET}                      ${DIM}BGP & ASN intelligence${RESET}"
    echo -e "  ${CYAN} 7.${RESET}  ${WHITE}Advanced Port Scanner${RESET}           ${DIM}Service & version detection${RESET}"
    echo -e "  ${CYAN}21.${RESET}  ${WHITE}Server Location & Hosting${RESET}       ${DIM}GeoIP, ISP, Cloud Provider${RESET}"
    echo ""

    echo -e "${BOLD}${WHITE}  Security & Threat Intelligence${RESET}"
    echo -e "${DIM}  $(printf '%.0s─' {1..60})${RESET}"
    echo -e "  ${CYAN} 3.${RESET}  ${WHITE}Log Intelligence${RESET}                ${DIM}Brute-force & anomaly detection${RESET}"
    echo -e "  ${CYAN} 4.${RESET}  ${WHITE}IP Threat Intelligence${RESET}          ${DIM}AbuseIPDB + GeoIP${RESET}"
    echo -e "  ${CYAN} 5.${RESET}  ${WHITE}Hash Threat Intelligence${RESET}         ${DIM}VirusTotal deep analysis${RESET}"
    echo -e "  ${CYAN} 8.${RESET}  ${WHITE}Censys Reconnaissance${RESET}           ${DIM}Internet-wide exposure search${RESET}"
    echo -e "  ${CYAN}22.${RESET}  ${WHITE}Domain Reputation Checker${RESET}       ${DIM}Blacklist & threat intel${RESET}"
    echo -e "  ${CYAN}23.${RESET}  ${WHITE}Email Harvester & Breach Check${RESET}  ${DIM}Email harvest & breach lookup${RESET}"
    echo ""

    echo -e "${BOLD}${WHITE}  Web Application Analysis${RESET}"
    echo -e "${DIM}  $(printf '%.0s─' {1..60})${RESET}"
    echo -e "  ${CYAN} 9.${RESET}  ${WHITE}HTTP Security Headers${RESET}           ${DIM}Security headers analysis${RESET}"
    echo -e "  ${CYAN}10.${RESET}  ${WHITE}CMS Detection${RESET}                   ${DIM}WordPress, Joomla, Drupal etc.${RESET}"
    echo -e "  ${CYAN}11.${RESET}  ${WHITE}Technology Stack Detector${RESET}       ${DIM}Server, frameworks, CMS${RESET}"
    echo -e "  ${CYAN}12.${RESET}  ${WHITE}Directory Brute Forcer${RESET}          ${DIM}Hidden directories & files${RESET}"
    echo -e "  ${CYAN}13.${RESET}  ${WHITE}Robots.txt Analyzer${RESET}             ${DIM}Sensitive paths & files${RESET}"
    echo -e "  ${CYAN}14.${RESET}  ${WHITE}WAF Detector${RESET}                    ${DIM}Cloudflare, Akamai, Imperva etc.${RESET}"
    echo -e "  ${CYAN}15.${RESET}  ${WHITE}SSL/TLS Security Analyzer${RESET}       ${DIM}Certificate & cipher analysis${RESET}"
    echo -e "  ${CYAN}16.${RESET}  ${WHITE}JS Library Vulnerability Scanner${RESET} ${DIM}Outdated JS libraries${RESET}"
    echo -e "  ${CYAN}17.${RESET}  ${WHITE}Subdomain Takeover Checker${RESET}      ${DIM}Dangling DNS records${RESET}"
    echo -e "  ${CYAN}18.${RESET}  ${WHITE}API Endpoint Discovery${RESET}          ${DIM}Swagger, GraphQL, REST APIs${RESET}"
    echo -e "  ${CYAN}19.${RESET}  ${WHITE}Wayback Machine Analyzer${RESET}        ${DIM}Archive exposure check${RESET}"
    echo -e "  ${CYAN}20.${RESET}  ${WHITE}CORS Misconfiguration Checker${RESET}   ${DIM}Dangerous CORS settings${RESET}"
    echo ""
    echo -e "  ${DIM}Tip: ${RESET}${CYAN}use <number>${RESET} or ${CYAN}use <name>${RESET} to load a module | ${CYAN}modules${RESET} to see this list"
    echo ""
}

# ── Module Help ──────────────────────────────────────────────────────────────
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
            echo -e "${DIM}  AbuseIPDB confidence score, GeoIP, proxy/VPN/Tor detection.${RESET}"
            echo ""
            print_kv " ip" "IPv4 address to analyze (e.g. 1.1.1.1)"
            echo ""
            local _conf="${SENTRYCLI_ROOT}/config/api_keys.conf"
            [[ -f "$_conf" ]] && source "$_conf" 2>/dev/null || true
            echo -e "  ${BOLD}${WHITE}API Key Status${RESET}"
            echo -e "  ${DIM}$(printf '%.0s─' {1..44})${RESET}"
            if [[ -n "${ABUSEIPDB_API_KEY:-}" ]]; then
                printf "  ${GREEN}✔${RESET}  %-22s ${GREEN}Configured${RESET}\n" "AbuseIPDB"
            else
                printf "  ${RED}✘${RESET}  %-22s ${RED}Not set${RESET}  ${DIM}(required for threat intel)${RESET}\n" "AbuseIPDB"
            fi
            echo ""
            echo -e "${DIM}  Example: set ip 8.8.8.8 | run${RESET}"
            ;;
        hashcheck)
            echo -e "${YELLOW}Hash Threat Intelligence${RESET}"
            echo -e "${DIM}  VirusTotal deep analysis — malware, vendor detections, file info.${RESET}"
            echo ""
            print_kv " hash" "File hash — MD5 / SHA1 / SHA256 / SHA512"
            echo ""
            local _conf="${SENTRYCLI_ROOT}/config/api_keys.conf"
            [[ -f "$_conf" ]] && source "$_conf" 2>/dev/null || true
            echo -e "  ${BOLD}${WHITE}API Key Status${RESET}"
            echo -e "  ${DIM}$(printf '%.0s─' {1..44})${RESET}"
            if [[ -n "${VIRUSTOTAL_API_KEY:-}" ]]; then
                printf "  ${GREEN}✔${RESET}  %-22s ${GREEN}Configured${RESET}\n" "VirusTotal"
            else
                printf "  ${RED}✘${RESET}  %-22s ${RED}Not set${RESET}  ${DIM}(required)${RESET}\n" "VirusTotal"
            fi
            echo ""
            echo -e "${DIM}  Example: set hash d41d8cd98f00b204e9800998ecf8427e | run${RESET}"
            ;;
        asnlookup)
            echo -e "${YELLOW}ASN Lookup${RESET}"
            print_kv " asn" "ASN number or IP address"
            ;;
        portscan)
            echo -e "${YELLOW}Advanced Port Scanner${RESET}"
            echo -e "${DIM}Service, version, and OS detection via nmap.${RESET}"
            print_kv " target" "Target IP or domain (required)"
            print_kv " mode"   "Scan mode: advanced | quick | full | stealth"
            echo ""
            echo -e "  ${WHITE}Scan Modes:${RESET}"
            echo -e "   ${CYAN}advanced${RESET}  → Top 1000 ports + Service + OS detection ${DIM}(default)${RESET}"
            echo -e "   ${CYAN}quick${RESET}     → Top 200 ports, faster scan"
            echo -e "   ${CYAN}full${RESET}      → All 65,535 ports (slow)"
            echo -e "   ${CYAN}stealth${RESET}   → Low-noise scan with host randomization"
            echo ""
            echo -e "${DIM}  Example: set target 192.168.1.1 | set mode quick | run${RESET}"
            ;;
        censys)
            echo -e "${YELLOW}Censys Reconnaissance${RESET}"
            echo -e "${DIM}  Internet-wide exposure search — banners, certs, open ports.${RESET}"
            echo ""
            print_kv " query" "IP, domain, or certificate query"
            echo ""
            local _conf="${SENTRYCLI_ROOT}/config/api_keys.conf"
            [[ -f "$_conf" ]] && source "$_conf" 2>/dev/null || true
            echo -e "  ${BOLD}${WHITE}API Key Status${RESET}"
            echo -e "  ${DIM}$(printf '%.0s─' {1..44})${RESET}"
            if [[ -n "${CENSYS_API_KEY:-}" ]]; then
                printf "  ${GREEN}✔${RESET}  %-22s ${GREEN}Configured${RESET}\n" "Censys"
            else
                printf "  ${RED}✘${RESET}  %-22s ${RED}Not set${RESET}  ${DIM}(required)${RESET}\n" "Censys"
            fi
            echo ""
            echo -e "${DIM}  Example: set query 8.8.8.8 | run${RESET}"
            ;;
        webheaders)
            echo -e "${YELLOW}HTTP Security Headers Analyzer${RESET}"
            echo -e "${DIM}Checks CSP, HSTS, X-Frame-Options, XCTO, Referrer-Policy etc.${RESET}"
            print_kv " target" "Domain or URL (e.g. example.com)"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        cmsdetect)
            echo -e "${YELLOW}CMS Detection${RESET}"
            echo -e "${DIM}Detects WordPress, Joomla, Drupal, Shopify, Ghost etc.${RESET}"
            print_kv " target" "Domain or URL (required)"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        techstack)
            echo -e "${YELLOW}Technology Stack Detector${RESET}"
            echo -e "${DIM}Identifies server, frameworks, CDN, JS libs from HTTP responses.${RESET}"
            print_kv " target" "Domain or URL (required)"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        dirbrute)
            echo -e "${YELLOW}Directory Brute Forcer${RESET}"
            echo -e "${DIM}Discovers hidden directories and files on web servers.${RESET}"
            print_kv " target"   "Domain or URL (required)"
            print_kv " wordlist" "Path to custom wordlist (optional)"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        robotsanalyzer)
            echo -e "${YELLOW}Robots.txt & Sensitive Files Analyzer${RESET}"
            echo -e "${DIM}Fetches and analyzes robots.txt for exposed paths.${RESET}"
            print_kv " target" "Domain or URL (required)"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        wafdetect)
            echo -e "${YELLOW}WAF Detector${RESET}"
            echo -e "${DIM}Multi-vector detection: headers, cookies, active probes, DNS.${RESET}"
            print_kv " target" "Domain or URL (e.g. example.com)"
            echo ""
            echo -e "  ${WHITE}Detects:${RESET} Cloudflare, Akamai, Imperva, AWS WAF, Sucuri,"
            echo -e "           F5 BIG-IP, ModSecurity, Fastly, Azure Front Door,"
            echo -e "           DataDome, PerimeterX, Wordfence, Barracuda, FortiWeb"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        sslanalyze)
            echo -e "${YELLOW}SSL/TLS Security Analyzer${RESET}"
            echo -e "${DIM}Certificate details, protocol probes, cipher analysis, vuln checks.${RESET}"
            print_kv " target" "Domain (e.g. example.com)"
            echo ""
            echo -e "  ${WHITE}Checks:${RESET} Issuer, expiry, SANs, TLS 1.0/1.1/1.2/1.3 support,"
            echo -e "          cipher suite, HSTS, POODLE, BEAST, SWEET32, FREAK, RC4"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        jsvulnscan)
            echo -e "${YELLOW}JS Library Vulnerability Scanner${RESET}"
            echo -e "${DIM}Detects outdated JS libraries with known CVEs.${RESET}"
            print_kv " target" "Domain or URL"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        subtakeover)
            echo -e "${YELLOW}Subdomain Takeover Checker${RESET}"
            echo -e "${DIM}Finds dangling DNS records pointing to unclaimed services.${RESET}"
            print_kv " target" "Domain (e.g. example.com)"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        apidiscover)
            echo -e "${YELLOW}API Endpoint Discovery${RESET}"
            echo -e "${DIM}Discovers API endpoints, Swagger UI, GraphQL, REST APIs.${RESET}"
            print_kv " target" "Domain or URL"
            echo ""
            echo -e "  ${WHITE}Scans:${RESET} /api /api/v1 /api/v2 /graphql /swagger"
            echo -e "          /openapi.json /admin/api /internal /backend"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        wayback)
            echo -e "${YELLOW}Wayback Machine Analyzer${RESET}"
            echo -e "${DIM}Checks historical archives for exposed sensitive files.${RESET}"
            print_kv " target" "Domain (e.g. example.com)"
            echo ""
            echo -e "  ${WHITE}Looks for:${RESET} .env, wp-config.php, backup files,"
            echo -e "             admin panels, debug files, old configs"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        corscheck)
            echo -e "${YELLOW}CORS Misconfiguration Checker${RESET}"
            echo -e "${DIM}Detects dangerous CORS settings that allow cross-origin attacks.${RESET}"
            print_kv " target" "Domain or URL"
            echo ""
            echo -e "  ${WHITE}Checks:${RESET} Wildcard origin + credentials, origin reflection,"
            echo -e "          null origin, overly permissive ACAO header"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        hostinfo)
            echo -e "${YELLOW}Server Location & Hosting Detector${RESET}"
            echo -e "${DIM}Detects city, country, ISP, hosting provider and cloud platform.${RESET}"
            print_kv " target" "Domain or IP address"
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        reputation)
            echo -e "${YELLOW}Domain Reputation & Blacklist Checker${RESET}"
            echo -e "${DIM}  Checks domain/IP against VirusTotal, AbuseIPDB, Spamhaus and DNS blacklists.${RESET}"
            echo ""
            print_kv " target" "Domain or IP address (e.g. example.com)"
            echo ""
            local _conf="${SENTRYCLI_ROOT}/config/api_keys.conf"
            [[ -f "$_conf" ]] && source "$_conf" 2>/dev/null || true
            echo -e "  ${BOLD}${WHITE}API Key Status${RESET}"
            echo -e "  ${DIM}$(printf '%.0s─' {1..44})${RESET}"
            _key_status() {
                local label="$1" val="$2"
                if [[ -n "$val" ]]; then
                    printf "  ${GREEN}✔${RESET}  %-22s ${GREEN}Configured${RESET}\n" "$label"
                else
                    printf "  ${RED}✘${RESET}  %-22s ${RED}Not set${RESET}  ${DIM}(optional)${RESET}\n" "$label"
                fi
            }
            _key_status "VirusTotal"  "${VIRUSTOTAL_API_KEY:-}"
            _key_status "AbuseIPDB"   "${ABUSEIPDB_API_KEY:-}"
            _key_status "Censys"      "${CENSYS_API_KEY:-}"
            _key_status "Shodan"      "${SHODAN_API_KEY:-}"
            echo ""
            if [[ ! -f "$_conf" ]]; then
                echo -e "  ${YELLOW}  ⚠${RESET}  ${DIM}Config not found:${RESET} ${CYAN}config/api_keys.conf${RESET}"
                echo -e "     ${DIM}Create it and add keys to enable threat intel lookups.${RESET}"
            else
                echo -e "  ${DIM}  Keys loaded from:${RESET} ${CYAN}config/api_keys.conf${RESET}"
            fi
            echo ""
            echo -e "${DIM}  Example: set target example.com | run${RESET}"
            ;;
        emailbreach)
            echo -e "${YELLOW}Email Harvester & Breach Check${RESET}"
            echo -e "${DIM}Harvests common emails and checks them against known data breaches.${RESET}"
            echo ""
            echo -e "${WHITE}Options:${RESET}"
            print_kv " target" "Domain to harvest emails from (required)"
            echo ""
            echo -e "${WHITE}Examples:${RESET}"
            echo -e "   ${CYAN}set target example.com${RESET}"
            echo -e "   ${CYAN}set target company.com${RESET}"
            ;;
        *)
            echo -e "${DIM}No detailed help available for this module.${RESET}"
            ;;
    esac
}

# ── REPL Core ────────────────────────────────────────────────────────────────
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
                    mod_key="${MODULE_MAP[$arg1]:-}"
                else
                    case "$arg1" in
                        incident|ir)                      mod_key="incident" ;;
                        recon)                            mod_key="recon" ;;
                        log|logintel)                     mod_key="log" ;;
                        ipcheck|ip)                       mod_key="ipcheck" ;;
                        hashcheck|hash)                   mod_key="hashcheck" ;;
                        asnlookup|asn)                    mod_key="asnlookup" ;;
                        portscan|port|scan)               mod_key="portscan" ;;
                        censys)                           mod_key="censys" ;;
                        webheaders|web|headers)           mod_key="webheaders" ;;
                        cmsdetect|cms)                    mod_key="cmsdetect" ;;
                        techstack|tech|stack)             mod_key="techstack" ;;
                        dirbrute|dir|brute|dirbuster)     mod_key="dirbrute" ;;
                        robotsanalyzer|robots|robots.txt) mod_key="robotsanalyzer" ;;
                        wafdetect|waf)                    mod_key="wafdetect" ;;
                        sslanalyze|ssl|tls)               mod_key="sslanalyze" ;;
                        jsvulnscan|js|jsvuln)             mod_key="jsvulnscan" ;;
                        subtakeover|sub|takeover)         mod_key="subtakeover" ;;
                        apidiscover|api|apis)             mod_key="apidiscover" ;;
                        wayback|archive)                  mod_key="wayback" ;;
                        corscheck|cors)                   mod_key="corscheck" ;;
                        hostinfo|host|geo)                mod_key="hostinfo" ;;
                        reputation|reput|rep)             mod_key="reputation" ;;
                        emailbreach|breach|email)         mod_key="emailbreach" ;;  
                        *)                                mod_key="" ;;
                    esac
                fi

                if [[ -n "$mod_key" && -n "${MODULE_NAMES[$mod_key]:-}" ]]; then
                    CURRENT_MODULE="$mod_key"
                    _reset_opts
                    print_success "Module loaded: ${MODULE_NAMES[$mod_key]}"
                    echo -e "${DIM}Type 'opts' or 'helpmod' to view options | 'run' to execute${RESET}"
                else
                    print_warn "Invalid module '${arg1}'. Type 'modules' to see the list."
                fi
                ;;

            set)
                if [[ -n "$CURRENT_MODULE" && -n "${arg1:-}" ]]; then
                    MODULE_OPTS["$arg1"]="${arg2:-}${rest:+ $rest}"
                    print_success "Set: ${arg1} = ${MODULE_OPTS[$arg1]}"
                else
                    print_warn "Load a module first: use <number or name>"
                fi
                ;;

            opts|options|"show options")
                if [[ -n "$CURRENT_MODULE" ]]; then
                    echo -e "${YELLOW}Configuration — ${MODULE_NAMES[$CURRENT_MODULE]}${RESET}"
                    echo -e "${DIM}$(printf '%.0s─' {1..40})${RESET}"
                    local _has_opts=0
                    for k in "${!MODULE_OPTS[@]}"; do
                        printf "  ${GREEN}%-14s${RESET} = %s\n" "$k" "${MODULE_OPTS[$k]}"
                        _has_opts=1
                    done
                    [[ $_has_opts -eq 0 ]] && echo -e "  ${DIM}No options set yet${RESET}"
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

                # All modules read MODULE_OPTS internally — called with no args.
                case "$CURRENT_MODULE" in
                    recon)          run_recon "${MODULE_OPTS[target]:-}" ;;
                    ipcheck)        run_ipcheck --ip "${MODULE_OPTS[ip]:-}" ;;
                    hashcheck)      run_hashcheck --hash "${MODULE_OPTS[hash]:-}" ;;
                    asnlookup)      run_asnlookup "${MODULE_OPTS[asn]:-${MODULE_OPTS[target]:-}}" ;;
                    portscan)       run_portscan ;;
                    censys)         run_censys --query "${MODULE_OPTS[query]:-}" ;;
                    log|logintel)   run_logintel "${MODULE_OPTS[log-file]:-}" ;;
                    incident|ir)    run_incident ;;
                    webheaders)     run_webheaders ;;
                    cmsdetect)      run_cmsdetect ;;
                    techstack)      run_techstack ;;
                    dirbrute)       run_dirbrute ;;
                    robotsanalyzer) run_robotsanalyzer ;;
                    wafdetect)      run_wafdetect ;;
                    sslanalyze)     run_sslanalyze ;;
                    jsvulnscan)     run_jsvulnscan ;;
                    subtakeover)    run_subtakeover ;;
                    apidiscover)    run_apidiscover ;;
                    wayback)        run_wayback ;;
                    corscheck)      run_corscheck ;;
                    hostinfo)       run_hostinfo ;;
                    reputation)     run_reputation ;;
                    emailbreach)    run_emailbreach ;;  
                    *) print_alert "No run handler for module: ${CURRENT_MODULE}" ;;
                esac

                echo ""
                print_success "Module execution completed."
                echo -e "${DIM}Back at main prompt. Type 'modules' or 'use <module>'.${RESET}"
                ;;

            runall)
                print_section "FULL SECURITY SWEEP"
                run_all_modules
                ;;

            helpmod|"help module")
                if [[ -n "$CURRENT_MODULE" ]]; then
                    show_module_help
                else
                    print_warn "No module loaded. Use 'use <number>' first."
                fi
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
                _reset_opts
                print_info "Module unloaded."
                ;;

            exit|quit|q)
                print_info "Exiting SentryCLI. Goodbye."
                exit 0
                ;;

            "")
                # Empty input — do nothing
                ;;

            *)
                print_warn "Unknown command '${cmd}'. Type 'help' or 'modules'."
                ;;
        esac
    done
}

# ── General Help ─────────────────────────────────────────────────────────────
show_help() {
    echo ""
    echo -e "${BOLD}${WHITE}SentryCLI v${VERSION}${RESET}  ${DIM}— Modular Security Operations Toolkit${RESET}"
    echo -e "${CYAN}$(printf '%.0s─' {1..55})${RESET}"
    echo ""
    echo -e "${BOLD}${WHITE}REPL Commands${RESET}"
    print_kv " modules"            "List all available modules"
    print_kv " use <num|name>"     "Load a module (e.g. use 9 | use ssl)"
    print_kv " set <key> <value>"  "Set a module option (e.g. set target google.com)"
    print_kv " opts"               "Show current module options + help"
    print_kv " run"                "Execute the loaded module"
    print_kv " helpmod"            "Show detailed help for loaded module"
    print_kv " back"               "Unload current module"
    print_kv " clear"              "Clear terminal and show banner"
    print_kv " runall"             "Run full security sweep"
    print_kv " help"               "Show this help"
    print_kv " exit"               "Exit SentryCLI"
    echo ""
    echo -e "${DIM}  Quick example:${RESET}"
    echo -e "   ${CYAN}use 23${RESET}               → Load Email Harvester"
    echo -e "   ${CYAN}set target example.com${RESET} → Set the target"
    echo -e "   ${CYAN}run${RESET}                  → Execute scan"
    echo ""
}

# ── Full Sweep ────────────────────────────────────────────────────────────────
run_all_modules() {
    local sweep_target="${MODULE_OPTS[target]:-}"
    if [[ -z "$sweep_target" ]]; then
        echo -ne "${CYAN}Enter target for full sweep (domain or IP): ${RESET}"
        read -r sweep_target
    fi
    [[ -z "$sweep_target" ]] && { print_alert "No target. Sweep aborted."; return 1; }

    print_info "Full sweep target: ${sweep_target}"
    echo ""

    run_recon    "$sweep_target"
    run_webheaders
    run_wafdetect
    run_sslanalyze
    run_cmsdetect
    run_techstack
    run_corscheck
    run_hostinfo

    log_success "MAIN" "Full security sweep completed for $sweep_target"
    print_success "Full sweep completed!"
}

# ── Argument Parser ───────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version|-v)
                echo "SentryCLI v${VERSION}"
                exit 0
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --menu)
                show_modules
                exit 0
                ;;
            *)
                print_warn "Unknown argument: $1. Starting REPL..."
                ;;
        esac
        shift
    done
    start_repl
}

# ── Entry Point ───────────────────────────────────────────────────────────────
main() {
    mkdir -p "${SENTRYCLI_ROOT}/reports"
    chmod 600 "${SENTRYCLI_ROOT}/config/api_keys.conf" 2>/dev/null || true
    log_session_start "MAIN"
    log_info "MAIN" "SentryCLI v${VERSION} started — PID:$$ USER:$(whoami)"
    parse_args "$@"
}

main "$@"
