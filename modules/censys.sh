#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Censys Reconnaissance Module
# modules/censys.sh
# Professional OSINT & Exposure Analysis using Censys
# =============================================================================

# ── Module Entry Point ────────────────────────────────────────────────────────
run_censys() {
    print_section "8. CENSYS RECONNAISSANCE [CENSYS-8]"

    local query=""

    # Parse arguments / REPL support
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --query|--q)
                query="$2"
                shift 2
                ;;
            --clear)
                unset CENSYS_QUERY 2>/dev/null || true
                print_success "Censys query cleared"
                return 0
                ;;
            *)
                print_alert "Unknown option: $1"
                echo "Usage: --query <search term>"
                return 1
                ;;
        esac
    done

    # REPL set support
    if [[ -z "$query" && -n "${MODULE_OPTS[query]:-}" ]]; then
        query="${MODULE_OPTS[query]}"
    elif [[ -z "$query" && -n "${CENSYS_QUERY:-}" ]]; then
        query="${CENSYS_QUERY}"
        print_info "Using REPL-set query → ${query}"
    fi

    # Interactive input
    if [[ -z "$query" ]]; then
        echo -ne "${CYAN}Enter Censys Search Query (e.g., 8.8.8.8, microsoft.com, ssl.cert.subject.cn:example.com): ${RESET}"
        read -r query
    fi

    [[ -z "$query" ]] && { print_alert "No query provided."; return 1; }

    # Load config
    local conf_file="${SENTRYCLI_ROOT}/config/api_keys.conf"
    [[ -f "$conf_file" ]] && source "$conf_file" || print_warn "Config file not found"

    local report
    report=$(report_init "censys")

    print_subsection "Censys Reconnaissance → ${query}"
    _censys_analyze "$query" "$report"

    report_finalize "$report"
    log_success "CENSYS" "Reconnaissance completed successfully"

    echo ""
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
}

# ── Helpers ───────────────────────────────────────────────────────────────────
_censys_verify_api_key() {
    if [[ -z "${CENSYS_API_ID:-}" || -z "${CENSYS_API_SECRET:-}" ]]; then
        print_warn " [Censys] API credentials not configured (using public search fallback)"
        return 1
    fi
    print_success " [Censys] API credentials loaded"
    return 0
}

_censys_curl_request() {
    local label="$1"
    local url="$2"
    shift 2

    local tmp_body=$(mktemp /tmp/censys_body_XXXX.json 2>/dev/null)
    local http_code

    http_code=$(curl -s -w "%{http_code}" -o "$tmp_body" \
        -H "Accept: application/json" \
        "${@}" "$url")

    local body=$(cat "$tmp_body" 2>/dev/null || echo "")
    rm -f "$tmp_body"

    if [[ "$http_code" != "200" ]]; then
        print_alert " [${label}] HTTP ${http_code} Error"
        return 1
    fi
    echo "$body"
    return 0
}

# ── Main Censys Analysis ─────────────────────────────────────────────────────
_censys_analyze() {
    local query="$1"
    local report="$2"

    local api_ok=0
    _censys_verify_api_key && api_ok=1

    if [[ $api_ok -eq 1 ]]; then
        print_info " Querying Censys API..."
        local response
        response=$(_censys_curl_request "Censys API" \
            "https://search.censys.io/api/v2/hosts/search" \
            -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
            -G --data-urlencode "q=${query}" \
            --data-urlencode "per_page=10")

        if [[ $? -eq 0 && -n "$response" ]]; then
            _report_add "$report" "### Censys API Results - ${query}"
            echo "$response" | python3 -c '
import sys, json
try:
    data = json.load(sys.stdin)
    hits = data.get("result", {}).get("hits", [])
    print(f"Total Results Found: {data.get("result", {}).get("total", 0)}")
    for i, host in enumerate(hits[:8], 1):
        ip = host.get("ip", "N/A")
        asn = host.get("asn", {}).get("asn", "N/A")
        org = host.get("asn", {}).get("name", "N/A")
        services = [s.get("service_name","Unknown") for s in host.get("services", [])]
        print(f"\n{i}. IP: {ip}")
        print(f"   ASN: {asn} | Org: {org}")
        print(f"   Services: {", ".join(services[:6]) or "None"}")
        print(f"   Last Seen: {host.get("last_seen", "N/A")}")
except:
    print("Could not parse API response.")
' >> "$report" 2>/dev/null
        fi
    else
        # Public / Fallback Search
        print_info " Using public Censys search (limited results)..."
        _report_add "$report" "### Censys Public Search Results"
        _report_add "$report" "**Query:** ${query}"
        _report_add "$report" "**Note:** Full results require API key in config/api_keys.conf"
        
        echo "https://search.censys.io/search?q=$(echo "$query" | tr ' ' '+')" >> "$report"
    fi

    # Additional Intelligence Sections
    _report_add "$report" ""
    _report_add "$report" "### Exposure Summary"
    _report_add "$report" "**Search Query**: ${query}"
    _report_add "$report" "**Search Type**: Host / Certificate / Website Discovery"
    _report_add "$report" "**Recommended Next Steps**: Check open ports, SSL certificates, and exposed services"

    _report_add "$report" ""
    _report_add "$report" "**Analysis completed on:** $(date '+%Y-%m-%d %H:%M:%S %Z')"

    print_success "Censys reconnaissance completed"
    echo "VERDICT:CENSYS_COMPLETE"
}

# ── Bonus: Quick Public Search Function ─────────────────────────────────────
censys_quick() {
    local q="$1"
    print_info "Quick Censys lookup for: ${q}"
    echo -e "\n${CYAN}→ Open in Browser:${RESET} https://search.censys.io/search?q=$(echo "$q" | tr ' ' '+')"
}
