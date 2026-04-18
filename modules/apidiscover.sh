#!/usr/bin/env bash
# =============================================================================
# SentryCLI - API Endpoint Discovery [API-18] - Enhanced
# modules/apidiscover.sh
# Discovers API endpoints, GraphQL, Swagger, and hidden API paths
# =============================================================================

run_apidiscover() {

    print_section "18. API ENDPOINT DISCOVERY [API-18]"

    # ── Resolve target ─────────────────────────────────────────────────────
    local target=""
    if [[ -n "${MODULE_OPTS[target]:-}" ]]; then
        target="${MODULE_OPTS[target]}"
        print_info "Using REPL-set target → ${target}"
    elif [[ -n "${MODULE_OPTS[host]:-}" ]]; then
        target="${MODULE_OPTS[host]}"
        print_info "Using REPL-set target → ${target}"
    elif [[ -n "${1:-}" ]]; then
        target="$1"
    fi

    if [[ -z "$target" ]]; then
        echo -ne "${CYAN}Enter Target Domain/URL (e.g. example.com): ${RESET}"
        read -r target
    fi

    [[ -z "$target" ]] && { print_alert "No target provided."; return 1; }

    # Normalize
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="https://${target}"
    fi

    local domain
    domain=$(echo "$target" | sed -E 's|https?://||' | sed 's|/.*||' | tr -d '[:space:]' 2>/dev/null || true)

    # ── Initialize Report ──────────────────────────────────────────────────
    local report
    report=$(report_init "API_Discovery_${domain//[^a-zA-Z0-9._-]/_}")

    report_section "$report" "Scan Target"
    report_append "$report" "Target : $target"
    report_append "$report" "Domain : $domain"

    print_subsection "Discovering API Endpoints on → ${domain}"
    echo ""

    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed."
        report_finalize "$report"
        return 1
    fi

    # ── Common API paths and patterns ──────────────────────────────────────
    print_info "Probing for common API endpoints..."

    local -a api_paths=(
        "/api" "/api/v1" "/api/v2" "/api/v3" "/api/v4"
        "/rest" "/rest/v1" "/rest/v2"
        "/graphql" "/graphiql" "/graphql.php"
        "/swagger" "/swagger-ui" "/swagger.json" "/openapi.json" "/api-docs"
        "/admin/api" "/backend" "/internal" "/private" "/dev"
        "/wp-json" "/wp-json/wp/v2" "/v1" "/v2"
        "/json" "/data" "/mobile" "/app" "/console"
    )

    local -a found_endpoints=()
    local count=0

    # Safe detection helper
    _check_path() {
        local path="$1"
        local full_url="${target}${path}"
        local response
        response=$(curl -s -I -L --max-time 8 --connect-timeout 6 \
            -A "Mozilla/5.0 (compatible; SentryCLI/2.8)" \
            -w "%{http_code}" "$full_url" 2>/dev/null) || true

        local status=${response: -3}
        local body=$(curl -s -L --max-time 10 --connect-timeout 6 \
            -A "Mozilla/5.0 (compatible; SentryCLI/2.8)" "$full_url" 2>/dev/null || true)

        if [[ "$status" -eq 200 || "$status" -eq 301 || "$status" -eq 302 ]]; then
            if echo "$body" | grep -qiE 'swagger|openapi|graphql|apiVersion|endpoint'; then
                found_endpoints+=("${full_url} | ${status} | API DOCUMENTATION")
                ((count++))
                echo -e "  ${GREEN}✔${RESET} ${full_url} ${CYAN}(API Docs)${RESET}"
            else
                found_endpoints+=("${full_url} | ${status} | POSSIBLE API")
                ((count++))
                echo -e "  ${GREEN}✔${RESET} ${full_url} ${YELLOW}(Possible API)${RESET}"
            fi
            return 0
        elif [[ "$status" -eq 403 || "$status" -eq 401 ]]; then
            echo -e "  ${YELLOW}⚠${RESET} ${full_url} ${DIM}(Access Denied - Possible Protected API)${RESET}"
        fi
        return 1
    }

    # ── Start Probing ──────────────────────────────────────────────────────
    for path in "${api_paths[@]}"; do
        _check_path "$path" >/dev/null || true
    done

    # Extra aggressive checks for GraphQL & Swagger
    echo ""
    print_info "Checking for GraphQL and Swagger specifically..."

    _check_path "/graphql" >/dev/null || true
    _check_path "/swagger-ui.html" >/dev/null || true
    _check_path "/api-docs" >/dev/null || true
    _check_path "/.well-known/openid-configuration" >/dev/null || true

    # ── Report Results ─────────────────────────────────────────────────────
    report_section "$report" "Discovered API Endpoints"
    report_append "$report" "Total Endpoints Found : $count"

    echo ""
    echo -e "${BOLD}${WHITE}API DISCOVERY RESULTS${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    if [[ $count -gt 0 ]]; then
        print_success "Found ${count} potential API endpoint(s)!"
        echo ""
        for endpoint in "${found_endpoints[@]}"; do
            echo -e "   ${GREEN}→${RESET} $endpoint"
            report_append "$report" "$endpoint"
        done
    else
        print_warn "No obvious API endpoints discovered."
        report_append "$report" "No API endpoints discovered."
    fi

    # ── Security Notes ─────────────────────────────────────────────────────
    report_section "$report" "Security Recommendations"
    echo ""
    echo -e "${BOLD}${WHITE}SECURITY NOTES${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_warn "Expose only necessary API endpoints"
    print_warn "Implement strong authentication (OAuth2, JWT, API Keys)"
    print_warn "Enable rate limiting and proper CORS policies"
    print_warn "Hide /swagger, /graphql, /api-docs in production"
    print_warn "Use API versioning properly"
    echo ""

    report_finalize "$report"
    log_success "APIDISCOVER" "Completed for $domain — $count endpoints found"

    # ── Summary ────────────────────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"              "$domain"
    print_kv "Endpoints Found"     "$count"
    print_kv "Report Saved"        "$report"
    echo ""

    print_success "API Endpoint Discovery completed successfully!"
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
    echo ""

    return 0
}
