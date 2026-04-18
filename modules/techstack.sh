#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Technology Stack Detector [TECH-11]
# modules/techstack.sh
#
# Detects web server, frameworks, CMS, CDN, JS libraries from HTTP responses.
# Pattern mirrors ipcheck.sh / fixed webheaders.sh / cmsdetect.sh exactly.
# =============================================================================

run_techstack() {

    print_section "11. TECHNOLOGY STACK DETECTOR [TECH-11]"

    # ── Resolve target ─────────────────────────────────────────────────────
    local target=""

    if   [[ -n "${MODULE_OPTS[target]:-}" ]]; then
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

    if ! command -v curl &>/dev/null; then
        print_alert "curl is not installed."
        return 1
    fi

    # ── Normalize: strip scheme and path, keep bare domain/IP ─────────────
    local domain
    domain=$(echo "$target" | sed -E 's|https?://||' | sed 's|/.*||' | tr -d '[:space:]')

    local url_https="https://${domain}"
    local url_http="http://${domain}"

    # ── Init report ────────────────────────────────────────────────────────
    local report
    report=$(report_init "TechStack_${domain//[^a-zA-Z0-9._-]/_}")

    report_section "$report" "Scan Target"
    report_append  "$report" "Target : $domain"
    report_append  "$report" "URL    : $url_https"

    print_subsection "Analyzing Technology Stack → ${domain}"
    echo ""

    # ── Fetch headers + body ───────────────────────────────────────────────
    # CRITICAL: every curl and grep must end with || true
    # grep returns exit 1 on no-match → kills main.sh under set -e
    print_info "Fetching HTTP headers and page body..."

    local headers="" body="" active_url="$url_https"

    headers=$(curl -s -I -L --max-time 12 --connect-timeout 8 \
        -A "Mozilla/5.0 (compatible; SentryCLI/2.7)" \
        "$url_https" 2>/dev/null) || true

    body=$(curl -s -L --max-time 15 --connect-timeout 8 \
        -A "Mozilla/5.0 (compatible; SentryCLI/2.7)" \
        "$url_https" 2>/dev/null) || true

    # Fallback to HTTP
    if [[ -z "$headers" ]] && [[ -z "$body" ]]; then
        print_warn "HTTPS unreachable — retrying with HTTP..."
        active_url="$url_http"
        headers=$(curl -s -I -L --max-time 12 --connect-timeout 8 \
            -A "Mozilla/5.0 (compatible; SentryCLI/2.7)" \
            "$url_http" 2>/dev/null) || true
        body=$(curl -s -L --max-time 15 --connect-timeout 8 \
            -A "Mozilla/5.0 (compatible; SentryCLI/2.7)" \
            "$url_http" 2>/dev/null) || true
        report_append "$report" "URL (fallback) : $url_http"
    fi

    if [[ -z "$headers" ]] && [[ -z "$body" ]]; then
        print_alert "No response from ${domain}. Host may be down or unreachable."
        report_append "$report" "ERROR: No response received."
        report_finalize "$report"
        log_error "TECHSTACK" "No response from $domain"
        return 1
    fi

    # ── Header extractor helper ────────────────────────────────────────────
    # || true is MANDATORY — grep exit 1 on no-match kills main.sh under set -e
    _ts_header() {
        printf '%s' "$headers" \
            | grep -i "^${1}:" \
            | head -1 \
            | cut -d':' -f2- \
            | sed 's/^[[:space:]]*//' \
            | tr -d '\r\n' \
            || true
    }

    # ── Extract key headers ────────────────────────────────────────────────
    local h_server h_powered h_generator h_framework h_via h_cf h_status
    local h_xruntime h_xdebug h_cookie h_csp h_cors

    h_status=$(printf '%s' "$headers"   | grep -i "^HTTP/"            | tail -1  | tr -d '\r'     || true)
    h_server=$(_ts_header    "Server")
    h_powered=$(_ts_header   "X-Powered-By")
    h_generator=$(_ts_header "X-Generator")
    h_framework=$(_ts_header "X-Framework")
    h_via=$(_ts_header       "Via")
    h_cf=$(_ts_header        "CF-Ray")
    h_xruntime=$(_ts_header  "X-Runtime")
    h_xdebug=$(_ts_header    "X-Debug-Token")
    h_cookie=$(printf '%s' "$headers"   | grep -i "^Set-Cookie:"      | head -3  | tr -d '\r'     || true)
    h_csp=$(_ts_header       "Content-Security-Policy")
    h_cors=$(_ts_header      "Access-Control-Allow-Origin")

    # ── Technology detection arrays ────────────────────────────────────────
    local -a detected_techs=()
    local -a detected_cats=()

    # Helper to record a detection
    _ts_add() {
        local category="$1" tech="$2" evidence="$3"
        detected_techs+=("${category}|${tech}|${evidence}")
    }

    # ── WEB SERVER ─────────────────────────────────────────────────────────
    if [[ -n "$h_server" ]]; then
        case "${h_server,,}" in
            *nginx*)    _ts_add "Web Server"  "Nginx"             "$h_server" ;;
            *apache*)   _ts_add "Web Server"  "Apache"            "$h_server" ;;
            *iis*)      _ts_add "Web Server"  "Microsoft IIS"     "$h_server" ;;
            *litespeed*) _ts_add "Web Server" "LiteSpeed"         "$h_server" ;;
            *caddy*)    _ts_add "Web Server"  "Caddy"             "$h_server" ;;
            *gunicorn*) _ts_add "Web Server"  "Gunicorn (Python)" "$h_server" ;;
            *openresty*) _ts_add "Web Server" "OpenResty (Nginx)" "$h_server" ;;
            *cowboy*)   _ts_add "Web Server"  "Cowboy (Erlang)"   "$h_server" ;;
            *)          _ts_add "Web Server"  "$h_server"         "Server header" ;;
        esac
    fi

    # ── LANGUAGE / RUNTIME ─────────────────────────────────────────────────
    if [[ -n "$h_powered" ]]; then
        case "${h_powered,,}" in
            *php*)      _ts_add "Language"  "PHP"        "$h_powered" ;;
            *asp.net*)  _ts_add "Language"  "ASP.NET"    "$h_powered" ;;
            *node*)     _ts_add "Language"  "Node.js"    "$h_powered" ;;
            *ruby*)     _ts_add "Language"  "Ruby"       "$h_powered" ;;
            *python*)   _ts_add "Language"  "Python"     "$h_powered" ;;
            *express*)  _ts_add "Framework" "Express.js" "$h_powered" ;;
            *)          _ts_add "Language"  "$h_powered" "X-Powered-By header" ;;
        esac
    fi

    # Ruby on Rails (X-Runtime is seconds float e.g. "0.234567")
    if [[ -n "$h_xruntime" ]] && echo "$h_xruntime" | grep -qE '^[0-9]+\.[0-9]+$' 2>/dev/null || false; then
        _ts_add "Framework" "Ruby on Rails" "X-Runtime: $h_xruntime"
    fi

    # Django (Symfony also uses this but less common)
    if [[ -n "$h_xdebug" ]]; then
        _ts_add "Framework" "Django / Symfony" "X-Debug-Token header"
    fi

    # ── FRAMEWORK via Generator ────────────────────────────────────────────
    if [[ -n "$h_generator" ]]; then
        _ts_add "Generator" "$h_generator" "X-Generator header"
    fi

    if [[ -n "$h_framework" ]]; then
        _ts_add "Framework" "$h_framework" "X-Framework header"
    fi

    # ── CDN / PROXY ────────────────────────────────────────────────────────
    if [[ -n "$h_cf" ]]; then
        _ts_add "CDN" "Cloudflare" "CF-Ray header: $h_cf"
    fi

    if [[ -n "$h_via" ]]; then
        case "${h_via,,}" in
            *cloudfront*) _ts_add "CDN"   "AWS CloudFront"  "$h_via" ;;
            *varnish*)    _ts_add "Cache" "Varnish Cache"   "$h_via" ;;
            *squid*)      _ts_add "Cache" "Squid Proxy"     "$h_via" ;;
            *nginx*)      _ts_add "Cache" "Nginx Proxy"     "$h_via" ;;
            *)            _ts_add "Proxy" "$h_via"          "Via header" ;;
        esac
    fi

    # ── CDN from body/headers signals ─────────────────────────────────────
    if echo "$headers" | grep -qi "x-amz-cf-id\|x-amz-request-id" 2>/dev/null || false; then
        _ts_add "CDN" "AWS CloudFront / S3" "x-amz headers"
    fi

    if echo "$headers" | grep -qi "x-fastly-request-id\|fastly" 2>/dev/null || false; then
        _ts_add "CDN" "Fastly" "x-fastly headers"
    fi

    if echo "$headers" | grep -qi "x-cache.*akamai\|akamai" 2>/dev/null || false; then
        _ts_add "CDN" "Akamai" "Akamai cache headers"
    fi

    # ── CMS DETECTION (body fingerprinting) ───────────────────────────────
    if echo "$body" | grep -qiE 'wp-content|wp-includes' 2>/dev/null || false; then
        local wp_ver
        wp_ver=$(echo "$body" | grep -oE 'ver=[0-9]+\.[0-9]+(\.[0-9]+)?' \
            | head -1 | cut -d'=' -f2 2>/dev/null) || true
        _ts_add "CMS" "WordPress${wp_ver:+ v${wp_ver}}" "wp-content/wp-includes in body"
    fi

    if echo "$body $headers" | grep -qiE 'joomla' 2>/dev/null || false; then
        _ts_add "CMS" "Joomla" "Joomla keyword in response"
    fi

    if echo "$body $headers" | grep -qiE 'drupal' 2>/dev/null || false; then
        _ts_add "CMS" "Drupal" "Drupal keyword in response"
    fi

    if echo "$headers" | grep -qiE 'x-shopid|shopify' 2>/dev/null || false; then
        _ts_add "CMS" "Shopify" "x-shopid / shopify header"
    fi

    if echo "$body" | grep -qiE 'Mage\.Cookies|mage-|Magento' 2>/dev/null || false; then
        _ts_add "CMS" "Magento" "Mage/Magento keyword in body"
    fi

    if echo "$body" | grep -qiE 'squarespace' 2>/dev/null || false; then
        _ts_add "CMS" "Squarespace" "squarespace reference in body"
    fi

    if echo "$body" | grep -qiE 'wix\.com|X-Wix' 2>/dev/null || false; then
        _ts_add "CMS" "Wix" "wix.com reference"
    fi

    if echo "$body" | grep -qiE 'ghost\.io|content="Ghost' 2>/dev/null || false; then
        _ts_add "CMS" "Ghost" "Ghost CMS meta detected"
    fi

    # ── JS LIBRARIES (body) ────────────────────────────────────────────────
    if echo "$body" | grep -qiE 'jquery[./]([0-9.]+)' 2>/dev/null || false; then
        local jq_ver
        jq_ver=$(echo "$body" | grep -oiE 'jquery[./]([0-9.]+)' \
            | head -1 | grep -oE '[0-9.]+' 2>/dev/null) || true
        _ts_add "JS Library" "jQuery${jq_ver:+ v${jq_ver}}" "jquery reference in body"
    fi

    if echo "$body" | grep -qiE 'react\.js|react\.min\.js|react-dom' 2>/dev/null || false; then
        _ts_add "JS Framework" "React.js" "react reference in body"
    fi

    if echo "$body" | grep -qiE 'vue\.js|vue\.min\.js|__vue__' 2>/dev/null || false; then
        _ts_add "JS Framework" "Vue.js" "vue reference in body"
    fi

    if echo "$body" | grep -qiE 'angular\.js|ng-version|angularjs' 2>/dev/null || false; then
        _ts_add "JS Framework" "Angular / AngularJS" "angular reference in body"
    fi

    if echo "$body" | grep -qiE 'next\.js|__NEXT_DATA__|_next/static' 2>/dev/null || false; then
        _ts_add "JS Framework" "Next.js" "_next/static or __NEXT_DATA__ in body"
    fi

    if echo "$body" | grep -qiE 'nuxt|__NUXT__' 2>/dev/null || false; then
        _ts_add "JS Framework" "Nuxt.js" "__NUXT__ in body"
    fi

    if echo "$body" | grep -qiE 'bootstrap\.min\.css|bootstrap\.css' 2>/dev/null || false; then
        _ts_add "CSS Framework" "Bootstrap" "bootstrap CSS reference"
    fi

    if echo "$body" | grep -qiE 'tailwindcss|tailwind\.css' 2>/dev/null || false; then
        _ts_add "CSS Framework" "Tailwind CSS" "tailwindcss reference"
    fi

    # ── ANALYTICS / TRACKING ──────────────────────────────────────────────
    if echo "$body" | grep -qiE 'google-analytics\.com|gtag|UA-[0-9]|G-[A-Z0-9]' 2>/dev/null || false; then
        _ts_add "Analytics" "Google Analytics" "GA script in body"
    fi

    if echo "$body" | grep -qiE 'googletagmanager\.com' 2>/dev/null || false; then
        _ts_add "Analytics" "Google Tag Manager" "GTM script in body"
    fi

    if echo "$body" | grep -qiE 'hotjar\.com' 2>/dev/null || false; then
        _ts_add "Analytics" "Hotjar" "hotjar.com reference"
    fi

    # ── COOKIES fingerprinting ─────────────────────────────────────────────
    if echo "$h_cookie" | grep -qi "PHPSESSID" 2>/dev/null || false; then
        _ts_add "Language" "PHP" "PHPSESSID cookie"
    fi

    if echo "$h_cookie" | grep -qi "JSESSIONID" 2>/dev/null || false; then
        _ts_add "Language" "Java (Servlet)" "JSESSIONID cookie"
    fi

    if echo "$h_cookie" | grep -qi "laravel_session\|XSRF-TOKEN" 2>/dev/null || false; then
        _ts_add "Framework" "Laravel (PHP)" "laravel_session / XSRF-TOKEN cookie"
    fi

    if echo "$h_cookie" | grep -qi "csrftoken\|sessionid" 2>/dev/null || false; then
        _ts_add "Framework" "Django (Python)" "csrftoken / sessionid cookie"
    fi

    if echo "$h_cookie" | grep -qi "rack.session\|_session_id" 2>/dev/null || false; then
        _ts_add "Framework" "Ruby on Rails / Rack" "rack.session cookie"
    fi

    # ── CORS ──────────────────────────────────────────────────────────────
    if [[ -n "$h_cors" ]]; then
        _ts_add "Security" "CORS: ${h_cors}" "Access-Control-Allow-Origin header"
    fi

    # ── WhatWeb (if available, append its output too) ──────────────────────
    local whatweb_out=""
    if command -v whatweb &>/dev/null; then
        print_info "WhatWeb available — running extended scan..."
        whatweb_out=$(whatweb -q --color=never "$url_https" 2>/dev/null \
            || whatweb -q --color=never "$url_http" 2>/dev/null) || true
    fi

    # ── DISPLAY RESULTS ────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}${WHITE}DETECTED TECHNOLOGIES${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"

    report_section "$report" "Detected Technologies"

    local last_cat="" count=0
    if [[ ${#detected_techs[@]} -gt 0 ]]; then
        for entry in "${detected_techs[@]}"; do
            local cat tech evidence
            cat=$(echo "$entry"      | cut -d'|' -f1)
            tech=$(echo "$entry"     | cut -d'|' -f2)
            evidence=$(echo "$entry" | cut -d'|' -f3)

            # Print category header when it changes
            if [[ "$cat" != "$last_cat" ]]; then
                echo ""
                echo -e "  ${BOLD}${WHITE}${cat}${RESET}"
                last_cat="$cat"
            fi

            printf "    ${GREEN}✔${RESET}  %-30s ${DIM}%s${RESET}\n" "$tech" "$evidence"
            report_append "$report" "[${cat}] ${tech} — ${evidence}"
            count=$(( count + 1 ))
        done
    else
        echo -e "  ${YELLOW}No specific technologies fingerprinted from headers/body.${RESET}"
        report_append "$report" "No specific technologies detected."
    fi

    echo ""

    # WhatWeb output block
    if [[ -n "$whatweb_out" ]]; then
        echo -e "  ${BOLD}${WHITE}WhatWeb Extended Results${RESET}"
        echo ""
        # Strip ANSI escape codes for clean display
        echo "$whatweb_out" | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' | sed 's/^/    /'
        echo ""
        report_section "$report" "WhatWeb Output"
        echo "$whatweb_out" | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' >> "$report"
    fi

    # ── CONNECTION INFO ────────────────────────────────────────────────────
    report_section "$report" "Connection Info"
    report_append  "$report" "Status  : ${h_status:-Unknown}"
    report_append  "$report" "Server  : ${h_server:-Not disclosed}"
    report_append  "$report" "Via     : ${h_via:-None}"
    report_append  "$report" "CF-Ray  : ${h_cf:-None}"

    echo -e "${BOLD}${WHITE}CONNECTION INFO${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "URL"     "$active_url"
    print_kv "Status"  "${h_status:-Unknown}"
    print_kv "Server"  "${h_server:-Not disclosed}"
    print_kv "Via/CDN" "${h_via:-None}"
    echo ""

    # ── Raw headers in report ──────────────────────────────────────────────
    report_section "$report" "Raw HTTP Headers"
    printf '%s\n' "$headers" >> "$report"

    # ── Finalize ───────────────────────────────────────────────────────────
    report_finalize "$report"
    log_success "TECHSTACK" "Tech stack scan complete for $domain — ${count} technologies detected"

    # ── SUMMARY ────────────────────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}SCAN SUMMARY${RESET}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${RESET}"
    print_kv "Target"               "$domain"
    print_kv "Technologies Found"   "$count"
    print_kv "WhatWeb"             "$(command -v whatweb &>/dev/null && echo 'Used' || echo 'Not installed (apt install whatweb)')"
    print_kv "Report Saved"         "$report"
    echo ""

    if [[ $count -gt 0 ]]; then
        print_success "Technology stack detection completed — ${count} technologies identified!"
    else
        print_warn "Detection completed — no technologies fingerprinted (site may use custom stack)"
    fi
    echo ""

    # ── Return to REPL ─────────────────────────────────────────────────────
    # NEVER touch CURRENT_MODULE or MODULE_OPTS — main.sh owns that state.
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
    echo ""

    return 0
}
