#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Log Intelligence Module
# modules/logintel.sh
#
# Analyzes authentication and system logs for brute-force attacks,
# suspicious activity patterns, and top offending IPs.
# =============================================================================

# ── Defaults ──────────────────────────────────────────────────────────────────
LOG_SOURCES=(
    "/var/log/auth.log"
    "/var/log/secure"
    "/var/log/syslog"
    "/var/log/messages"
)

BRUTE_FORCE_THRESHOLD=5          # Failed attempts before flagging as brute-force
TOP_IPS_COUNT=10                 # How many top IPs to display
SUSPICIOUS_IPS_FILE=""           # Will be set at runtime

# ── Module Entry Point ────────────────────────────────────────────────────────
run_logintel() {
    local target_log="${1:-}"

    print_section "LOG INTELLIGENCE MODULE"
    log_info "LOGINTEL" "Module started"

    # Initialize report
    local report
    report=$(report_init "logintel")
    report_section "$report" "Log Intelligence Analysis"

    # Resolve log file to analyze
    local log_file
    log_file=$(_logintel_resolve_log "$target_log")
    if [[ $? -ne 0 ]]; then
        print_alert "No readable log file found. Ensure you have appropriate permissions."
        log_error "LOGINTEL" "No readable log file found"
        return 1
    fi

    print_info "Analyzing log: ${log_file}"
    log_info "LOGINTEL" "Analyzing: ${log_file}"
    report_append "$report" "Log Source: ${log_file}"
    report_append "$report" "Analysis Start: $(date)"
    echo ""

    # Run all analysis functions
    _logintel_summary          "$log_file" "$report"
    _logintel_failed_logins    "$log_file" "$report"
    _logintel_brute_force      "$log_file" "$report"
    _logintel_top_ips          "$log_file" "$report"
    _logintel_successful_logins "$log_file" "$report"
    _logintel_user_activity    "$log_file" "$report"
    _logintel_sudo_events      "$log_file" "$report"

    # Export suspicious IPs for correlation engine
    SUSPICIOUS_IPS_FILE=$(mktemp /tmp/sentrycli_suspicious_ips_XXXX.txt)
    _logintel_export_suspicious_ips "$log_file" "$SUSPICIOUS_IPS_FILE"

    report_finalize "$report"
    log_success "LOGINTEL" "Module completed. Report: ${report}"
    echo ""
    print_info "Suspicious IPs exported for correlation → ${SUSPICIOUS_IPS_FILE}"
}

# ── Resolve Log File ──────────────────────────────────────────────────────────
_logintel_resolve_log() {
    local target="$1"
    if [[ -n "$target" && -r "$target" ]]; then
        echo "$target"
        return 0
    fi
    for f in "${LOG_SOURCES[@]}"; do
        if [[ -r "$f" ]]; then
            echo "$f"
            return 0
        fi
    done
    # Fallback: use last syslog or create a sample for demo
    if command -v journalctl &>/dev/null; then
        local tmp
        tmp=$(mktemp /tmp/sentrycli_journal_XXXX.log)
        journalctl -n 5000 --no-pager > "$tmp" 2>/dev/null
        echo "$tmp"
        return 0
    fi
    return 1
}

# ── Log Summary ──────────────────────────────────────────────────────────────
_logintel_summary() {
    local log_file="$1"
    local report="$2"

    print_subsection "Log Summary"
    local total_lines
    total_lines=$(wc -l < "$log_file")
    local file_size
    file_size=$(du -sh "$log_file" 2>/dev/null | cut -f1)
    local date_range_start
    date_range_start=$(head -1 "$log_file" | awk '{print $1, $2, $3}')
    local date_range_end
    date_range_end=$(tail -1 "$log_file" | awk '{print $1, $2, $3}')

    print_kv "Log File"      "$log_file"
    print_kv "File Size"     "$file_size"
    print_kv "Total Lines"   "$total_lines"
    print_kv "Period Start"  "$date_range_start"
    print_kv "Period End"    "$date_range_end"

    {
        echo "Log File    : $log_file"
        echo "File Size   : $file_size"
        echo "Total Lines : $total_lines"
        echo "Period      : $date_range_start  →  $date_range_end"
    } >> "$report"
}

# ── Failed Login Analysis ────────────────────────────────────────────────────
_logintel_failed_logins() {
    local log_file="$1"
    local report="$2"

    print_subsection "Failed Login Attempts"
    report_section "$report" "Failed Login Attempts"

    local patterns=(
        "Failed password"
        "Invalid user"
        "authentication failure"
        "FAILED LOGIN"
        "pam_unix.*failure"
    )

    local total_failed=0
    for pattern in "${patterns[@]}"; do
        local count
        count=$(grep -c -i "$pattern" "$log_file" 2>/dev/null || echo 0)
        if [[ $count -gt 0 ]]; then
            print_kv "  $pattern" "$count occurrences"
            report_append "$report" "  $pattern : $count"
            (( total_failed += count ))
        fi
    done

    echo ""
    if [[ $total_failed -gt 100 ]]; then
        print_critical "Total failed login events: ${total_failed} — HIGH ACTIVITY DETECTED"
        log_alert "LOGINTEL" "High failed login count: $total_failed"
    elif [[ $total_failed -gt 20 ]]; then
        print_warn "Total failed login events: ${total_failed} — Elevated activity"
        log_warn "LOGINTEL" "Elevated failed login count: $total_failed"
    else
        print_info "Total failed login events: ${total_failed}"
    fi

    report_append "$report" "TOTAL FAILED LOGINS: $total_failed"
}

# ── Brute Force Detection ─────────────────────────────────────────────────────
_logintel_brute_force() {
    local log_file="$1"
    local report="$2"

    print_subsection "Brute-Force Detection (threshold: ${BRUTE_FORCE_THRESHOLD}+ attempts)"
    report_section "$report" "Brute-Force Candidates"

    local brute_ips
    brute_ips=$(grep -E "(Failed password|Invalid user)" "$log_file" 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort | uniq -c | sort -rn \
        | awk -v thresh="$BRUTE_FORCE_THRESHOLD" '$1 >= thresh {print}')

    if [[ -z "$brute_ips" ]]; then
        print_success "No brute-force activity detected above threshold"
        report_append "$report" "No brute-force candidates found"
        return
    fi

    local count=0
    while IFS= read -r line; do
        local attempts ip
        attempts=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        if [[ $attempts -ge 100 ]]; then
            print_critical "  BRUTE FORCE: ${ip} — ${attempts} attempts"
            log_critical "LOGINTEL" "Brute-force IP: $ip ($attempts attempts)"
        elif [[ $attempts -ge 20 ]]; then
            print_alert "  SUSPECTED BF: ${ip} — ${attempts} attempts"
            log_alert "LOGINTEL" "Suspected brute-force IP: $ip ($attempts attempts)"
        else
            print_warn "  SUSPICIOUS:   ${ip} — ${attempts} attempts"
        fi
        report_append "$report" "  $ip : $attempts attempts"
        (( count++ ))
    done <<< "$brute_ips"

    echo ""
    print_info "Brute-force candidate IPs found: ${count}"
    report_append "$report" "BRUTE-FORCE IPS TOTAL: $count"
}

# ── Top Attacking IPs ─────────────────────────────────────────────────────────
_logintel_top_ips() {
    local log_file="$1"
    local report="$2"

    print_subsection "Top ${TOP_IPS_COUNT} Attacking IPs"
    report_section "$report" "Top Attacking IPs"

    local top_ips
    top_ips=$(grep -E "(Failed password|Invalid user|authentication failure)" "$log_file" 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort | uniq -c | sort -rn \
        | head -"$TOP_IPS_COUNT")

    if [[ -z "$top_ips" ]]; then
        print_info "No attacking IPs identified in log"
        return
    fi

    printf "\n  ${BOLD}%-8s  %-18s  %s${RESET}\n" "Hits" "IP Address" "Threat Level"
    print_divider
    while IFS= read -r line; do
        local count ip threat_label threat_color
        count=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line"   | awk '{print $2}')
        if [[ $count -ge 100 ]]; then
            threat_label="CRITICAL"
            threat_color=$RED
        elif [[ $count -ge 50 ]]; then
            threat_label="HIGH"
            threat_color=$RED
        elif [[ $count -ge 10 ]]; then
            threat_label="MEDIUM"
            threat_color=$YELLOW
        else
            threat_label="LOW"
            threat_color=$GREEN
        fi
        printf "  ${WHITE}%-8s${RESET}  ${CYAN}%-18s${RESET}  ${threat_color}%s${RESET}\n" \
            "$count" "$ip" "$threat_label"
        report_append "$report" "  $ip | $count hits | $threat_label"
    done <<< "$top_ips"
}

# ── Successful Logins ────────────────────────────────────────────────────────
_logintel_successful_logins() {
    local log_file="$1"
    local report="$2"

    print_subsection "Successful Authentication Events"
    report_section "$report" "Successful Logins"

    local success_count
    success_count=$(grep -cE "(Accepted password|Accepted publickey|session opened)" \
        "$log_file" 2>/dev/null || echo 0)

    print_kv "Successful auth events" "$success_count"
    report_append "$report" "Successful auth events: $success_count"

    # Show unique users who logged in successfully
    local success_users
    success_users=$(grep -E "Accepted (password|publickey)" "$log_file" 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' \
        | sort | uniq -c | sort -rn | head -10)

    if [[ -n "$success_users" ]]; then
        echo ""
        print_info "Users with successful logins:"
        while IFS= read -r line; do
            local cnt usr
            cnt=$(echo "$line" | awk '{print $1}')
            usr=$(echo "$line" | awk '{print $2}')
            print_kv "    $usr" "$cnt sessions"
            report_append "$report" "  $usr : $cnt sessions"
        done <<< "$success_users"
    fi
}

# ── User Activity ────────────────────────────────────────────────────────────
_logintel_user_activity() {
    local log_file="$1"
    local report="$2"

    print_subsection "Invalid/Non-Existent User Attempts"
    report_section "$report" "Invalid User Attempts"

    local invalid_users
    invalid_users=$(grep "Invalid user" "$log_file" 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="user") print $(i+1)}' \
        | sort | uniq -c | sort -rn | head -15)

    if [[ -z "$invalid_users" ]]; then
        print_success "No invalid user attempts found"
        return
    fi

    print_info "Most targeted non-existent usernames:"
    while IFS= read -r line; do
        local cnt uname
        cnt=$(echo "$line"   | awk '{print $1}')
        uname=$(echo "$line" | awk '{print $2}')
        printf "  ${YELLOW}%-5s${RESET}  ${WHITE}%s${RESET}\n" "$cnt" "$uname"
        report_append "$report" "  $uname : $cnt attempts"
    done <<< "$invalid_users"
}

# ── Sudo Events ──────────────────────────────────────────────────────────────
_logintel_sudo_events() {
    local log_file="$1"
    local report="$2"

    print_subsection "Sudo & Privilege Escalation Events"
    report_section "$report" "Privilege Escalation"

    local sudo_count
    sudo_count=$(grep -c "sudo" "$log_file" 2>/dev/null || echo 0)
    local sudo_fail
    sudo_fail=$(grep -c "sudo.*FAILED\|sudo.*incorrect password\|sudo.*3 incorrect" \
        "$log_file" 2>/dev/null || echo 0)

    print_kv "Total sudo events"   "$sudo_count"
    print_kv "Failed sudo attempts" "$sudo_fail"

    report_append "$report" "Total sudo events   : $sudo_count"
    report_append "$report" "Failed sudo attempts: $sudo_fail"

    if [[ $sudo_fail -gt 0 ]]; then
        print_warn "Failed sudo attempts detected — possible privilege escalation attempt"
        log_warn "LOGINTEL" "Failed sudo attempts: $sudo_fail"
    fi
}

# ── Export Suspicious IPs for Correlation ─────────────────────────────────────
_logintel_export_suspicious_ips() {
    local log_file="$1"
    local output_file="$2"

    grep -E "(Failed password|Invalid user)" "$log_file" 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort -u \
        | head -"$MAX_CORRELATION_IPS" > "$output_file"

    local count
    count=$(wc -l < "$output_file")
    log_info "LOGINTEL" "Exported $count unique suspicious IPs to $output_file"
}
