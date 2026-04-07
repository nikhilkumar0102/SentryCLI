#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Incident Response Module
# modules/incident.sh
#
# Collects forensic triage data during a security incident:
# running processes, network connections, logged-in users,
# cron jobs, recent file changes, and system integrity checks.
# =============================================================================

# ── Module Entry Point ────────────────────────────────────────────────────────
run_incident() {
    print_section "INCIDENT RESPONSE MODULE"
    log_info "INCIDENT" "Module started — forensic triage initiated"
    print_alert "INCIDENT RESPONSE TRIAGE IN PROGRESS..."
    echo ""

    # Initialize timestamped report
    local report
    report=$(report_init "incident_response")
    report_section "$report" "Incident Response Triage"
    report_append "$report" "Triage Host   : $(hostname)"
    report_append "$report" "Triage Time   : $(date)"
    report_append "$report" "Analyst User  : $(whoami)"
    report_append "$report" "Kernel Version: $(uname -r)"
    report_append "$report" "OS Info       : $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"

    # Collect all forensic data
    _ir_system_info       "$report"
    _ir_running_processes "$report"
    _ir_network_connections "$report"
    _ir_logged_in_users   "$report"
    _ir_cron_jobs         "$report"
    _ir_recent_file_changes "$report"
    _ir_open_files        "$report"
    _ir_loaded_modules    "$report"
    _ir_startup_services  "$report"
    _ir_env_and_shell     "$report"
    _ir_shadow_and_passwd "$report"
    _ir_suid_sgid         "$report"

    report_finalize "$report"
    print_success "Incident triage complete. Report: ${report}"
    log_success "INCIDENT" "Triage complete. Report: $report"

    echo ""
    print_warn "NEXT STEPS:"
    print_kv "  1. Preserve" "Copy report off the system immediately"
    print_kv "  2. Isolate"  "Consider network isolation if compromise confirmed"
    print_kv "  3. Escalate" "Notify security team / management"
    print_kv "  4. Contain"  "Block suspicious IPs, revoke compromised credentials"
}

# ── System Information ────────────────────────────────────────────────────────
_ir_system_info() {
    local report="$1"

    print_subsection "System Information"
    report_section "$report" "System Information"

    local hostname os_info kernel uptime cpu_info mem_info disk_info
    hostname=$(hostname -f 2>/dev/null || hostname)
    os_info=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')
    kernel=$(uname -r)
    uptime=$(uptime -p 2>/dev/null || uptime)
    cpu_info=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | sed 's/^ *//')
    mem_info=$(free -h 2>/dev/null | grep Mem | awk '{print "Total:"$2" Used:"$3" Free:"$4}')
    disk_info=$(df -h / 2>/dev/null | tail -1 | awk '{print "Total:"$2" Used:"$3" Free:"$4" ("$5" used)"}')

    print_kv "Hostname"    "$hostname"
    print_kv "OS"          "${os_info:-unknown}"
    print_kv "Kernel"      "$kernel"
    print_kv "Uptime"      "$uptime"
    print_kv "CPU"         "${cpu_info:-N/A}"
    print_kv "Memory"      "$mem_info"
    print_kv "Disk (/)"    "$disk_info"

    {
        echo "Hostname : $hostname"
        echo "OS       : ${os_info:-unknown}"
        echo "Kernel   : $kernel"
        echo "Uptime   : $uptime"
        echo "CPU      : ${cpu_info:-N/A}"
        echo "Memory   : $mem_info"
        echo "Disk     : $disk_info"
    } >> "$report"
}

# ── Running Processes ─────────────────────────────────────────────────────────
_ir_running_processes() {
    local report="$1"

    print_subsection "Running Processes (Top CPU/Memory)"
    report_section "$report" "Running Processes"
    log_info "INCIDENT" "Collecting process list"

    # Show top 20 by CPU
    local ps_output
    ps_output=$(ps aux --sort=-%cpu 2>/dev/null | head -21)

    echo ""
    echo -e "  ${BOLD}${WHITE}$(echo "$ps_output" | head -1)${RESET}"
    echo "$ps_output" | tail -n +2 | while IFS= read -r line; do
        local cpu
        cpu=$(echo "$line" | awk '{print $3}')
        # Highlight high-CPU processes
        if (( $(echo "$cpu > 50" | bc -l 2>/dev/null || echo 0) )); then
            echo -e "  ${RED}$line${RESET}"
        elif (( $(echo "$cpu > 20" | bc -l 2>/dev/null || echo 0) )); then
            echo -e "  ${YELLOW}$line${RESET}"
        else
            echo -e "  ${DIM}$line${RESET}"
        fi
    done

    echo "$ps_output" >> "$report"

    # Flag suspicious processes
    _ir_flag_suspicious_processes "$report"
}

# ── Flag Suspicious Processes ─────────────────────────────────────────────────
_ir_flag_suspicious_processes() {
    local report="$1"

    local suspicious_names=(
        "nc" "netcat" "ncat" "socat"
        "meterpreter" "mimikatz" "hydra" "john"
        "base64" "python -c" "perl -e" "ruby -e"
        "bash -i" "sh -i" "wget.*http" "curl.*http.*|.*bash"
        "cryptominer" "xmrig" "minerd" "cgminer"
    )

    local found_suspicious=0
    for sp in "${suspicious_names[@]}"; do
        if ps aux 2>/dev/null | grep -v grep | grep -qi "$sp"; then
            if [[ $found_suspicious -eq 0 ]]; then
                echo ""
                print_critical "SUSPICIOUS PROCESSES DETECTED:"
            fi
            local matching
            matching=$(ps aux 2>/dev/null | grep -i "$sp" | grep -v grep)
            print_alert "  Pattern '$sp' found:"
            echo -e "  ${RED}$matching${RESET}"
            report_append "$report" "SUSPICIOUS PROCESS [$sp]: $matching"
            log_critical "INCIDENT" "Suspicious process detected: $sp"
            (( found_suspicious++ ))
        fi
    done
}

# ── Network Connections ───────────────────────────────────────────────────────
_ir_network_connections() {
    local report="$1"

    print_subsection "Active Network Connections"
    report_section "$report" "Network Connections"
    log_info "INCIDENT" "Collecting network connections"

    if command -v ss &>/dev/null; then
        local conn_data
        conn_data=$(ss -tulpn 2>/dev/null)
        echo ""
        echo "$conn_data" | head -30 | while IFS= read -r line; do
            echo -e "  ${DIM}$line${RESET}"
        done
        echo "$conn_data" >> "$report"

        # Established connections
        echo ""
        print_info "Established outbound connections:"
        local established
        established=$(ss -tnp state established 2>/dev/null | head -20)
        echo "$established" | while IFS= read -r line; do
            echo -e "  ${YELLOW}$line${RESET}"
        done
        echo "$established" >> "$report"

    elif command -v netstat &>/dev/null; then
        local netstat_data
        netstat_data=$(netstat -tulpn 2>/dev/null)
        echo "$netstat_data" | head -30 | while IFS= read -r line; do
            echo -e "  ${DIM}$line${RESET}"
        done
        echo "$netstat_data" >> "$report"
    fi

    # Flag unusual listening ports
    _ir_flag_unusual_ports "$report"
}

# ── Flag Unusual Ports ───────────────────────────────────────────────────────
_ir_flag_unusual_ports() {
    local report="$1"

    local unusual_ports=(
        "4444" "1234" "31337" "6666" "12345"
        "54321" "8888" "9999" "1337" "2222"
    )

    for port in "${unusual_ports[@]}"; do
        if ss -tulpn 2>/dev/null | grep -q ":${port}"; then
            print_critical "Unusual port LISTENING: $port — possible backdoor!"
            report_append "$report" "ALERT: Unusual listening port: $port"
            log_critical "INCIDENT" "Unusual listening port: $port"
        fi
    done
}

# ── Logged-In Users ───────────────────────────────────────────────────────────
_ir_logged_in_users() {
    local report="$1"

    print_subsection "Currently Logged-In Users"
    report_section "$report" "Logged-In Users"
    log_info "INCIDENT" "Collecting user sessions"

    echo ""
    print_info "Active sessions (w):"
    local w_output
    w_output=$(w 2>/dev/null)
    echo "$w_output" | while IFS= read -r line; do
        echo -e "  ${WHITE}$line${RESET}"
    done
    echo "$w_output" >> "$report"

    echo ""
    print_info "Login history (last 10):"
    local last_output
    last_output=$(last -n 10 2>/dev/null)
    echo "$last_output" | while IFS= read -r line; do
        echo -e "  ${DIM}$line${RESET}"
    done
    echo "$last_output" >> "$report"

    echo ""
    print_info "Failed logins (lastb top 10):"
    local lastb_output
    lastb_output=$(lastb -n 10 2>/dev/null || echo "  (requires root or not available)")
    echo "$lastb_output" | while IFS= read -r line; do
        echo -e "  ${YELLOW}$line${RESET}"
    done
    echo "$lastb_output" >> "$report"
}

# ── Cron Jobs ────────────────────────────────────────────────────────────────
_ir_cron_jobs() {
    local report="$1"

    print_subsection "Cron Jobs & Scheduled Tasks"
    report_section "$report" "Cron Jobs"
    log_info "INCIDENT" "Collecting cron jobs"

    local cron_locations=(
        "/etc/crontab"
        "/etc/cron.d/"
        "/etc/cron.daily/"
        "/etc/cron.hourly/"
        "/etc/cron.weekly/"
        "/var/spool/cron/"
        "/var/spool/cron/crontabs/"
    )

    for loc in "${cron_locations[@]}"; do
        if [[ -e "$loc" ]]; then
            local content
            content=$(cat "$loc" 2>/dev/null || ls -la "$loc" 2>/dev/null)
            if [[ -n "$content" ]]; then
                print_kv "  $loc" ""
                echo "$content" | head -20 | while IFS= read -r line; do
                    [[ "$line" =~ ^#.*$ ]] && continue
                    [[ -z "$line" ]] && continue
                    echo -e "    ${YELLOW}$line${RESET}"
                    report_append "$report" "  $loc: $line"
                done
            fi
        fi
    done

    # User crontabs
    echo ""
    print_info "User crontab (current user):"
    local user_cron
    user_cron=$(crontab -l 2>/dev/null || echo "  No crontab for current user")
    echo -e "  ${DIM}${user_cron}${RESET}"
    report_append "$report" "User crontab: $user_cron"
}

# ── Recent File Changes ───────────────────────────────────────────────────────
_ir_recent_file_changes() {
    local report="$1"

    print_subsection "Recently Modified Files (last 24h)"
    report_section "$report" "Recent File Changes"
    log_info "INCIDENT" "Scanning for recently modified files"

    local search_dirs=("/tmp" "/var/tmp" "/dev/shm" "/etc" "/usr/bin" "/usr/local/bin")
    local suspicious_locations=()

    for dir in "${search_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local recent
            recent=$(find "$dir" -maxdepth 3 -mtime -1 -type f 2>/dev/null | head -10)
            if [[ -n "$recent" ]]; then
                print_kv "  $dir" ""
                while IFS= read -r file; do
                    local perms
                    perms=$(stat -c "%A %U %G" "$file" 2>/dev/null)
                    echo -e "    ${YELLOW}$file${RESET} ${DIM}($perms)${RESET}"
                    report_append "$report" "  MODIFIED: $file ($perms)"

                    # Flag executable files in temp locations
                    if [[ -x "$file" && ("$dir" == "/tmp" || "$dir" == "/var/tmp" || "$dir" == "/dev/shm") ]]; then
                        print_critical "    Executable in temp directory: $file"
                        log_critical "INCIDENT" "Executable in temp dir: $file"
                        suspicious_locations+=("$file")
                    fi
                done <<< "$recent"
            fi
        fi
    done

    if [[ ${#suspicious_locations[@]} -gt 0 ]]; then
        report_append "$report" ""
        report_append "$report" "SUSPICIOUS EXECUTABLES IN TEMP DIRS:"
        for f in "${suspicious_locations[@]}"; do
            report_append "$report" "  $f"
        done
    fi
}

# ── Open Files ───────────────────────────────────────────────────────────────
_ir_open_files() {
    local report="$1"

    print_subsection "Open Files & Descriptors (Top Processes)"
    report_section "$report" "Open Files"

    if command -v lsof &>/dev/null; then
        local lsof_net
        lsof_net=$(lsof -i -n -P 2>/dev/null | head -20)
        echo "$lsof_net" | while IFS= read -r line; do
            echo -e "  ${DIM}$line${RESET}"
        done
        echo "$lsof_net" >> "$report"
    else
        print_warn "lsof not available — skipping open files analysis"
        report_append "$report" "lsof not available"
    fi
}

# ── Loaded Kernel Modules ────────────────────────────────────────────────────
_ir_loaded_modules() {
    local report="$1"

    print_subsection "Loaded Kernel Modules"
    report_section "$report" "Kernel Modules"

    local modules
    modules=$(lsmod 2>/dev/null | head -20)
    echo "$modules" | while IFS= read -r line; do
        echo -e "  ${DIM}$line${RESET}"
    done
    echo "$modules" >> "$report"
}

# ── Startup Services ──────────────────────────────────────────────────────────
_ir_startup_services() {
    local report="$1"

    print_subsection "Startup Services & Systemd Units"
    report_section "$report" "Startup Services"

    if command -v systemctl &>/dev/null; then
        local services
        services=$(systemctl list-units --type=service --state=running 2>/dev/null | head -25)
        echo "$services" | while IFS= read -r line; do
            echo -e "  ${DIM}$line${RESET}"
        done
        echo "$services" >> "$report"
    elif command -v service &>/dev/null; then
        service --status-all 2>/dev/null | head -20 >> "$report"
    fi

    # Check rc.local for persistence
    if [[ -f "/etc/rc.local" ]]; then
        local rc_content
        rc_content=$(grep -v "^#" /etc/rc.local | grep -v "^$")
        if [[ -n "$rc_content" ]]; then
            echo ""
            print_warn "Non-empty /etc/rc.local — check for persistence:"
            echo -e "  ${YELLOW}$rc_content${RESET}"
            report_append "$report" "rc.local content: $rc_content"
        fi
    fi
}

# ── Environment & Shell History ───────────────────────────────────────────────
_ir_env_and_shell() {
    local report="$1"

    print_subsection "Shell History (last 20 commands)"
    report_section "$report" "Shell History"

    local history_files=(
        ~/.bash_history
        ~/.zsh_history
        ~/.sh_history
    )

    for hfile in "${history_files[@]}"; do
        if [[ -r "$hfile" ]]; then
            print_info "History from: $hfile"
            tail -20 "$hfile" | while IFS= read -r line; do
                echo -e "  ${DIM}$line${RESET}"
            done
            {
                echo "History ($hfile):"
                tail -20 "$hfile"
            } >> "$report"
        fi
    done
}

# ── /etc/passwd and Shadow Analysis ──────────────────────────────────────────
_ir_shadow_and_passwd() {
    local report="$1"

    print_subsection "User Account Integrity Check"
    report_section "$report" "User Accounts"

    # Show users with login shells (potential accounts)
    print_info "Accounts with login shells:"
    local login_users
    login_users=$(grep -vE "(nologin|false)$" /etc/passwd 2>/dev/null \
        | grep -vE "^#" \
        | cut -d: -f1,3,7)

    while IFS= read -r line; do
        local username uid shell
        username=$(echo "$line" | cut -d: -f1)
        uid=$(echo "$line"      | cut -d: -f2)
        shell=$(echo "$line"    | cut -d: -f3)

        if [[ "$uid" -eq 0 && "$username" != "root" ]]; then
            print_critical "  UID 0 non-root account: $username ($shell)"
            log_critical "INCIDENT" "UID 0 non-root account: $username"
        else
            print_kv "  $username (UID: $uid)" "$shell"
        fi
        report_append "$report" "  $username UID:$uid $shell"
    done <<< "$login_users"

    # Check for UID 0 duplicates
    local uid0_accounts
    uid0_accounts=$(awk -F: '$3==0' /etc/passwd 2>/dev/null)
    local uid0_count
    uid0_count=$(echo "$uid0_accounts" | grep -c "." || echo 0)
    if [[ $uid0_count -gt 1 ]]; then
        print_critical "Multiple UID 0 accounts detected! Potential backdoor:"
        echo -e "  ${RED}$uid0_accounts${RESET}"
        report_append "$report" "CRITICAL: Multiple UID 0 accounts: $uid0_accounts"
    fi
}

# ── SUID/SGID Files ───────────────────────────────────────────────────────────
_ir_suid_sgid() {
    local report="$1"

    print_subsection "SUID/SGID Binary Audit"
    report_section "$report" "SUID/SGID Files"
    log_info "INCIDENT" "Scanning for SUID/SGID files"

    print_info "Searching for SUID binaries (may take a moment)..."
    local suid_files
    suid_files=$(find / -perm -4000 -type f 2>/dev/null | sort | head -30)

    print_info "SUID files found:"
    echo "$suid_files" | while IFS= read -r file; do
        local perms owner
        perms=$(stat -c "%A" "$file" 2>/dev/null)
        owner=$(stat -c "%U" "$file" 2>/dev/null)
        echo -e "  ${YELLOW}$perms${RESET}  ${DIM}$owner${RESET}  ${WHITE}$file${RESET}"
        report_append "$report" "SUID: $perms $owner $file"
    done

    # Highlight unusual SUID locations
    echo "$suid_files" | while IFS= read -r file; do
        if echo "$file" | grep -qvE "^/(usr|bin|sbin|lib)"; then
            print_critical "Unusual SUID location: $file"
            log_alert "INCIDENT" "Unusual SUID binary: $file"
        fi
    done
}
