#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Incident Response Module (Enhanced Detection Version)
# modules/incident.sh
#
# Improved forensic triage with better detection of suspicious activity,
# persistence mechanisms, and attacker techniques.
# =============================================================================

# ── Module Entry Point ────────────────────────────────────────────────────────
run_incident() {
    print_section "INCIDENT RESPONSE MODULE"
    log_info "INCIDENT" "Enhanced forensic triage started"
    print_alert "INCIDENT RESPONSE TRIAGE IN PROGRESS..."
    echo ""

    local report
    report=$(report_init "incident_response")
    report_section "$report" "Incident Response Triage Report"
    report_append "$report" "Triage Host     : $(hostname)"
    report_append "$report" "Triage Time     : $(date)"
    report_append "$report" "Analyst         : $(whoami)"
    report_append "$report" "Kernel          : $(uname -r)"
    report_append "$report" "OS              : $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo "Unknown")"

    # Core forensic collection
    _ir_system_info "$report"
    _ir_running_processes "$report"
    _ir_network_connections "$report"
    _ir_logged_in_users "$report"
    _ir_persistence_checks "$report"
    _ir_recent_file_changes "$report"
    _ir_open_files "$report"
    _ir_loaded_modules "$report"
    _ir_startup_services "$report"
    _ir_env_and_shell "$report"
    _ir_user_account_audit "$report"
    _ir_suid_sgid_audit "$report"

    report_finalize "$report"

    print_success "Incident triage completed successfully."
    print_success "Report saved to: ${report}"
    log_success "INCIDENT" "Triage complete → Report: $report"

    echo ""
    print_warn "RECOMMENDED NEXT STEPS:"
    print_kv "1. Preserve Evidence" "Copy the report and suspicious files to external media"
    print_kv "2. Isolate Host"      "Consider network isolation if compromise is confirmed"
    print_kv "3. Escalate"         "Notify incident response team immediately"
    print_kv "4. Contain"          "Block suspicious IPs and revoke credentials"
}

# ── System Information ────────────────────────────────────────────────────────
_ir_system_info() {
    local report="$1"
    print_subsection "System Information"
    report_section "$report" "System Information"

    local hostname os_info kernel uptime cpu mem disk
    hostname=$(hostname -f 2>/dev/null || hostname)
    os_info=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo "Unknown")
    kernel=$(uname -r)
    uptime=$(uptime -p 2>/dev/null || uptime)
    cpu=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2- | sed 's/^ *//')
    mem=$(free -h 2>/dev/null | grep Mem | awk '{print "Total:"$2" Used:"$3" Free:"$4}')
    disk=$(df -h / 2>/dev/null | tail -1 | awk '{print "Total:"$2" Used:"$3" ("$5" used)"}')

    print_kv "Hostname" "$hostname"
    print_kv "OS"       "${os_info}"
    print_kv "Kernel"   "$kernel"
    print_kv "Uptime"   "$uptime"
    print_kv "CPU"      "${cpu:-N/A}"
    print_kv "Memory"   "$mem"
    print_kv "Root Disk" "$disk"

    {
        echo "Hostname : $hostname"
        echo "OS       : $os_info"
        echo "Kernel   : $kernel"
        echo "Uptime   : $uptime"
        echo "CPU      : ${cpu:-N/A}"
        echo "Memory   : $mem"
        echo "Disk     : $disk"
    } >> "$report"
}

# ── Running Processes with Stronger Detection ───────────────────────────────
_ir_running_processes() {
    local report="$1"
    print_subsection "Running Processes (Top by CPU)"
    report_section "$report" "Running Processes"

    print_info "Top 20 processes sorted by CPU usage:"
    echo ""

    local ps_output
    ps_output=$(ps aux --sort=-%cpu | head -21)

    echo -e " ${BOLD}${WHITE}$(echo "$ps_output" | head -1)${RESET}"
    echo "$ps_output" | tail -n +2 | while IFS= read -r line; do
        local cpu=$(echo "$line" | awk '{print int($3)}')
        if [[ $cpu -ge 50 ]]; then
            echo -e " ${RED}$line${RESET}"
        elif [[ $cpu -ge 20 ]]; then
            echo -e " ${YELLOW}$line${RESET}"
        else
            echo -e " ${DIM}$line${RESET}"
        fi
    done

    echo "$ps_output" >> "$report"
    _ir_flag_suspicious_processes "$report"
}

# ── Enhanced Suspicious Process Detection ───────────────────────────────────
_ir_flag_suspicious_processes() {
    local report="$1"

    print_subsection "Suspicious Process Detection"
    local patterns=(
        # Reverse shells & C2
        "bash -i" "sh -i" "nc -e" "ncat -e" "socat.*exec" "python.*socket" "perl -e.*socket"
        # Download & execute
        "wget .*http" "curl .*http.*bash" "curl .*--output" "base64 -d"
        # Common tools
        "meterpreter" "mimikatz" "hydra" "john" "hashcat" "cobaltstrike" "empire"
        # Crypto miners
        "xmrig" "minerd" "cgminer" "stratum" "cryptonight"
        # Persistence / hiding
        "nohup" "screen -dm" "tmux new-session" "setsid" "disown"
        # Living off the land
        "python -c" "perl -e" "ruby -e" "awk .*system" "echo .*>" 
    )

    local detected=0
    for pat in "${patterns[@]}"; do
        if ps aux 2>/dev/null | grep -v grep | grep -qiE "$pat"; then
            [[ $detected -eq 0 ]] && { echo ""; print_critical "SUSPICIOUS PROCESSES DETECTED:"; }
            local matches=$(ps aux 2>/dev/null | grep -v grep | grep -iE "$pat")
            print_alert "  Pattern: $pat"
            echo -e "   ${RED}$matches${RESET}"
            report_append "$report" "SUSPICIOUS: $pat → $matches"
            log_critical "INCIDENT" "Suspicious process: $pat"
            ((detected++))
        fi
    done

    [[ $detected -eq 0 ]] && print_success "No high-confidence suspicious processes found"
}

# ── Network Connections ─────────────────────────────────────────────────────
_ir_network_connections() {
    local report="$1"
    print_subsection "Network Connections Analysis"
    report_section "$report" "Network Connections"

    if command -v ss &>/dev/null; then
        print_info "Listening Ports:"
        ss -tulpn 2>/dev/null | head -30 | while IFS= read -r line; do
            echo -e " ${DIM}$line${RESET}"
        done

        echo ""
        print_info "Established Outbound Connections:"
        ss -tnp state established 2>/dev/null | head -25 | while IFS= read -r line; do
            echo -e " ${YELLOW}$line${RESET}"
        done
    elif command -v netstat &>/dev/null; then
        print_info "Network connections (netstat):"
        netstat -tulpn 2>/dev/null | head -40 | while IFS= read -r line; do
            echo -e " ${DIM}$line${RESET}"
        done
    fi

    _ir_flag_unusual_ports "$report"
}

# ── Unusual Ports Detection ─────────────────────────────────────────────────
_ir_flag_unusual_ports() {
    local report="$1"
    local suspicious_ports=("4444" "4445" "6666" "1234" "31337" "1337" "9001" "9999" "8081" "8888")

    local found=0
    for p in "${suspicious_ports[@]}"; do
        if ss -tulpn 2>/dev/null | grep -q ":${p}"; then
            [[ $found -eq 0 ]] && print_critical "UNUSUAL LISTENING PORTS DETECTED:"
            print_critical "   Port $p is listening — possible backdoor or C2 channel"
            report_append "$report" "ALERT: Unusual listening port $p"
            log_critical "INCIDENT" "Unusual port $p detected"
            ((found++))
        fi
    done
}

# ── Logged-in Users ─────────────────────────────────────────────────────────
_ir_logged_in_users() {
    local report="$1"
    print_subsection "Logged-in Users & Login History"
    report_section "$report" "Logged-in Users"

    print_info "Current sessions (w command):"
    w 2>/dev/null | while IFS= read -r line; do
        echo -e " ${WHITE}$line${RESET}"
    done
    w 2>/dev/null >> "$report"

    echo ""
    print_info "Recent successful logins (last 10):"
    last -n 10 2>/dev/null | while IFS= read -r line; do
        echo -e " ${DIM}$line${RESET}"
    done
    last -n 10 2>/dev/null >> "$report"

    echo ""
    print_info "Failed login attempts (lastb):"
    lastb -n 10 2>/dev/null | head -15 | while IFS= read -r line; do
        echo -e " ${YELLOW}$line${RESET}"
    done
}

# ── Persistence Mechanisms (Enhanced) ───────────────────────────────────────
_ir_persistence_checks() {
    local report="$1"
    print_subsection "Persistence & Autostart Mechanisms"
    report_section "$report" "Persistence Checks"

    print_info "Checking common persistence locations..."

    # Cron
    local cron_count=$(find /etc/cron.* /var/spool/cron 2>/dev/null | wc -l)
    print_kv "Cron entries" "$cron_count"

    # Systemd
    if command -v systemctl &>/dev/null; then
        local timers=$(systemctl list-timers --all 2>/dev/null | wc -l)
        print_kv "Systemd timers" "$((timers-1))"
    fi

    # rc.local
    if [[ -f "/etc/rc.local" ]] && grep -qvE '^#|^$' /etc/rc.local 2>/dev/null; then
        print_critical "Non-empty /etc/rc.local detected — potential persistence"
        report_append "$report" "PERSISTENCE: /etc/rc.local contains commands"
    fi

    # SSH authorized_keys
    find /home -name authorized_keys -exec ls -l {} + 2>/dev/null | while read -r line; do
        print_warn "authorized_keys file found: $line"
        report_append "$report" "PERSISTENCE: $line"
    done
}

# ── Recent File Changes ─────────────────────────────────────────────────────
_ir_recent_file_changes() {
    local report="$1"
    print_subsection "Recently Modified Files (last 24 hours)"
    report_section "$report" "Recent File Changes"

    local dirs=("/tmp" "/var/tmp" "/dev/shm" "/etc" "/usr/local/bin" "/root")
    local suspicious=()

    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local recent=$(find "$dir" -type f -mtime -1 2>/dev/null | head -15)
            if [[ -n "$recent" ]]; then
                print_kv " $dir" ""
                while IFS= read -r file; do
                    local info=$(stat -c "%A %U:%G" "$file" 2>/dev/null)
                    echo -e "   ${YELLOW}$file${RESET} ${DIM}($info)${RESET}"
                    report_append "$report" "RECENT FILE: $file ($info)"

                    if [[ -x "$file" && ("$dir" == "/tmp" || "$dir" == "/var/tmp" || "$dir" == "/dev/shm") ]]; then
                        print_critical "   Executable in temporary directory: $file"
                        suspicious+=("$file")
                    fi
                done <<< "$recent"
            fi
        fi
    done

    if [[ ${#suspicious[@]} -gt 0 ]]; then
        report_append "$report" "SUSPICIOUS EXECUTABLES IN TEMP DIRS:"
        for f in "${suspicious[@]}"; do
            report_append "$report" " $f"
        done
    fi
}

# ── Open Files ──────────────────────────────────────────────────────────────
_ir_open_files() {
    local report="$1"
    print_subsection "Open Files & Network Sockets"
    report_section "$report" "Open Files"

    if command -v lsof &>/dev/null; then
        print_info "Top network-related open files:"
        lsof -i -n -P 2>/dev/null | head -25 | while IFS= read -r line; do
            echo -e " ${DIM}$line${RESET}"
        done
        lsof -i -n -P 2>/dev/null >> "$report"
    else
        print_warn "lsof not installed — skipping open files check"
    fi
}

# ── Loaded Kernel Modules ───────────────────────────────────────────────────
_ir_loaded_modules() {
    local report="$1"
    print_subsection "Loaded Kernel Modules"
    report_section "$report" "Kernel Modules"

    lsmod 2>/dev/null | head -30 | while IFS= read -r line; do
        echo -e " ${DIM}$line${RESET}"
    done
    lsmod 2>/dev/null >> "$report"
}

# ── Startup Services ────────────────────────────────────────────────────────
_ir_startup_services() {
    local report="$1"
    print_subsection "Startup Services"
    report_section "$report" "Startup Services"

    if command -v systemctl &>/dev/null; then
        print_info "Running systemd services:"
        systemctl list-units --type=service --state=running 2>/dev/null | head -25 | while IFS= read -r line; do
            echo -e " ${DIM}$line${RESET}"
        done
    fi
}

# ── Shell History ───────────────────────────────────────────────────────────
_ir_env_and_shell() {
    local report="$1"
    print_subsection "Shell History (Recent Commands)"
    report_section "$report" "Shell History"

    local hist_files=(~/.bash_history ~/.zsh_history ~/.sh_history)
    for hf in "${hist_files[@]}"; do
        if [[ -r "$hf" ]]; then
            print_info "Last 20 commands from $hf:"
            tail -20 "$hf" | while IFS= read -r line; do
                echo -e " ${DIM}$line${RESET}"
            done
            {
                echo "=== History from $hf ==="
                tail -20 "$hf"
            } >> "$report"
        fi
    done
}

# ── User Account Audit ──────────────────────────────────────────────────────
_ir_user_account_audit() {
    local report="$1"
    print_subsection "User Account Integrity Check"
    report_section "$report" "User Accounts"

    print_info "Accounts with login shells:"
    grep -vE "(nologin|false)$" /etc/passwd 2>/dev/null | while IFS= read -r line; do
        local user=$(echo "$line" | cut -d: -f1)
        local uid=$(echo "$line" | cut -d: -f3)
        local shell=$(echo "$line" | cut -d: -f7)
        if [[ "$uid" -eq 0 && "$user" != "root" ]]; then
            print_critical "UID 0 account (non-root): $user"
            report_append "$report" "CRITICAL: UID 0 account → $user"
        else
            print_kv " $user (UID $uid)" "$shell"
        fi
        report_append "$report" "User: $user UID:$uid Shell:$shell"
    done

    # Check for multiple UID 0 accounts
    local uid0_count=$(awk -F: '$3==0' /etc/passwd 2>/dev/null | wc -l)
    if [[ $uid0_count -gt 1 ]]; then
        print_critical "Multiple UID 0 accounts detected — possible backdoor!"
        report_append "$report" "CRITICAL: Multiple UID 0 accounts found"
    fi
}

# ── SUID/SGID Audit (Enhanced) ──────────────────────────────────────────────
_ir_suid_sgid_audit() {
    local report="$1"
    print_subsection "SUID / SGID Binary Audit"
    report_section "$report" "SUID/SGID Files"

    print_info "Scanning for SUID/SGID binaries..."

    local suid_files=$(find / -perm -4000 -type f 2>/dev/null | sort | head -40)

    if [[ -n "$suid_files" ]]; then
        echo "$suid_files" | while IFS= read -r file; do
            local perms=$(stat -c "%A" "$file" 2>/dev/null)
            local owner=$(stat -c "%U" "$file" 2>/dev/null)
            echo -e " ${YELLOW}$perms${RESET} ${DIM}$owner${RESET} $file"
            report_append "$report" "SUID: $perms $owner $file"

            if echo "$file" | grep -qvE '^/(usr|bin|sbin|lib)'; then
                print_critical "Unusual SUID location: $file"
                log_alert "INCIDENT" "Unusual SUID binary: $file"
            fi
        done
    else
        print_success "No SUID binaries found"
    fi
}
      
