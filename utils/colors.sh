#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Color & Output Utilities
# utils/colors.sh
# =============================================================================

# ── ANSI Color Codes ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_YELLOW='\033[43m'
BG_BLUE='\033[44m'

# ── Print Functions ───────────────────────────────────────────────────────────

print_info() {
    echo -e "${CYAN}  ●${RESET}  ${WHITE}$1${RESET}"
}

print_success() {
    echo -e "${GREEN}  ✔${RESET}  ${GREEN}$1${RESET}"
}

print_warn() {
    echo -e "${YELLOW}  ⚠${RESET}  ${YELLOW}$1${RESET}"
}

print_alert() {
    echo -e "${RED}  !${RESET}  ${RED}${BOLD}$1${RESET}"
}

print_critical() {
    echo -e "${BG_RED}${WHITE}${BOLD}  ✘ CRITICAL  ${RESET}  ${RED}${BOLD}$1${RESET}"
}

# Section header — clean single-line style
print_section() {
    echo ""
    echo -e "${BLUE}${BOLD}  ╔══ $1${RESET}"
    echo -e "${BLUE}${DIM}  ╚$(printf '%.0s─' {1..52})${RESET}"
}

# Subsection — indented, lighter
print_subsection() {
    echo ""
    echo -e "${CYAN}  ▸  ${BOLD}$1${RESET}"
}

# Key-Value pair — aligned, compact
print_kv() {
    printf "    ${DIM}%-26s${RESET} ${WHITE}%s${RESET}\n" "$1" "$2"
}

# Table row for port scan results
print_port_row() {
    # $1=port/proto  $2=state  $3=service  $4=version  $5=risk_color
    local col="${5:-$WHITE}"
    printf "    ${col}%-18s${RESET}  ${GREEN}%-8s${RESET}  ${CYAN}%-14s${RESET}  ${DIM}%s${RESET}\n" \
        "$1" "$2" "$3" "$4"
}

# Table header for port scan
print_port_header() {
    echo ""
    printf "    ${BOLD}${WHITE}%-18s  %-8s  %-14s  %s${RESET}\n" \
        "PORT" "STATE" "SERVICE" "VERSION / BANNER"
    echo -e "    ${DIM}$(printf '%.0s─' {1..70})${RESET}"
}

print_divider() {
    echo -e "${DIM}    $(printf '%.0s─' {1..54})${RESET}"
}

# ── Banner — called ONCE from main() ─────────────────────────────────────────
print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
  ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗ ██████╗██╗     ██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝██╔════╝██║     ██║
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ ██║     ██║     ██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  ██║     ██║     ██║
  ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   ╚██████╗███████╗██║
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚══════╝╚═╝
EOF
    echo -e "${RESET}"
    echo -e "  ${DIM}Modular Security Operations & Penetration Testing Toolkit${RESET}"
    echo -e "  ${DIM}v1.0.0  ·  $(date '+%Y-%m-%d %H:%M')  ·  $(whoami)@$(hostname 2>/dev/null || echo localhost)${RESET}"
    echo -e "  ${DIM}$(printf '%.0s─' {1..60})${RESET}"
    echo ""
}

# ── Spinner ───────────────────────────────────────────────────────────────────
spinner_start() {
    local msg="${1:-Working...}"
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    (
        while true; do
            i=$(( (i+1) % 10 ))
            printf "\r${CYAN}${BOLD}    ${spin:$i:1}  ${RESET}${DIM}%s${RESET}" "$msg"
            sleep 0.1
        done
    ) &
    SPINNER_PID=$!
}

spinner_stop() {
    if [[ -n "${SPINNER_PID:-}" ]]; then
        kill "$SPINNER_PID" 2>/dev/null
        wait "$SPINNER_PID" 2>/dev/null
        printf "\r%-70s\r" " "
        unset SPINNER_PID
    fi
}
