#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Centralized Logging Utility
# utils/logger.sh
# =============================================================================

# ── Log Config ────────────────────────────────────────────────────────────────
SENTRYCLI_LOG_DIR="${SENTRYCLI_ROOT}/reports"
SENTRYCLI_LOG_FILE="${SENTRYCLI_LOG_DIR}/sentrycli_audit.log"
SENTRYCLI_SESSION_ID="$(date +%Y%m%d_%H%M%S)_$$"

# Ensure log directory exists
mkdir -p "$SENTRYCLI_LOG_DIR"

# ── Internal Log Writer ───────────────────────────────────────────────────────
_log_write() {
    local level="$1"
    local module="$2"
    local message="$3"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${timestamp}] [${level}] [SESSION:${SENTRYCLI_SESSION_ID}] [${module}] ${message}" \
        >> "$SENTRYCLI_LOG_FILE"
}

# ── Public Log Functions ──────────────────────────────────────────────────────

log_info() {
    local module="${1:-MAIN}"
    local message="$2"
    _log_write "INFO    " "$module" "$message"
}

log_warn() {
    local module="${1:-MAIN}"
    local message="$2"
    _log_write "WARNING " "$module" "$message"
}

log_alert() {
    local module="${1:-MAIN}"
    local message="$2"
    _log_write "ALERT   " "$module" "$message"
}

log_error() {
    local module="${1:-MAIN}"
    local message="$2"
    _log_write "ERROR   " "$module" "$message"
}

log_success() {
    local module="${1:-MAIN}"
    local message="$2"
    _log_write "SUCCESS " "$module" "$message"
}

log_critical() {
    local module="${1:-MAIN}"
    local message="$2"
    _log_write "CRITICAL" "$module" "$message"
}

# ── Session Management ────────────────────────────────────────────────────────

log_session_start() {
    local module="${1:-MAIN}"
    _log_write "SESSION " "$module" "═══ SESSION START ═══ PID:$$ USER:$(whoami) HOST:$(hostname)"
}

log_session_end() {
    local module="${1:-MAIN}"
    _log_write "SESSION " "$module" "═══ SESSION END   ═══ PID:$$"
}

# ── Report Generator ──────────────────────────────────────────────────────────

# Initialize a named report file, return its path
report_init() {
    local name="$1"
    local timestamp
    timestamp="$(date '+%Y%m%d_%H%M%S')"
    local report_path="${SENTRYCLI_LOG_DIR}/${name}_${timestamp}.txt"
    echo "# SentryCLI Report: ${name}" > "$report_path"
    echo "# Generated  : $(date '+%Y-%m-%d %H:%M:%S')" >> "$report_path"
    echo "# Session ID : ${SENTRYCLI_SESSION_ID}" >> "$report_path"
    echo "# Host       : $(hostname)" >> "$report_path"
    echo "# User       : $(whoami)" >> "$report_path"
    echo "#$(printf '%.0s─' {1..70})" >> "$report_path"
    echo ""  >> "$report_path"
    echo "$report_path"   # Return the path
}

# Append a section to an existing report
report_section() {
    local report_path="$1"
    local section_title="$2"
    {
        echo ""
        echo "## ${section_title}"
        echo "## Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "#$(printf '%.0s─' {1..50})"
    } >> "$report_path"
}

# Append raw content to a report
report_append() {
    local report_path="$1"
    shift
    echo "$*" >> "$report_path"
}

# Append a file's contents to a report
report_append_file() {
    local report_path="$1"
    local file="$2"
    if [[ -f "$file" ]]; then
        cat "$file" >> "$report_path"
    fi
}

# Print a summary of the report to terminal
report_finalize() {
    local report_path="$1"
    echo "" >> "$report_path"
    echo "#$(printf '%.0s─' {1..70})" >> "$report_path"
    echo "# END OF REPORT" >> "$report_path"
    print_success "Report saved → ${report_path}"
    log_info "REPORT" "Report finalized: ${report_path}"
}
