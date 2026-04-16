#!/usr/bin/env bash
# =============================================================================
# SentryCLI - Hash Threat Intelligence Module
# modules/hashcheck.sh
# =============================================================================

# ── Module Entry Point ────────────────────────────────────────────────────────
run_hashcheck() {
    print_section "5. HASH THREAT INTELLIGENCE [HASH-5]"

    local input=""

    # Parse arguments / REPL support
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hash)
                input="$2"
                shift 2
                ;;
            --clear-hash|--unset-hash|--clear|--unset)
                unset HASH 2>/dev/null || true
                print_success "Hash cleared from REPL session"
                return 0
                ;;
            *)
                print_alert "Unknown option: $1"
                echo "Usage: --hash <HASH>"
                return 1
                ;;
        esac
    done

    # REPL set support
    if [[ -z "$input" && -n "${HASH:-}" ]]; then
        input="${HASH}"
        print_info "Using REPL-set HASH → ${input}"
    fi

    # Interactive fallback
    if [[ -z "$input" ]]; then
        echo -ne "${CYAN}Enter File Hash: ${RESET}"
        read -r input
    fi

    [[ -z "$input" ]] && { print_alert "No hash provided."; return 1; }
    input=$(echo "$input" | tr -d '[:space:]')

    # Load config
    local conf_file="${SENTRYCLI_ROOT}/config/api_keys.conf"
    [[ -f "$conf_file" ]] && source "$conf_file" || print_warn "Config file not found"

    echo ""
    print_subsection "API Key Status"
    local virustotal_ok=0
    _hash_verify_api_key "VirusTotal" "${VIRUSTOTAL_API_KEY:-}" && virustotal_ok=1

    local report
    report=$(report_init "hashcheck")

    print_subsection "Analyzing HASH → ${input}"
    _hashcheck_analyze "$input" "$report" "$virustotal_ok"

    report_finalize "$report"
    log_success "HASHCHECK" "Analysis completed successfully"

    echo ""
    echo -ne "${CYAN}Press ENTER to return to SentryCLI REPL...${RESET}"
    read -r
}

# ── Helpers (extracted & fixed from your original code) ───────────────────────
_hash_verify_api_key() {
    local service="$1" key="$2"
    if [[ -z "$key" ]]; then
        print_warn " [${service}] No API key configured"
        return 1
    fi
    print_success " [${service}] API key loaded (...${key: -4})"
    return 0
}

_json_get() {
    local json="$1" key="$2"
    if command -v python3 &>/dev/null; then
        echo "$json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    keys = '$key'.split('.')
    v = d
    for k in keys:
        v = v.get(k) if isinstance(v, dict) else ''
    print(v if v is not None else '')
except:
    print('')
" 2>/dev/null
    else
        echo "$json" | grep -o "\"${key}\":[^,}]*" | head -1 | sed 's/^\"[^\"]*\":[[:space:]]*//' | tr -d '"'
    fi
}

_report_add() {
    local report="$1"
    local line="$2"
    [[ -n "$report" && -f "$report" ]] || return
    echo -e "$line" >> "$report"
}

_report_add_kv() {
    local report="$1"
    local key="$2"
    local value="$3"
    _report_add "$report" "**${key}**: ${value}"
}

# ── Robust Curl (renamed to avoid conflict with ipcheck) ─────────────────────
_hash_curl_request() {
    local label="$1"
    local url="$2"
    shift 2
    local tmp_body=$(mktemp /tmp/sentry_body_XXXX.json 2>/dev/null)
    local tmp_err=$(mktemp /tmp/sentry_err_XXXX.txt 2>/dev/null)

    http_code=$(curl -4 -s --retry 3 --retry-delay 2 --max-time 30 \
        -w "%{http_code}" -o "$tmp_body" "${@}" "$url" 2>"$tmp_err")
    local body=$(cat "$tmp_body" 2>/dev/null || echo "")
    rm -f "$tmp_body" "$tmp_err"

    if [[ "$http_code" != "200" || -z "$body" ]]; then
        print_alert " [${label}] Failed (HTTP ${http_code})"
        return 1
    fi
    echo "$body"
    return 0
}

# ── FULL ENHANCED VirusTotal Report (All 11 required sections added) ─────────
_report_add_virustotal_human() {
    local report="$1"
    local vt_body="$2"
    local hash="$3"

    [[ -z "$vt_body" || ! -f "$report" ]] && return

    _report_add "$report" ""
    _report_add "$report" "### VirusTotal Human-Readable Summary"

    # Auto-detect hash type
    local hash_type="Unknown"
    case ${#hash} in
        32) hash_type="MD5" ;;
        40) hash_type="SHA1" ;;
        64) hash_type="SHA256" ;;
        128) hash_type="SHA512" ;;
    esac

    local malicious suspicious harmless undetected size file_type magic first_seen last_analysis popular_threat
    malicious=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0))' 2>/dev/null)
    suspicious=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("suspicious",0))' 2>/dev/null)
    harmless=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("harmless",0))' 2>/dev/null)
    undetected=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("undetected",0))' 2>/dev/null)
    size=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("size",0))' 2>/dev/null)
    file_type=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("type_description","Unknown"))' 2>/dev/null)
    magic=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("magic","Unknown"))' 2>/dev/null)
    first_seen=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("first_submission_date","N/A"))' 2>/dev/null)
    last_analysis=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_date","N/A"))' 2>/dev/null)
    popular_threat=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("popular_threat_classification",{}).get("suggested_threat_label","None"))' 2>/dev/null)

    _report_add_kv "$report" "Hash" "$hash"
    _report_add_kv "$report" "Hash Type" "$hash_type"
    _report_add_kv "$report" "File Type" "$file_type"
    _report_add_kv "$report" "Magic" "$magic"
    _report_add_kv "$report" "File Size" "$((size/1024)) KB"
    _report_add_kv "$report" "First Seen" "$first_seen"
    _report_add_kv "$report" "Last Analysis" "$last_analysis"
    _report_add_kv "$report" "Popular Threat Label" "${popular_threat:-None}"

    _report_add "$report" ""
    _report_add "$report" "#### Detection Statistics"
    _report_add_kv "$report" "Malicious" "${malicious}"
    _report_add_kv "$report" "Suspicious" "${suspicious}"
    _report_add_kv "$report" "Harmless" "${harmless}"
    _report_add_kv "$report" "Undetected" "${undetected}"

    # Known File Names
    _report_add "$report" ""
    _report_add "$report" "#### Known File Names"
    echo "$vt_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    names = d.get("data",{}).get("attributes",{}).get("names", [])[:8]
    if names:
        for name in names: print(f"• {name}")
    else:
        print("No file names available.")
except:
    print("Could not parse file names.")
' >> "$report" 2>/dev/null

    # ── ALL REQUIRED NEW SECTIONS (exactly as you asked) ─────────────────────
    _report_add "$report" ""
    _report_add "$report" "### Extended Hash Intelligence"
    echo "$vt_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    attr = d.get("data", {}).get("attributes", {})
    print(f"**SHA256**: {attr.get("sha256") or "N/A"}")
    print(f"**SHA1**: {attr.get("sha1") or "N/A"}")
    print(f"**TLSH**: {attr.get("tlsh") or "N/A"}")
    print(f"**SSDEEP**: {attr.get("ssdeep") or "N/A"}")
    print(f"**VHASH**: {attr.get("vhash") or "N/A"}")
except:
    print("Could not parse extended hash intelligence.")
' >> "$report" 2>/dev/null

    _report_add "$report" ""
    _report_add "$report" "### File Intelligence"
    echo "$vt_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    attr = d.get("data", {}).get("attributes", {})
    print(f"**Type Extension**: {attr.get("type_extension", "N/A")}")
    print(f"**Magic**: {attr.get("magic", "N/A")}")
    size = attr.get("size", 0)
    print(f"**Size**: {size} bytes ({size//1024 if size else 0} KB)")
    tags = attr.get("type_tags", [])
    print(f"**Type Tags**: {", ".join(str(t) for t in tags) if tags else "N/A"}")
    packers = attr.get("packers", {})
    print(f"**Packers**: {", ".join(f"{k}({v})" for k,v in packers.items()) if packers else "N/A"}")
    trid = attr.get("trid", [])
    if trid:
        print("**TRID Results**:")
        for t in trid[:8]:
            print(f"   • {t.get("file_type","Unknown")} ({t.get("probability",0)*100:.1f}%)")
    else:
        print("**TRID Results**: N/A")
except:
    print("Could not parse file intelligence.")
' >> "$report" 2>/dev/null

    _report_add "$report" ""
    _report_add "$report" "### Archive Content Analysis"
    echo "$vt_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    attr = d.get("data", {}).get("attributes", {})
    b = attr.get("bundle_info", {}) or {}
    print(f"**Number of Children**: {b.get("num_children", "N/A")}")
    print(f"**Extensions**: {", ".join(str(x) for x in b.get("extensions", [])) if b.get("extensions") else "N/A"}")
    print(f"**File Types**: {", ".join(str(x) for x in b.get("file_types", [])) if b.get("file_types") else "N/A"}")
    print(f"**Uncompressed Size**: {b.get("uncompressed_size", "N/A")} bytes")
except:
    print("Could not parse archive content analysis.")
' >> "$report" 2>/dev/null

    _report_add "$report" ""
    _report_add "$report" "### Malware Classification"
    echo "$vt_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    attr = d.get("data", {}).get("attributes", {})
    ptc = attr.get("popular_threat_classification", {}) or {}
    print(f"**Suggested Threat Label**: {ptc.get("suggested_threat_label", "None")}")
    print(f"**Popular Threat Category**: {attr.get("popular_threat_category") or ptc.get("popular_threat_category") or "N/A"}")
    print(f"**Popular Threat Name**: {attr.get("popular_threat_name") or ptc.get("popular_threat_name") or "N/A"}")
except:
    print("Could not parse malware classification.")
' >> "$report" 2>/dev/null

    _report_add "$report" ""
    _report_add "$report" "### Behavioral Indicators"
    echo "$vt_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    tags = d.get("data",{}).get("attributes",{}).get("tags", [])
    print(f"**Tags**: {", ".join(str(t) for t in tags[:15]) if tags else "No behavioral indicators"}")
except:
    print("Could not parse behavioral indicators.")
' >> "$report" 2>/dev/null

    _report_add "$report" ""
    _report_add "$report" "### Sigma Detection Rules"
    echo "$vt_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    attr = d.get("data", {}).get("attributes", {})
    stats = attr.get("sigma_analysis_stats", {})
    if stats:
        print("**Sigma Analysis Stats**:")
        for k,v in stats.items(): print(f"   • {k}: {v}")
    results = attr.get("sigma_analysis_results", [])
    if results:
        print("**Sigma Rules**:")
        for r in results[:5]:
            print(f"   • **{r.get("rule_title","Untitled")}**")
            print(f"     {str(r.get("rule_description",""))[:200]}")
except:
    print("Could not parse sigma detection rules.")
' >> "$report" 2>/dev/null

    _report_add "$report" ""
    _report_add "$report" "### Top AV Detections"
    echo "$vt_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    results = d.get("data",{}).get("attributes",{}).get("last_analysis_results", {})
    malicious = [f"{eng}: {info.get("result","malicious")}" for eng,info in results.items() if isinstance(info,dict) and info.get("category")=="malicious"]
    print("**Top Malicious Detections (first 10)**:")
    for m in malicious[:10]:
        print(f"   • {m}")
    if not malicious:
        print("No malicious detections found.")
except:
    print("Could not parse top AV detections.")
' >> "$report" 2>/dev/null

    _report_add "$report" ""
    _report_add "$report" "### Submission History"
    echo "$vt_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    attr = d.get("data", {}).get("attributes", {})
    print(f"**First Submission Date**: {attr.get("first_submission_date","N/A")}")
    print(f"**Last Submission Date**: {attr.get("last_submission_date","N/A")}")
    print(f"**Times Submitted**: {attr.get("times_submitted","N/A")}")
    print(f"**Unique Sources**: {attr.get("unique_sources","N/A")}")
except:
    print("Could not parse submission history.")
' >> "$report" 2>/dev/null

    _report_add "$report" ""
    _report_add "$report" "### Community Reputation"
    echo "$vt_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    attr = d.get("data", {}).get("attributes", {})
    print(f"**Reputation**: {attr.get("reputation","N/A")}")
    votes = attr.get("total_votes", {})
    print(f"**Total Votes**: Harmless {votes.get("harmless",0)} / Malicious {votes.get("malicious",0)}")
except:
    print("Could not parse community reputation.")
' >> "$report" 2>/dev/null

    _report_add "$report" ""
    _report_add "$report" "### Improved Detection Statistics"
    echo "$vt_body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    stats = d.get("data",{}).get("attributes",{}).get("last_analysis_stats", {})
    print("**Extended Last Analysis Stats**:")
    for k in ["malicious","undetected","failure","timeout","type-unsupported"]:
        print(f"   • {k.capitalize()}: {stats.get(k,0)}")
except:
    print("Could not parse improved detection statistics.")
' >> "$report" 2>/dev/null

    _report_add "$report" "---"
}

# ── Hash Analysis Core ───────────────────────────────────────────────────────
_hashcheck_analyze() {
    local hash="$1"
    local report="$2"
    local vt_ok="$3"

    if [[ $vt_ok -ne 1 ]]; then
        print_alert "VirusTotal API key is required for hash analysis"
        echo "VERDICT:HASH_ERROR"
        return
    fi

    print_info " Querying VirusTotal..."
    local vt_body
    vt_body=$(_hash_curl_request "VirusTotal" \
        "https://www.virustotal.com/api/v3/files/${hash}" \
        -H "x-apikey: ${VIRUSTOTAL_API_KEY}")

    if [[ $? -ne 0 || -z "$vt_body" ]]; then
        print_alert "Failed to retrieve VirusTotal report"
        echo "VERDICT:HASH_ERROR"
        return
    fi

    local malicious suspicious
    malicious=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0))' 2>/dev/null)
    suspicious=$(echo "$vt_body" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("suspicious",0))' 2>/dev/null)

    print_kv " [VirusTotal] Malicious engines" "${malicious}"
    print_kv " [VirusTotal] Suspicious engines" "${suspicious}"

    _report_add_virustotal_human "$report" "$vt_body" "$hash"

    local score=0
    if [[ "${malicious}" -ge 5 ]]; then
        print_critical " VERDICT: ★ MALICIOUS FILE"
        score=90
    elif [[ "${malicious}" -gt 0 || "${suspicious}" -gt 0 ]]; then
        print_alert " VERDICT: ⚠ SUSPICIOUS FILE"
        score=55
    else
        print_success " VERDICT: CLEAN FILE"
        score=10
    fi

    print_kv " Threat Score" "${score}/100"
    _report_add_kv "$report" "Final Threat Score" "${score}/100"
    _report_add_kv "$report" "Verdict" "HASH_${score}"
    _report_add "$report" "**Analysis completed on:** $(date '+%Y-%m-%d %H:%M:%S %Z')"

    echo "VERDICT:HASH_${score}"
}
                                                
