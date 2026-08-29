
set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATION_DIR="$REPO_DIR/validation"
EVIDENCE_DIR="$VALIDATION_DIR/final_report_evidence"

TARGET="${TARGET:-192.168.10.104}"
SECOND_TARGET="${SECOND_TARGET:-192.168.10.100}"
WORDLIST="${WORDLIST:-/tmp/wl_small.txt}"
HYDRA_USER="${HYDRA_USER:-root}"
EICAR_URL="${EICAR_URL:-}"

mkdir -p "$EVIDENCE_DIR"

timestamp() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

banner() {
    echo
    echo "============================================================"
    echo "$1"
    echo "UTC: $(timestamp)"
    echo "============================================================"
    echo
}

pause_for_screenshots() {
    echo
    echo "================ TAKE SCREENSHOTS NOW ================"
    echo "1. KALI: this terminal, command + result + UTC time"
    echo "2. WAZUH: matching event/rule"
    echo "3. KAFKA/CORRELATION: resulting incident if present"
    echo "4. DASHBOARD: resulting incident if present"
    echo "========================================================"
    read -r -p "Press ENTER after screenshots are taken..."
}

run_logged() {
    local scenario="$1"
    local attack_class="$2"
    local command="$3"
    local target="$4"
    local note="$5"
    local logfile="$EVIDENCE_DIR/${scenario}_kali.txt"

    {
        echo "SCENARIO=$scenario"
        echo "CLASS=$attack_class"
        echo "TARGET=$target"
        echo "START_UTC=$(timestamp)"
        echo "COMMAND=$command"
        echo "NOTE=$note"
        echo "----- EXECUTION -----"
    } | tee "$logfile"

    python3 "$VALIDATION_DIR/06_run_logger.py"         --scenario "$scenario"         --class "$attack_class"         --cmd "$command"         --target "$target"         --note "$note" 2>&1 | tee -a "$logfile"

    echo "END_UTC=$(timestamp)" | tee -a "$logfile"
    echo "Saved: $logfile"
}

cd "$REPO_DIR" || exit 1

banner "0/6 PRECHECK"
echo "Repository: $REPO_DIR"
echo "Target: $TARGET"
echo "Second target: $SECOND_TARGET"
echo "Wordlist: $WORDLIST"
echo
whoami
hostname
ip -br addr
echo
command -v python3 || true
command -v nmap || true
command -v hydra || true

if [[ ! -f "$VALIDATION_DIR/06_run_logger.py" ]]; then
    echo "ERROR: validation/06_run_logger.py not found."
    exit 1
fi

if [[ ! -f "$WORDLIST" ]]; then
    echo "ERROR: wordlist not found: $WORDLIST"
    echo "Set WORDLIST=/path/to/wordlist.txt and rerun."
    exit 1
fi

read -r -p "Press ENTER to start..."

banner "1/6 BRUTE FORCE"
run_logged "BRUTE-01" "brute_force"     "timeout 45 hydra -l $HYDRA_USER -P $WORDLIST -t 4 ssh://$TARGET"     "$TARGET" "single controlled evidence run for final PFE report"
pause_for_screenshots

banner "2/6 RECONNAISSANCE"
run_logged "RECON-01" "reconnaissance"     "timeout 75 nmap -sV -T4 -p- $TARGET"     "$TARGET" "single controlled evidence run for final PFE report"
pause_for_screenshots

banner "3/6 ALERT STORM"
run_logged "DOS-01" "alert_storm"     "timeout 30 nmap -sS -T5 --min-rate 1000 -p 1-2000 $TARGET"     "$TARGET" "single controlled high-rate scan for final PFE report"
pause_for_screenshots

banner "4/6 PRIVILEGE-ESCALATION TELEMETRY"
PRIV_LOG="$EVIDENCE_DIR/PRIVESC-01_kali.txt"
{
    echo "SCENARIO=PRIVESC-01"
    echo "CLASS=privilege_escalation"
    echo "START_UTC=$(timestamp)"
    echo "----- IDENTITY -----"
    whoami
    id
    echo "----- SUDO CONFIGURATION -----"
    sudo -l
    echo "----- SESSION -----"
    who
    echo "END_UTC=$(timestamp)"
} 2>&1 | tee "$PRIV_LOG"
echo "Saved: $PRIV_LOG"
echo "NOTE: repository marks the expected privilege-escalation Wazuh rule as TBD."
echo "This collects privilege-related telemetry; it does not claim CORR-002 validation."
pause_for_screenshots

banner "5/6 LATERAL-MOVEMENT TELEMETRY"
LAT_LOG="$EVIDENCE_DIR/LATERAL-01_kali.txt"
{
    echo "SCENARIO=LATERAL-01"
    echo "CLASS=lateral_movement"
    echo "SOURCE=$(hostname)"
    echo "START_UTC=$(timestamp)"
    echo "----- TARGET 1: $TARGET -----"
    timeout 5 ssh -o ConnectTimeout=3 -o ConnectionAttempts=1         -o StrictHostKeyChecking=no -o PreferredAuthentications=none         "$TARGET" 2>&1 || true
    echo "----- TARGET 2: $SECOND_TARGET -----"
    timeout 5 ssh -o ConnectTimeout=3 -o ConnectionAttempts=1         -o StrictHostKeyChecking=no -o PreferredAuthentications=none         "$SECOND_TARGET" 2>&1 || true
    echo "END_UTC=$(timestamp)"
} 2>&1 | tee "$LAT_LOG"
echo "Saved: $LAT_LOG"
echo "NOTE: repository marks the expected lateral-movement Wazuh rule as TBD."
echo "This collects connection telemetry; it does not claim CORR-003 validation."
pause_for_screenshots

banner "6/6 EICAR TEST"
if [[ -z "$EICAR_URL" ]]; then
    echo "EICAR_URL is not configured; no download performed."
    echo "The repository defines MALWARE-01 and expects Wazuh rule 1002."
    echo "Set EICAR_URL to the URL already approved/configured in your lab."
else
    MAL_LOG="$EVIDENCE_DIR/MALWARE-01_kali.txt"
    {
        echo "SCENARIO=MALWARE-01"
        echo "CLASS=malware"
        echo "START_UTC=$(timestamp)"
        curl -fL --max-time 30 -o /tmp/eicar.com "$EICAR_URL"
        ls -lh /tmp/eicar.com 2>&1 || true
        echo "END_UTC=$(timestamp)"
    } 2>&1 | tee "$MAL_LOG"
    rm -f /tmp/eicar.com
    echo "Saved: $MAL_LOG"
    pause_for_screenshots
fi

banner "KALI EVIDENCE RUNS COMPLETE"
echo "Evidence directory: $EVIDENCE_DIR"
find "$EVIDENCE_DIR" -maxdepth 1 -type f -printf '%f\n' | sort
echo
echo "Do not rerun the scenarios until we review Wazuh/Kafka results."