#!/bin/bash
# =====================================================================
# SecToolkit (Bash)
# Modes:  logs      -> Log Analyzer (SSH auth logs)
#         integrity -> File Integrity Checker (SHA-256 baseline)
# Requires: bash 4+, grep, awk, sort, find, sha256sum
# =====================================================================

VERSION="1.0"
BRUTE_FORCE_THRESHOLD=5   # failed attempts from one IP before we raise a warning

# ---------------------------------------------------------------------
# usage: print help text and exit
# ---------------------------------------------------------------------
usage() {
  cat <<EOF
SecToolkit v$VERSION - Log Analyzer + File Integrity Checker

USAGE:
  $0 logs <logfile>
  $0 integrity create <directory> <baseline_file>
  $0 integrity check  <directory> <baseline_file>
  $0 -h | --help

EXAMPLES:
  $0 logs /var/log/auth.log
  $0 integrity create /etc/ssh ssh_baseline.txt
  $0 integrity check  /etc/ssh ssh_baseline.txt
EOF
  exit 1
}

# ---------------------------------------------------------------------
# die: print an error message and exit with failure code
# ---------------------------------------------------------------------
die() {
  echo "[ERROR] $1" >&2
  exit 2
}

# ---------------------------------------------------------------------
# analyze_logs: summarise failed logins, attackers and sudo usage
# $1 = path to log file
# ---------------------------------------------------------------------
analyze_logs() {
  local logfile="$1"

  # --- input validation ---
  [[ -z "$logfile" ]]  && die "No log file given. Try: $0 logs /var/log/auth.log"
  [[ ! -f "$logfile" ]] && die "File not found: $logfile"
  [[ ! -r "$logfile" ]] && die "Cannot read $logfile (try running with sudo)"

  # --- counters (grep -c counts matching lines) ---
  local failed invalid accepted sudo_count
  failed=$(grep -c "sshd[^:]*: Failed password" "$logfile")
  invalid=$(grep -c "sshd[^:]*: Invalid user" "$logfile")
  accepted=$(grep -c "sshd[^:]*: Accepted " "$logfile")
  sudo_count=$(grep -c "COMMAND=" "$logfile")

  echo "=============================================="
  echo " LOG ANALYSIS REPORT"
  echo " File: $logfile"
  echo " Date: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "=============================================="
  echo "Failed password attempts : $failed"
  echo "Invalid user attempts    : $invalid"
  echo "Successful logins        : $accepted"
  echo "Sudo commands logged     : $sudo_count"

  # --- top attacking IPs ---
  # 1) keep only failed lines  2) pull out "from <IP>"  3) count duplicates
  echo
  echo "--- Top 5 source IPs of failed logins ---"
  local top_ips
  top_ips=$(grep "sshd[^:]*: Failed password" "$logfile" \
            | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' \
            | awk '{print $2}' | sort | uniq -c | sort -rn | head -5)
  if [[ -z "$top_ips" ]]; then
    echo "(none found)"
  else
    echo "$top_ips" | awk '{printf "  %-6s attempts  <-  %s\n", $1, $2}'
  fi

  # --- most targeted usernames ---
  echo
  echo "--- Top 5 targeted usernames ---"
  local top_users
  top_users=$(grep "sshd[^:]*: Failed password for" "$logfile" \
              | sed -E 's/.*Failed password for (invalid user )?([^ ]+) from.*/\2/' \
              | sort | uniq -c | sort -rn | head -5)
  if [[ -z "$top_users" ]]; then
    echo "(none found)"
  else
    echo "$top_users" | awk '{printf "  %-6s attempts  ->  %s\n", $1, $2}'
  fi

  # --- brute-force warning: any IP at or above the threshold ---
  echo
  echo "--- Brute-force check (threshold: $BRUTE_FORCE_THRESHOLD) ---"
  local suspects
  suspects=$(echo "$top_ips" | awk -v t="$BRUTE_FORCE_THRESHOLD" '$1 >= t {print $2 " (" $1 " attempts)"}')
  if [[ -n "$suspects" ]]; then
    echo "[WARNING] Possible brute-force sources:"
    echo "$suspects" | sed 's/^/   - /'
  else
    echo "[OK] No IP exceeded the threshold."
  fi
}

# ---------------------------------------------------------------------
# integrity_create: store SHA-256 hash of every file in a directory
# $1 = directory   $2 = baseline file to write
# ---------------------------------------------------------------------
integrity_create() {
  local dir="$1" baseline="$2"

  # find walks the tree; sort makes the output stable between runs
  # -print0 / -0 keeps filenames with spaces safe
  find "$dir" -type f -print0 | sort -z | xargs -0 sha256sum > "$baseline" 2>/dev/null \
    || die "Could not write baseline to $baseline"

  # the baseline must not list itself (it changes every time it is written)
  local baseline_abs; baseline_abs=$(realpath -m "$baseline")
  grep -vF "  $baseline_abs" "$baseline" > "$baseline.tmp" && mv "$baseline.tmp" "$baseline"

  echo "[OK] Baseline created: $baseline"
  echo "     Files recorded : $(wc -l < "$baseline")"
}

# ---------------------------------------------------------------------
# integrity_check: compare current hashes against the baseline
# $1 = directory   $2 = baseline file
# ---------------------------------------------------------------------
integrity_check() {
  local dir="$1" baseline="$2"
  [[ ! -f "$baseline" ]] && die "Baseline file not found: $baseline (run 'create' first)"

  local baseline_abs; baseline_abs=$(realpath -m "$baseline")

  # associative arrays: path -> hash (needs bash 4+)
  declare -A old_hash new_hash
  local hash path

  # load baseline
  while read -r hash path; do
    old_hash["$path"]="$hash"
  done < "$baseline"

  # hash the directory as it is right now
  while read -r hash path; do
    [[ "$path" == "$baseline_abs" ]] && continue
    new_hash["$path"]="$hash"
  done < <(find "$dir" -type f -print0 | xargs -0 sha256sum 2>/dev/null)

  local modified=0 deleted=0 added=0

  echo "=============================================="
  echo " FILE INTEGRITY CHECK"
  echo " Directory: $dir"
  echo " Baseline : $baseline"
  echo "=============================================="

  # modified or deleted: walk the baseline
  for path in "${!old_hash[@]}"; do
    if [[ -z "${new_hash[$path]}" ]]; then
      echo "[DELETED]  $path"; ((deleted++))
    elif [[ "${new_hash[$path]}" != "${old_hash[$path]}" ]]; then
      echo "[MODIFIED] $path"; ((modified++))
    fi
  done

  # new: in current scan but not in baseline
  for path in "${!new_hash[@]}"; do
    if [[ -z "${old_hash[$path]}" ]]; then
      echo "[NEW]      $path"; ((added++))
    fi
  done

  echo "----------------------------------------------"
  echo "Modified: $modified   Deleted: $deleted   New: $added"
  if (( modified + deleted + added == 0 )); then
    echo "[OK] All files match the baseline."
  else
    echo "[WARNING] Changes detected!"
    return 1
  fi
}

# ---------------------------------------------------------------------
# integrity_mode: validate arguments, then dispatch create/check
# $1 = action  $2 = directory  $3 = baseline
# ---------------------------------------------------------------------
integrity_mode() {
  local action="$1" dir="$2" baseline="$3"

  [[ -z "$action" || -z "$dir" || -z "$baseline" ]] && usage
  [[ ! -d "$dir" ]] && die "Not a directory: $dir"

  case "$action" in
    create) integrity_create "$dir" "$baseline" ;;
    check)  integrity_check  "$dir" "$baseline" ;;
    *)      die "Unknown integrity action: $action (use create or check)" ;;
  esac
}

# ---------------------------------------------------------------------
# main: choose a mode from the first argument
# ---------------------------------------------------------------------
case "$1" in
  logs)         analyze_logs "$2" ;;
  integrity)    integrity_mode "$2" "$3" "$4" ;;
  -h|--help|"") usage ;;
  *)            echo "Unknown mode: $1"; usage ;;
esac
