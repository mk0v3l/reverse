#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <cap.txt>"
  exit 1
fi

f="$1"
if [[ ! -f "$f" ]]; then
  echo "File not found: $f"
  exit 1
fi

# --- Colors (ANSI) ---
RED=$'\033[31m'
YELLOW=$'\033[33m'
CYAN=$'\033[36m'
BOLD=$'\033[1m'
RESET=$'\033[0m'

# Highlight "problematic" tokens (case-insensitive where useful)
highlight_line() {
  local s="$1"

  # Keep it simple: successive replacements.
  # Windows paths contain backslashes; use bash parameter expansions carefully.
  # We'll use sed for robust highlighting.
  printf '%s\n' "$s" | sed -E \
    -e "s/(AppData|Application Data)/${RED}\1${RESET}/Ig" \
    -e "s/(HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)/${RED}\1${RESET}/g" \
    -e "s/(RunOnce|Run|Winlogon|Shell Folders|User Shell Folders|Policies)/${RED}\1${RESET}/Ig" \
    -e "s/(\\\\vboxsrv\\\\|\\?:\\\\vboxsrv\\\\|vboxsrv)/${YELLOW}\1${RESET}/Ig" \
    -e "s/([Cc]:\\\\WINDOWS\\\\system32\\\\cmd\\.exe|[Cc]:\\\\WINDOWS\\\\cmd\\.exe)/${CYAN}\1${RESET}/g" \
    -e "s/(\\\\cmd\\.exe|cmd\\.exe)/${RED}\1${RESET}/Ig" \
    -e "s/(powershell\\.exe|wscript\\.exe|cscript\\.exe|rundll32\\.exe|regsvr32\\.exe|mshta\\.exe|certutil\\.exe|bitsadmin\\.exe|wmic\\.exe|svchost\\.exe)/${RED}\1${RESET}/Ig" \
    -e "s/(Startup|Start Menu|Programs\\\\Startup)/${RED}\1${RESET}/Ig" \
    -e "s/(Temp|TMP|\\\\Temp\\\\)/${YELLOW}\1${RESET}/Ig" \
    -e "s/(\\.ps1|\\.vbs|\\.js|\\.jse|\\.bat|\\.cmd|\\.scr|\\.dll|\\.sys|\\.exe)/${YELLOW}\1${RESET}/Ig"
}

print_section() {
  local title="$1"
  shift
  local -a patterns=("$@")

  echo
  echo "${BOLD}== ${title} ==${RESET}"

  # Build one awk script that:
  # - prints line number + line if it matches any pattern (regex)
  # - then pipes each line to highlight

# Join patterns into ONE string, separated by an uncommon delimiter
pat_joined=""
for i in "${!patterns[@]}"; do
  pat_joined+="${patterns[$i]}"$'\034'   # ASCII FS as separator
done

awk -v OFS=' ' -v pats="$pat_joined" '
  BEGIN {
    IGNORECASE=1
    np = split(pats, p, "\034")
  }
  {
    line=$0
    for (i=1; i<=np; i++) {
      if (p[i] != "" && line ~ p[i]) {
        printf("%d %s\n", NR, line)
        break
      }
    }
  }
' "$f" \
| while IFS= read -r out; do
      # out begins with line number then space then original line
      ln="${out%% *}"
      rest="${out#* }"
      # print line number in bold, then highlighted content
      printf "%s%5s%s %s\n" "$BOLD" "$ln" "$RESET" "$(highlight_line "$rest")"
    done
}

# -------------------------
# Sections you requested
# -------------------------

# 1) New / modified files (Writes etc.) + focus AppData + cmd.exe + suspicious locations
print_section "check new files (Write/Create/Rename/Delete) + AppData/cmd.exe/suspicious paths" \
  '"file","(Write|Create|CreateNewFile|Rename|Delete|SetDisposition|Close|Read)"' \
  '("\\\\(Application Data|AppData)\\\\")' \
  '(\\\\cmd\.exe")' \
  '(\\\\(Startup|Start Menu|Temp|TMP)\\\\)' \
  '(\\.(ps1|vbs|js|jse|bat|cmd|scr|dll|sys|exe)")'

# 2) Registry keys (Run/RunOnce/ShellFolders/AppData/Policies/Winlogon etc.)
print_section "check reg key (Run/RunOnce/Shell Folders/AppData/Policies/Winlogon)" \
  '"registry","(SetValueKey|CreateKey|DeleteKey|DeleteValue|RenameKey)"' \
  'HK(CU|LM)\\Software\\Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce)' \
  'HK(CU|LM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\(Shell Folders|User Shell Folders)' \
  'HK(CU|LM)\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' \
  'HK(CU|LM)\\Software\\(Policies|Classes|Wow6432Node)'

# 3) Processes (created/terminated) + suspicious parents/children + LOLBins
print_section "check process (created/terminated) + LOLBins + cmd.exe in AppData" \
  '"process","(created|terminated)"' \
  '(\\\\(cmd|powershell|wscript|cscript|rundll32|regsvr32|mshta|certutil|bitsadmin|wmic)\.exe")' \
  '("\\\\(Application Data|AppData)\\\\.*\.exe")' \
  '(\\?:\\\\vboxsrv\\\\)'

# 4) Network (if your capture has it)
print_section "check network (connect/dns/http/https) (if present)" \
  '"network","' \
  '(DNS|dns|http|https|Connect|connect|TCP|UDP)'

# 5) Everything mentioning AppData / Application Data (high-signal pivot)
print_section "extra: everything touching AppData / Application Data" \
  '(\\\\(Application Data|AppData)\\\\)'

echo
echo "${BOLD}Done.${RESET} Tip: redirect output to a report: ./capcheck.sh cap.txt | tee cap_report.txt"
