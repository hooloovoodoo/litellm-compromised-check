#!/usr/bin/env bash
# =============================================================================
# LiteLLM Supply Chain Attack - Compromise Checker
# Ref: https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/
#
# Checks for indicators of compromise from the litellm 1.82.7 / 1.82.8
# backdoor (March 24, 2026 - TeamPCP / SNYK-PYTHON-LITELLM-15762713)
#
# Usage: bash check_litellm_compromise.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

FOUND_ISSUES=0

banner() {
  echo ""
  echo -e "${BOLD}========================================${NC}"
  echo -e "${BOLD} LiteLLM Compromise Checker${NC}"
  echo -e "${BOLD} CVE: SNYK-PYTHON-LITELLM-15762713${NC}"
  echo -e "${BOLD} Affected versions: 1.82.7, 1.82.8${NC}"
  echo -e "${BOLD}========================================${NC}"
  echo ""
}

ok()   { echo -e "  ${GREEN}[OK]${NC}    $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC}  $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC}  $1"; FOUND_ISSUES=$((FOUND_ISSUES + 1)); }

section() { echo ""; echo -e "${BOLD}--- $1 ---${NC}"; }

# ---- 1. Check litellm in default pip ----------------------------------------
section "1. Checking default pip/pip3 for litellm"

check_pip() {
  local pip_cmd="$1"
  if ! command -v "$pip_cmd" &>/dev/null; then
    ok "$pip_cmd not found on PATH (skipped)"
    return
  fi
  local version
  version=$("$pip_cmd" show litellm 2>/dev/null | grep -i "^Version:" | awk '{print $2}') || true
  if [ -z "$version" ]; then
    ok "litellm not installed via $pip_cmd"
  elif [[ "$version" == "1.82.7" || "$version" == "1.82.8" ]]; then
    fail "COMPROMISED litellm $version found via $pip_cmd"
  else
    ok "litellm $version found via $pip_cmd (safe)"
  fi
}

check_pip pip
check_pip pip3

# ---- 2. Scan all virtual environments ---------------------------------------
section "2. Scanning all virtual environments under \$HOME"

COMPROMISED_VENVS=()
SAFE_VENVS=()

while IFS= read -r cfg; do
  venv_dir="$(dirname "$cfg")"
  pip_bin="$venv_dir/bin/pip"
  [ -x "$pip_bin" ] || pip_bin="$venv_dir/Scripts/pip.exe"  # Windows compat
  [ -x "$pip_bin" ] || continue

  version=$("$pip_bin" show litellm 2>/dev/null | grep -i "^Version:" | awk '{print $2}') || true
  if [ -z "$version" ]; then
    continue
  elif [[ "$version" == "1.82.7" || "$version" == "1.82.8" ]]; then
    fail "COMPROMISED litellm $version in $venv_dir"
    COMPROMISED_VENVS+=("$venv_dir ($version)")
  else
    SAFE_VENVS+=("$venv_dir ($version)")
  fi
done < <(find "$HOME" -name "pyvenv.cfg" -not -path "*/Trash/*" -not -path "*/.Trash/*" 2>/dev/null)

if [ ${#COMPROMISED_VENVS[@]} -eq 0 ] && [ ${#SAFE_VENVS[@]} -eq 0 ]; then
  ok "No venvs with litellm found"
elif [ ${#COMPROMISED_VENVS[@]} -eq 0 ]; then
  ok "${#SAFE_VENVS[@]} venv(s) with safe litellm versions found"
fi

# ---- 3. Malicious .pth file -------------------------------------------------
section "3. Checking for malicious litellm_init.pth"

PTH_FOUND=false
while IFS= read -r site_dir; do
  if [ -f "$site_dir/litellm_init.pth" ]; then
    fail "Malicious .pth file found: $site_dir/litellm_init.pth"
    PTH_FOUND=true
  fi
done < <(python3 -c "import site; print('\n'.join(site.getsitepackages()))" 2>/dev/null || true)

# Also check inside venvs
while IFS= read -r pth; do
  fail "Malicious .pth file found: $pth"
  PTH_FOUND=true
done < <(find "$HOME" -name "litellm_init.pth" -not -path "*/Trash/*" 2>/dev/null)

if [ "$PTH_FOUND" = false ]; then
  ok "No litellm_init.pth found"
fi

# ---- 4. Suspicious .pth files with encoded payloads -------------------------
section "4. Checking for suspicious .pth files (base64/exec/subprocess)"

SUSPICIOUS_PTH=false
while IFS= read -r site_dir; do
  [ -d "$site_dir" ] || continue
  while IFS= read -r pth; do
    warn "Suspicious .pth file: $pth"
    SUSPICIOUS_PTH=true
  done < <(find "$site_dir" -name "*.pth" -exec grep -l "base64\|subprocess\|exec(" {} \; 2>/dev/null)
done < <(python3 -c "import site; print('\n'.join(site.getsitepackages()))" 2>/dev/null || true)

if [ "$SUSPICIOUS_PTH" = false ]; then
  ok "No suspicious .pth files found"
fi

# ---- 5. Persistence artifacts ------------------------------------------------
section "5. Checking for backdoor persistence"

# Backdoor script
for path in "$HOME/.config/sysmon/sysmon.py" "/root/.config/sysmon/sysmon.py"; do
  if [ -f "$path" ]; then
    fail "Backdoor script found: $path"
    sha=$(shasum -a 256 "$path" 2>/dev/null | awk '{print $1}')
    echo "       SHA-256: $sha"
    echo "       Known malicious hash: 6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"
  fi
done
if [ ! -f "$HOME/.config/sysmon/sysmon.py" ] && [ ! -f "/root/.config/sysmon/sysmon.py" ]; then
  ok "No sysmon.py backdoor found"
fi

# Systemd service (Linux)
if [ -f "$HOME/.config/systemd/user/sysmon.service" ]; then
  fail "Malicious systemd service found: ~/.config/systemd/user/sysmon.service"
else
  ok "No sysmon.service found"
fi

# Systemd running (Linux)
if command -v systemctl &>/dev/null; then
  if systemctl --user is-active sysmon.service &>/dev/null; then
    fail "sysmon.service is RUNNING"
  else
    ok "sysmon.service not running"
  fi
fi

# ---- 6. Exfiltration temp files ---------------------------------------------
section "6. Checking for exfiltration artifacts in /tmp"

EXFIL_FOUND=false
for f in /tmp/tpcp.tar.gz /tmp/session.key /tmp/payload.enc /tmp/session.key.enc /tmp/.pg_state /tmp/pglog; do
  if [ -f "$f" ]; then
    fail "Exfiltration artifact found: $f"
    EXFIL_FOUND=true
  fi
done
if [ "$EXFIL_FOUND" = false ]; then
  ok "No exfiltration temp files found"
fi

# ---- 7. C2 domain references ------------------------------------------------
section "7. Checking for C2 domain references"

C2_FOUND=false
for domain in "models.litellm.cloud" "checkmarx.zone"; do
  hits=$(grep -rl "$domain" /tmp/ "$HOME/.config/" 2>/dev/null | head -5) || true
  if [ -n "$hits" ]; then
    fail "C2 domain '$domain' referenced in:"
    echo "$hits" | while read -r f; do echo "       $f"; done
    C2_FOUND=true
  fi
done
if [ "$C2_FOUND" = false ]; then
  ok "No C2 domain references found"
fi

# ---- 8. Active network connections -------------------------------------------
section "8. Checking for suspicious network connections"

NET_FOUND=false
if command -v lsof &>/dev/null; then
  suspicious=$(lsof -i -nP 2>/dev/null | grep -iE "litellm|checkmarx|sysmon" || true)
  if [ -n "$suspicious" ]; then
    fail "Suspicious network connections:"
    echo "$suspicious"
    NET_FOUND=true
  fi
elif command -v ss &>/dev/null; then
  suspicious=$(ss -tunap 2>/dev/null | grep -iE "litellm|checkmarx|sysmon" || true)
  if [ -n "$suspicious" ]; then
    fail "Suspicious network connections:"
    echo "$suspicious"
    NET_FOUND=true
  fi
fi
if [ "$NET_FOUND" = false ]; then
  ok "No suspicious network connections"
fi

# ---- 9. DNS cache check (macOS) ---------------------------------------------
section "9. Checking DNS cache for C2 domains (macOS only)"

if [[ "$(uname)" == "Darwin" ]]; then
  for domain in "models.litellm.cloud" "checkmarx.zone"; do
    if dscacheutil -cachedump 2>/dev/null | grep -q "$domain" 2>/dev/null; then
      warn "C2 domain '$domain' found in DNS cache"
    fi
  done
  ok "DNS cache check complete (manual check: run 'log show --predicate \"process == \\\"mDNSResponder\\\"\" --info --last 24h | grep -E \"litellm|checkmarx\"')"
else
  ok "Not macOS, skipping DNS cache check"
fi

# ---- 10. Kubernetes checks ---------------------------------------------------
section "10. Checking Kubernetes for malicious pods"

if command -v kubectl &>/dev/null; then
  malicious_pods=$(kubectl get pods -A 2>/dev/null | grep "node-setup-" || true)
  if [ -n "$malicious_pods" ]; then
    fail "Suspicious 'node-setup-*' pods found in cluster:"
    echo "$malicious_pods"
  else
    ok "No 'node-setup-*' pods found"
  fi
else
  ok "kubectl not installed (skipped)"
fi

# ---- Summary -----------------------------------------------------------------
section "SUMMARY"

if [ "$FOUND_ISSUES" -eq 0 ]; then
  echo ""
  echo -e "  ${GREEN}${BOLD}All clear - no indicators of compromise found.${NC}"
  echo ""
else
  echo ""
  echo -e "  ${RED}${BOLD}COMPROMISED: $FOUND_ISSUES indicator(s) of compromise found!${NC}"
  echo ""
  echo -e "  ${BOLD}Immediate actions:${NC}"
  echo "  1. Disconnect from network"
  echo "  2. Rotate ALL credentials (SSH keys, API keys, cloud tokens)"
  echo "  3. Remove persistence: rm -rf ~/.config/sysmon/ ~/.config/systemd/user/sysmon.service"
  echo "  4. Remove temp files: rm -f /tmp/tpcp.tar.gz /tmp/session.key* /tmp/payload.enc /tmp/.pg_state /tmp/pglog"
  echo "  5. Uninstall litellm: pip uninstall litellm"
  echo "  6. If on Kubernetes: kubectl delete pod -n kube-system -l app=node-setup"
  echo "  7. Audit AWS Secrets Manager, SSM Parameter Store, and cloud IAM"
  echo "  8. Check https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/ for latest guidance"
  echo ""
fi

exit "$FOUND_ISSUES"
