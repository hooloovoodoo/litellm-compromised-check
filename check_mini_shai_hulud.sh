#!/usr/bin/env bash
# check_mini_shai_hulud.sh
#
# Detection for the Mini Shai-Hulud npm/PyPI supply chain worm
# (Wave 4, May 11 2026 — TanStack / Mistral / UiPath / Guardrails AI).
#
# CVE-2026-45321 (CVSS 9.6)  GHSA-g7cv-rxg3-hmpx
#
# READ-ONLY. Skripta ne briše, ne menja, ne rotira ništa — samo prijavljuje
# šta nađe i ispisuje sledeće korake ako bilo šta zatekne.
#
# Usage:
#   bash check_mini_shai_hulud.sh           # skenira CWD i ~
#
# Exit codes:
#   0  — ništa pronađeno, verovatno čisto
#   1  — pronađen bar jedan indikator kompromitacije
#   2  — greška u izvršavanju (npr. bash 3.2 sintaksa, find nedostaje)
#
# Reference:
#   https://snyk.io/blog/tanstack-npm-packages-compromised/
#   https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx
#   https://tanstack.com/blog/npm-supply-chain-compromise-postmortem

set -u

# ---------- pretty output (TTY only) ----------
if [ -t 1 ]; then
  RED=$'\033[0;31m'
  GREEN=$'\033[0;32m'
  YELLOW=$'\033[0;33m'
  BOLD=$'\033[1m'
  RESET=$'\033[0m'
else
  RED='' GREEN='' YELLOW='' BOLD='' RESET=''
fi

FINDINGS=0

section() { printf '\n%s=== %s ===%s\n' "$BOLD" "$1" "$RESET"; }
found()   { FINDINGS=$((FINDINGS + 1)); printf '%s[!]%s %s\n' "$RED" "$RESET" "$1"; }
clean()   { printf '%s[ok]%s %s\n' "$GREEN" "$RESET" "$1"; }
info()    { printf '%s[i]%s  %s\n' "$YELLOW" "$RESET" "$1"; }

# ---------- preflight ----------
if ! command -v find >/dev/null 2>&1; then
  echo "find nije dostupan, ne mogu da skeniram" >&2
  exit 2
fi

printf '%s%s%s\n' "$BOLD" "Mini Shai-Hulud detector — wave 4 (TanStack / Mistral / UiPath / Guardrails AI)" "$RESET"
info "OS: $(uname -s 2>/dev/null || echo unknown)"
info "skeniram CWD: $(pwd) i HOME: $HOME"

# ---------- 1. router_init.js (glavni npm IoC) ----------
section "router_init.js"
RI_HITS=$(find . -name "router_init.js" 2>/dev/null)
if [ -n "$RI_HITS" ]; then
  found "router_init.js pronađen:"
  printf '    %s\n' $RI_HITS

  # known-bad hash check
  KNOWN_HASH="ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
  HASHER=""
  if command -v sha256sum >/dev/null 2>&1; then
    HASHER="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    HASHER="shasum -a 256"
  fi
  if [ -n "$HASHER" ]; then
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      H=$($HASHER "$f" 2>/dev/null | awk '{print $1}')
      if [ "$H" = "$KNOWN_HASH" ]; then
        found "    ↳ $f matches known-bad SHA-256"
      else
        info "    ↳ $f ima drugi hash (proveri ručno): $H"
      fi
    done <<EOF
$RI_HITS
EOF
  fi
else
  clean "router_init.js nije pronađen u CWD"
fi

# ---------- 2. malicious @tanstack/setup optionalDependency ----------
section "sumnjivi @tanstack/setup optionalDependencies"
if [ -d node_modules/@tanstack ]; then
  OD_HITS=$(find node_modules/@tanstack -name package.json 2>/dev/null \
    -exec grep -l "79ac49ee\|@tanstack/setup" {} + 2>/dev/null)
  if [ -n "$OD_HITS" ]; then
    found "@tanstack/setup malicious optionalDependency u:"
    printf '    %s\n' $OD_HITS
  else
    clean "nema sumnjive @tanstack/setup optionalDependency"
  fi
else
  info "nema node_modules/@tanstack u trenutnom direktorijumu"
fi

# ---------- 3. Claude Code persistence ----------
section "Claude Code persistence (router_runtime.js, setup.mjs)"
CC_HITS=""
for base in "$HOME/.claude" ".claude"; do
  if [ -d "$base" ]; then
    out=$(find "$base" -maxdepth 2 \
      \( -name "router_runtime.js" -o -name "setup.mjs" \) 2>/dev/null)
    [ -n "$out" ] && CC_HITS="$CC_HITS$out"$'\n'
  fi
done
CC_HITS="${CC_HITS%$'\n'}"
if [ -n "$CC_HITS" ]; then
  found "Claude Code persistence fajlovi:"
  printf '    %s\n' $CC_HITS
else
  clean "nema Claude Code persistence fajlova"
fi

# ---------- 4. VS Code persistence ----------
section "VS Code persistence (.vscode/tasks.json, .vscode/setup.mjs)"
VS_FOUND=0
if [ -f .vscode/tasks.json ] && \
   grep -lE "setup\.mjs|router_runtime" .vscode/tasks.json >/dev/null 2>&1; then
  found ".vscode/tasks.json referencira setup.mjs ili router_runtime"
  VS_FOUND=1
fi
if [ -f .vscode/setup.mjs ]; then
  found ".vscode/setup.mjs postoji"
  VS_FOUND=1
fi
[ "$VS_FOUND" -eq 0 ] && clean "VS Code persistence nije pronađen"

# ---------- 5. Dead-man switch (Linux) ----------
section "dead-man switch — Linux (gh-token-monitor)"
LIN_HITS=()
for f in "$HOME/.local/bin/gh-token-monitor.sh" \
         "$HOME/.config/systemd/user/gh-token-monitor.service"; do
  [ -e "$f" ] && LIN_HITS+=("$f")
done
if [ "${#LIN_HITS[@]}" -gt 0 ]; then
  found "Linux dead-man switch fajlovi:"
  printf '    %s\n' "${LIN_HITS[@]}"
else
  clean "nema Linux dead-man switch fajlova"
fi

# ---------- 6. Dead-man switch (macOS) ----------
section "dead-man switch — macOS (LaunchAgent)"
MAC_FILE="$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist"
if [ -e "$MAC_FILE" ]; then
  found "macOS dead-man switch postoji: $MAC_FILE"
else
  clean "nema macOS dead-man switch LaunchAgent-a"
fi

# ---------- 7. Injected GH workflow ----------
section "injected GitHub Actions workflow (codeql_analysis.yml)"
if [ -f .github/workflows/codeql_analysis.yml ]; then
  info ".github/workflows/codeql_analysis.yml postoji"
  info "    ako ga nisi sam dodao, verovatno je injectovan exfil workflow"
  info "    pregledaj sadržaj — ako vidi 'toJSON(secrets)' ili nepoznat host, FOUND"
fi

# ---------- 8. Python paketi (PyPI strana napada) ----------
section "PyPI paketi (guardrails-ai, mistralai)"
if command -v pip >/dev/null 2>&1; then
  PIP_GA=$(pip show guardrails-ai 2>/dev/null | awk -F': ' '/^Version/{print $2}')
  PIP_MI=$(pip show mistralai     2>/dev/null | awk -F': ' '/^Version/{print $2}')

  if [ -n "$PIP_GA" ]; then
    if [ "$PIP_GA" = "0.10.1" ]; then
      found "guardrails-ai 0.10.1 instaliran (KOMPROMITOVANA verzija — payload na import!)"
    else
      info "guardrails-ai instaliran, verzija $PIP_GA (kompromitovana je 0.10.1)"
    fi
  fi
  if [ -n "$PIP_MI" ]; then
    if [ "$PIP_MI" = "2.4.6" ]; then
      found "mistralai 2.4.6 instaliran (KOMPROMITOVANA verzija)"
    else
      info "mistralai instaliran, verzija $PIP_MI (kompromitovana je 2.4.6)"
    fi
  fi
  if [ -z "$PIP_GA" ] && [ -z "$PIP_MI" ]; then
    clean "guardrails-ai i mistralai nisu instalirani u current pip env"
  fi
  info "napomena: ako koristiš virtualenv-e, pokreni skriptu unutar svakog"
else
  info "pip nije dostupan, preskačem PyPI proveru"
fi

# ---------- 9. Dead-drop git commits ----------
section "dead-drop git commits (claude@users.noreply.github.com)"
if command -v git >/dev/null 2>&1 && [ -d .git ]; then
  GIT_HITS=$(git log --all --author="claude@users.noreply.github.com" \
    --pretty=format:'%H %s' 2>/dev/null | head -20)
  if [ -n "$GIT_HITS" ]; then
    info "commit-ovi sa tim author-om u repo-u:"
    echo "$GIT_HITS" | sed 's/^/    /'
    info "    ako koristiš legitiman Claude GitHub App, OK"
    info "    ako ne — sumnjivo (dead-drop exfil pattern)"
  else
    clean "nema commit-ova sa claude@users.noreply.github.com author-om"
  fi
else
  info "nisam u git repu (ili git nije instaliran), preskačem"
fi

# ---------- summary ----------
echo
printf '%s================================%s\n' "$BOLD" "$RESET"
if [ "$FINDINGS" -eq 0 ]; then
  printf '%s%sNEMA NALAZA. Verovatno čisto.%s\n' "$BOLD" "$GREEN" "$RESET"
  printf '%s================================%s\n' "$BOLD" "$RESET"
  exit 0
else
  printf '%s%sNALAZA: %d%s\n' "$BOLD" "$RED" "$FINDINGS" "$RESET"
  printf '%s================================%s\n' "$BOLD" "$RESET"
  echo
  printf '%sKRITIČAN REDOSLED SANIRANJA:%s\n' "$BOLD" "$RESET"
  echo "  1. NE rotiraj još tokene."
  echo "  2. PRVO ubij gh-token-monitor servis:"
  echo "       Linux:  systemctl --user stop gh-token-monitor.service"
  echo "               systemctl --user disable gh-token-monitor.service"
  echo "               rm -f ~/.config/systemd/user/gh-token-monitor.service \\"
  echo "                     ~/.local/bin/gh-token-monitor.sh"
  echo "       macOS:  launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist"
  echo "               rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist"
  echo "  3. Obriši persistence fajlove (.claude/, .vscode/, injected workflow)."
  echo "  4. TEK ONDA rotiraj sve tokene koji su bili na mašini"
  echo "     (npm publish tokens → GitHub PAT → AWS → Vault → K8s SA → SSH → GCP)."
  echo "  5. DNS blok na perimetru: *.getsession.org, api.masscan.cloud, git-tanstack.com"
  echo
  printf '%sZašto ovaj redosled:%s gh-token-monitor servis svakih 60s proverava da li je\n' "$BOLD" "$RESET"
  echo "ukradeni GitHub token validan. Ako primeti revocation, pokreće 'rm -rf ~/'."
  echo
  echo "Detalji: https://snyk.io/blog/tanstack-npm-packages-compromised/"
  exit 1
fi
