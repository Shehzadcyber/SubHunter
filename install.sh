#!/usr/bin/env bash
# SubHunter — Dependency Installer
# Tested on Ubuntu/Debian/Kali. Adjust package manager for Arch/Fedora.

set -e
BOLD="\033[1m"; CYAN="\033[96m"; GREEN="\033[92m"; YELLOW="\033[93m"; RESET="\033[0m"

log()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }

log "SubHunter Dependency Installer"

# ── Python deps ──────────────────────────────────────────────────────────────────
log "Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt
ok "Python deps installed"

# ── Go tools (requires Go 1.20+) ─────────────────────────────────────────────────
if command -v go &>/dev/null; then
    log "Installing Go-based tools..."

    GOPATH_BIN="$(go env GOPATH)/bin"
    export PATH="$PATH:$GOPATH_BIN"

    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && ok "subfinder" || warn "subfinder failed"
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null && ok "dnsx" || warn "dnsx failed"
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest 2>/dev/null && ok "shuffledns" || warn "shuffledns failed"
    go install -v github.com/tomnomnom/assetfinder@latest 2>/dev/null && ok "assetfinder" || warn "assetfinder failed"
    go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest 2>/dev/null && ok "chaos" || warn "chaos failed"

    # crobat (Rapid7 Sonar)
    go install -v github.com/cgboal/sonarsearch/cmd/crobat@latest 2>/dev/null && ok "crobat" || warn "crobat failed"

    log "Adding GOPATH/bin to PATH in ~/.bashrc ..."
    grep -q 'GOPATH/bin' ~/.bashrc || echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
else
    warn "Go not found — skipping Go tools. Install from https://go.dev/dl/"
fi

# ── amass ─────────────────────────────────────────────────────────────────────────
if command -v snap &>/dev/null; then
    snap install amass 2>/dev/null && ok "amass (snap)" || warn "amass snap failed"
elif command -v apt-get &>/dev/null; then
    apt-get install -y amass 2>/dev/null && ok "amass (apt)" || warn "amass apt failed"
else
    warn "amass: install manually from https://github.com/owasp-amass/amass/releases"
fi

# ── findomain ─────────────────────────────────────────────────────────────────────
if ! command -v findomain &>/dev/null; then
    log "Installing findomain..."
    ARCH=$(uname -m)
    if [[ "$ARCH" == "x86_64" ]]; then
        curl -sLo /tmp/findomain.zip \
            "https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip" && \
        unzip -o /tmp/findomain.zip -d /usr/local/bin/ && chmod +x /usr/local/bin/findomain && ok "findomain" || warn "findomain failed"
    else
        warn "findomain: unsupported arch ($ARCH), install manually"
    fi
fi

# ── puredns ───────────────────────────────────────────────────────────────────────
if command -v go &>/dev/null; then
    go install -v github.com/d3mondev/puredns/v2@latest 2>/dev/null && ok "puredns" || warn "puredns failed"
fi

# ── SecLists wordlist ─────────────────────────────────────────────────────────────
if [[ ! -f "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" ]]; then
    if command -v apt-get &>/dev/null; then
        log "Installing seclists..."
        apt-get install -y seclists 2>/dev/null && ok "seclists" || warn "seclists not available via apt"
    else
        warn "SecLists not found. Clone from https://github.com/danielmiessler/SecLists to /usr/share/seclists"
    fi
fi

echo ""
ok "Installation complete. Run: python3 subhunter.py -d example.com"
