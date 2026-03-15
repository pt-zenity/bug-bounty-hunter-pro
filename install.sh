#!/bin/bash
# ============================================================
# Bug Bounty Hunter Pro - Full Auto Installer
# Tested on: Ubuntu 20.04/22.04, Debian 11/12, Kali Linux
# Usage: chmod +x install.sh && ./install.sh
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "${GREEN}${BOLD}[✓]${NC} $1"; }
err()  { echo -e "${RED}${BOLD}[✗]${NC} $1"; }
info() { echo -e "${CYAN}${BOLD}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}${BOLD}[!]${NC} $1"; }

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$HOME/tools"
GO_VERSION="1.22.5"
GOPATH="$HOME/go"

echo ""
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}${BOLD}  🔴 Bug Bounty Hunter Pro - Auto Installer${NC}"
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── Deteksi OS ─────────────────────────────────────────────
ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" ]]; then
    warn "Arsitektur $ARCH belum sepenuhnya diuji. Melanjutkan..."
fi

# ── Step 1: Update & paket sistem ──────────────────────────
info "Step 1: Update sistem & install paket dasar..."
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        python3 python3-pip python3-venv git curl wget unzip \
        nmap dnsutils whois whatweb nikto nginx net-tools \
        libxml-writer-perl libjson-perl libnet-ssleay-perl \
        perl ca-certificates 2>/dev/null || true
    ok "Paket sistem terinstall"
else
    warn "apt tidak ditemukan. Install manual: python3, pip3, nmap, whois, whatweb, nginx, perl"
fi

# ── Step 2: Go ─────────────────────────────────────────────
info "Step 2: Install Go $GO_VERSION..."
if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | awk '{print $3}' | sed 's/go//')
    ok "Go sudah terinstall: $CURRENT_GO"
else
    info "Mendownload Go $GO_VERSION..."
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz

    # Tambah ke bashrc & zshrc
    for RC in ~/.bashrc ~/.zshrc; do
        if [[ -f "$RC" ]]; then
            grep -q 'go/bin' "$RC" || echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$RC"
        fi
    done
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    ok "Go $GO_VERSION berhasil diinstall"
fi

export GOPATH="$GOPATH"
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
mkdir -p "$GOPATH/bin"

# ── Step 3: Python dependencies ────────────────────────────
info "Step 3: Install Python dependencies..."
pip3 install -q flask flask-cors requests dnspython \
             aiohttp beautifulsoup4 lxml python-whois sqlmap \
             XSStrike 2>/dev/null || \
pip3 install --user flask flask-cors requests dnspython \
             aiohttp beautifulsoup4 lxml python-whois sqlmap \
             XSStrike 2>/dev/null || true
ok "Python dependencies terinstall"

# ── Step 4: Go tools ───────────────────────────────────────
info "Step 4: Install Go tools..."

install_go_tool() {
    local name="$1"
    local pkg="$2"
    if command -v "$name" &>/dev/null; then
        ok "$name sudah terinstall"
    else
        info "  Installing $name..."
        go install "$pkg" 2>/dev/null && ok "$name" || warn "$name gagal (non-fatal)"
    fi
}

install_go_tool "subfinder"         "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx"             "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "dnsx"              "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "nuclei"            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "katana"            "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "interactsh-client" "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
install_go_tool "dalfox"            "github.com/hahwul/dalfox/v2@latest"
install_go_tool "gau"               "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool "waybackurls"       "github.com/tomnomnom/waybackurls@latest"
install_go_tool "assetfinder"       "github.com/tomnomnom/assetfinder@latest"
install_go_tool "anew"              "github.com/tomnomnom/anew@latest"
install_go_tool "qsreplace"         "github.com/tomnomnom/qsreplace@latest"
install_go_tool "gf"                "github.com/tomnomnom/gf@latest"
install_go_tool "subjack"           "github.com/haccer/subjack@latest"

# ── Step 5: Binary tools (ffuf, amass) ─────────────────────
info "Step 5: Install binary tools..."

# ffuf
if ! command -v ffuf &>/dev/null; then
    info "  Installing ffuf..."
    wget -q "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz" \
         -O /tmp/ffuf.tar.gz
    tar -xzf /tmp/ffuf.tar.gz -C /tmp/ ffuf 2>/dev/null
    sudo mv /tmp/ffuf /usr/local/bin/ && sudo chmod +x /usr/local/bin/ffuf
    rm -f /tmp/ffuf.tar.gz
    ok "ffuf v2.1.0"
else
    ok "ffuf sudah terinstall"
fi

# amass
if ! command -v amass &>/dev/null; then
    info "  Installing amass..."
    wget -q "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_linux_amd64.zip" \
         -O /tmp/amass.zip
    unzip -q /tmp/amass.zip -d /tmp/amass_extract/
    sudo cp /tmp/amass_extract/amass_Linux_amd64/amass /usr/local/bin/
    sudo chmod +x /usr/local/bin/amass
    rm -rf /tmp/amass.zip /tmp/amass_extract/
    ok "amass v4.2.0"
else
    ok "amass sudah terinstall"
fi

# ── Step 6: Nikto ──────────────────────────────────────────
info "Step 6: Install Nikto..."
if ! command -v nikto &>/dev/null; then
    if [[ -d /usr/local/nikto ]]; then
        ok "Nikto source sudah ada"
    else
        git clone -q https://github.com/sullo/nikto /usr/local/nikto 2>/dev/null || \
        sudo git clone -q https://github.com/sullo/nikto /usr/local/nikto
    fi
    sudo tee /usr/local/bin/nikto > /dev/null << 'NIKTO_EOF'
#!/bin/bash
perl /usr/local/nikto/program/nikto.pl "$@"
NIKTO_EOF
    sudo chmod +x /usr/local/bin/nikto
    ok "Nikto terinstall"
else
    ok "Nikto sudah terinstall"
fi

# ── Step 7: Python tools ───────────────────────────────────
info "Step 7: Install SecretFinder & LinkFinder..."
mkdir -p "$TOOLS_DIR"

# SecretFinder
if [[ ! -d "$TOOLS_DIR/SecretFinder" ]]; then
    git clone -q https://github.com/m4ll0k/SecretFinder "$TOOLS_DIR/SecretFinder"
    pip3 install -q -r "$TOOLS_DIR/SecretFinder/requirements.txt" 2>/dev/null || true
fi
cat > /usr/local/bin/secretfinder << SCRIPT
#!/bin/bash
python3 $TOOLS_DIR/SecretFinder/SecretFinder.py "\$@"
SCRIPT
sudo chmod +x /usr/local/bin/secretfinder
ok "SecretFinder"

# LinkFinder
if [[ ! -d "$TOOLS_DIR/LinkFinder" ]]; then
    git clone -q https://github.com/GerbenJavado/LinkFinder "$TOOLS_DIR/LinkFinder"
    pip3 install -q -r "$TOOLS_DIR/LinkFinder/requirements.txt" 2>/dev/null || true
fi
cat > /usr/local/bin/linkfinder << SCRIPT
#!/bin/bash
python3 $TOOLS_DIR/LinkFinder/linkfinder.py "\$@"
SCRIPT
sudo chmod +x /usr/local/bin/linkfinder
ok "LinkFinder"

# XSStrike wrapper
if python3 -c "import XSStrike" 2>/dev/null; then
    XSSTRIKE_PATH=$(python3 -c "import XSStrike, os; print(os.path.dirname(XSStrike.__file__))" 2>/dev/null)
    if [[ -n "$XSSTRIKE_PATH" ]]; then
        cat > /usr/local/bin/xsstrike << SCRIPT
#!/bin/bash
python3 $XSSTRIKE_PATH/xsstrike.py "\$@"
SCRIPT
        sudo chmod +x /usr/local/bin/xsstrike
        ok "XSStrike"
    fi
elif [[ ! -d "$TOOLS_DIR/XSStrike" ]]; then
    git clone -q https://github.com/s0md3v/XSStrike "$TOOLS_DIR/XSStrike"
    pip3 install -q -r "$TOOLS_DIR/XSStrike/requirements.txt" 2>/dev/null || true
    cat > /usr/local/bin/xsstrike << SCRIPT
#!/bin/bash
python3 $TOOLS_DIR/XSStrike/xsstrike.py "\$@"
SCRIPT
    sudo chmod +x /usr/local/bin/xsstrike
    ok "XSStrike"
fi

# ── Step 8: sqlmap wrapper ─────────────────────────────────
info "Step 8: Setup sqlmap..."
if ! command -v sqlmap &>/dev/null; then
    SQLMAP_PY=$(find /usr/local/lib -name "sqlmap.py" 2>/dev/null | head -1)
    if [[ -n "$SQLMAP_PY" ]]; then
        cat > /usr/local/bin/sqlmap << SCRIPT
#!/bin/bash
python3 $SQLMAP_PY "\$@"
SCRIPT
        sudo chmod +x /usr/local/bin/sqlmap
        ok "sqlmap wrapper dibuat"
    else
        warn "sqlmap tidak ditemukan, coba: pip3 install sqlmap"
    fi
else
    ok "sqlmap sudah terinstall"
fi

# ── Step 9: Download wordlists ─────────────────────────────
info "Step 9: Download wordlists..."
mkdir -p "$INSTALL_DIR/wordlists"

download_wordlist() {
    local name="$1"
    local url="$2"
    local dest="$INSTALL_DIR/wordlists/$name"
    if [[ -f "$dest" ]] && [[ $(wc -l < "$dest") -gt 100 ]]; then
        ok "  $name sudah ada ($(wc -l < "$dest") baris)"
    else
        info "  Downloading $name..."
        curl -sL "$url" -o "$dest" 2>/dev/null && ok "  $name" || warn "  $name gagal"
    fi
}

download_wordlist "common.txt" \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
download_wordlist "api-endpoints.txt" \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt"
download_wordlist "raft-medium-dirs.txt" \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"

# Update nuclei templates
if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates (background)..."
    nuclei -update-templates -silent 2>/dev/null &
fi

# ── Step 10: Verifikasi ────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}${BOLD}  📋 Verifikasi Instalasi${NC}"
echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

INSTALLED=0
MISSING=0
TOOLS=(nmap curl dig whois whatweb nikto subfinder ffuf nuclei
       httpx dnsx katana gau anew assetfinder gf waybackurls
       dalfox sqlmap amass interactsh-client xsstrike
       secretfinder linkfinder)

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✅${NC} $tool → $(command -v $tool)"
        ((INSTALLED++))
    else
        echo -e "  ${RED}❌${NC} $tool → TIDAK DITEMUKAN"
        ((MISSING++))
    fi
done

echo ""
echo -e "${BOLD}Hasil: ${GREEN}$INSTALLED terinstall${NC}, ${RED}$MISSING tidak ditemukan${NC} dari ${#TOOLS[@]} tools"

# ── Selesai ────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  🎉 Instalasi Selesai!${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Jalankan aplikasi dengan:"
echo -e "  ${CYAN}${BOLD}cd $INSTALL_DIR && ./start.sh${NC}"
echo ""
echo -e "  Lalu buka browser: ${CYAN}http://localhost:3000${NC}"
echo ""

if [[ $MISSING -gt 0 ]]; then
    warn "Ada $MISSING tool yang tidak terinstall."
    warn "Pastikan PATH sudah benar: export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin"
    warn "Lalu jalankan ulang: source ~/.bashrc"
fi
