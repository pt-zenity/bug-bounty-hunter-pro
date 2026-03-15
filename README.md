# 🔴 Bug Bounty Hunter Pro

**Platform keamanan web profesional berbasis AI** dengan 25+ tool recon & vulnerability scanner terintegrasi dalam satu UI modern.

![Version](https://img.shields.io/badge/version-3.0.0-red)
![Tools](https://img.shields.io/badge/tools-25%2B-orange)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Fitur Utama

| Kategori | Tools |
|----------|-------|
| 🔍 **DNS & Recon** | `dig`, `dnsx`, `subfinder`, `amass`, `assetfinder` |
| 🌐 **HTTP Probe** | `httpx` (ProjectDiscovery), `curl` |
| 🕷️ **Crawling & URLs** | `katana`, `gau`, `waybackurls`, `anew`, `gf` |
| 🔌 **Port & Vuln** | `nmap`, `nikto`, `nuclei`, `ffuf` |
| 💉 **Injection** | `dalfox` (XSS), `sqlmap` (SQLi), `xsstrike` |
| 🔑 **Secrets** | `secretfinder`, `linkfinder` |
| 🌍 **OSINT** | `whois`, `whatweb`, `interactsh-client`, `subjack` |

---

## 📋 Persyaratan Sistem

| Komponen | Versi Minimum |
|----------|---------------|
| OS | Ubuntu 20.04 / Debian 11 / Kali Linux |
| Python | 3.10+ |
| Go | 1.22+ |
| RAM | 2 GB (rekomendasi 4 GB) |
| Storage | 5 GB |
| Koneksi | Internet (untuk tool download & scan) |

---

## 🚀 Instalasi dari 0 (Step-by-Step)

### Step 1 — Clone Repository

```bash
git clone https://github.com/pt-zenity/bug-bounty-hunter-pro.git
cd bug-bounty-hunter-pro
```

---

### Step 2 — Install Dependensi Sistem

```bash
# Update package list
sudo apt update && sudo apt upgrade -y

# Install paket dasar
sudo apt install -y \
    python3 python3-pip python3-venv \
    git curl wget unzip \
    nmap dnsutils whois whatweb nikto \
    nginx net-tools

# Verifikasi
python3 --version    # Python 3.x.x
nmap --version       # Nmap x.xx
```

---

### Step 3 — Install Go (untuk tool-tool Go)

```bash
# Download Go 1.22.5
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz -O /tmp/go.tar.gz

# Extract ke /usr/local
sudo tar -C /usr/local -xzf /tmp/go.tar.gz

# Tambah ke PATH (permanent)
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verifikasi
go version    # go version go1.22.5 linux/amd64
```

---

### Step 4 — Install Python Dependencies

```bash
# Install library Python
pip3 install flask flask-cors requests dnspython \
             aiohttp beautifulsoup4 lxml python-whois \
             sqlmap XSStrike

# Verifikasi sqlmap
sqlmap --version
```

---

### Step 5 — Install Tool Go (ProjectDiscovery & lainnya)

```bash
# Set GOPATH
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# --- ProjectDiscovery Tools ---
# subfinder - subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx - HTTP toolkit (ProjectDiscovery)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# dnsx - DNS resolver
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# nuclei - vulnerability scanner
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# katana - web crawler
go install github.com/projectdiscovery/katana/cmd/katana@latest

# interactsh-client - OOB testing
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# --- Other Go Tools ---
# dalfox - XSS scanner
go install github.com/hahwul/dalfox/v2@latest

# gau - get all URLs
go install github.com/lc/gau/v2/cmd/gau@latest

# waybackurls - Wayback Machine URLs
go install github.com/tomnomnom/waybackurls@latest

# assetfinder - asset discovery
go install github.com/tomnomnom/assetfinder@latest

# anew - deduplicate lines
go install github.com/tomnomnom/anew@latest

# qsreplace - query string replacement
go install github.com/tomnomnom/qsreplace@latest

# gf - grep patterns
go install github.com/tomnomnom/gf@latest

# subjack - subdomain takeover
go install github.com/haccer/subjack@latest

# Verifikasi tools
subfinder -version
nuclei -version
dalfox version
gau --version
```

---

### Step 6 — Install Tool Binary (ffuf & amass)

```bash
# --- ffuf - fast web fuzzer ---
wget https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
     -O /tmp/ffuf.tar.gz
tar -xzf /tmp/ffuf.tar.gz -C /tmp/
sudo mv /tmp/ffuf /usr/local/bin/
sudo chmod +x /usr/local/bin/ffuf
ffuf -V    # ffuf v2.1.0

# --- amass - subdomain enumeration ---
wget https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_linux_amd64.zip \
     -O /tmp/amass.zip
unzip /tmp/amass.zip -d /tmp/amass_extract/
sudo cp /tmp/amass_extract/amass_Linux_amd64/amass /usr/local/bin/
sudo chmod +x /usr/local/bin/amass
amass version

# --- subfinder binary (alternatif dari Go install) ---
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip \
     -O /tmp/subfinder.zip
unzip /tmp/subfinder.zip -d /tmp/
sudo mv /tmp/subfinder /usr/local/bin/
sudo chmod +x /usr/local/bin/subfinder

# --- nuclei binary (alternatif dari Go install) ---
wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.9/nuclei_3.3.9_linux_amd64.zip \
     -O /tmp/nuclei.zip
unzip /tmp/nuclei.zip -d /tmp/
sudo mv /tmp/nuclei /usr/local/bin/
sudo chmod +x /usr/local/bin/nuclei

# Update nuclei templates
nuclei -update-templates
```

---

### Step 7 — Install Tool Python (SecretFinder & LinkFinder)

```bash
# Buat direktori tools
mkdir -p ~/tools

# --- SecretFinder - mencari API key tersembunyi ---
git clone https://github.com/m4ll0k/SecretFinder ~/tools/SecretFinder
pip3 install -r ~/tools/SecretFinder/requirements.txt

# Buat wrapper script
cat > /usr/local/bin/secretfinder << 'EOF'
#!/bin/bash
python3 ~/tools/SecretFinder/SecretFinder.py "$@"
EOF
chmod +x /usr/local/bin/secretfinder

# --- LinkFinder - endpoint dari JS files ---
git clone https://github.com/GerbenJavado/LinkFinder ~/tools/LinkFinder
pip3 install -r ~/tools/LinkFinder/requirements.txt

cat > /usr/local/bin/linkfinder << 'EOF'
#!/bin/bash
python3 ~/tools/LinkFinder/linkfinder.py "$@"
EOF
chmod +x /usr/local/bin/linkfinder

# --- XSStrike - advanced XSS scanner ---
pip3 install XSStrike
# atau dari source:
# git clone https://github.com/s0md3v/XSStrike ~/tools/XSStrike
# pip3 install -r ~/tools/XSStrike/requirements.txt

# Buat wrapper
cat > /usr/local/bin/xsstrike << 'EOF'
#!/bin/bash
python3 ~/tools/XSStrike/xsstrike.py "$@"
EOF
chmod +x /usr/local/bin/xsstrike
```

---

### Step 8 — Install Nikto (Web Vulnerability Scanner)

```bash
# Clone Nikto
git clone https://github.com/sullo/nikto /usr/local/nikto

# Install Perl dependencies
sudo apt install -y libxml-writer-perl libjson-perl libnet-ssleay-perl

# Buat wrapper
cat > /usr/local/bin/nikto << 'EOF'
#!/bin/bash
perl /usr/local/nikto/program/nikto.pl "$@"
EOF
sudo chmod +x /usr/local/bin/nikto

# Verifikasi
nikto -Version
```

---

### Step 9 — Download Wordlists

```bash
mkdir -p wordlists

# SecLists - common paths
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
     -o wordlists/common.txt

# API endpoints
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" \
     -o wordlists/api-endpoints.txt

# Raft medium dirs
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" \
     -o wordlists/raft-medium-dirs.txt

echo "Wordlists downloaded:"
wc -l wordlists/*.txt
```

---

### Step 10 — Jalankan Aplikasi

```bash
# Pastikan berada di direktori project
cd bug-bounty-hunter-pro

# Beri izin execute
chmod +x start.sh

# Jalankan semua service sekaligus
./start.sh
```

Output yang diharapkan:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔴 Bug Bounty Hunter Pro - Starting Services
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[*] Cleaning up existing processes...
[*] Starting API backend (port 5000)...
  ✅ API backend is up
[*] Starting Frontend server (port 8080)...
[*] Starting Nginx (port 3000)...

[*] Checking services...
  ✅ API Backend (port 5000) - Running
  ✅ Frontend (port 8080) - Running
  ✅ Nginx Proxy (port 3000) - Running

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🌐 Application: http://localhost:3000
  🔌 API Health:  http://localhost:3000/api/health
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Buka browser: **http://localhost:3000**

---

## 🔍 Verifikasi Instalasi

```bash
# Cek semua 25 tools
curl -s http://localhost:3000/api/health | python3 -m json.tool

# Output yang diharapkan:
# "installed_count": 25,
# "total_count": 25,
# "version": "3.0.0"
```

Atau cek manual satu per satu:
```bash
for tool in nmap curl dig whois whatweb nikto subfinder ffuf nuclei \
            httpx dnsx katana gau anew assetfinder gf waybackurls \
            dalfox sqlmap amass interactsh-client xsstrike \
            secretfinder linkfinder; do
    if which "$tool" > /dev/null 2>&1; then
        echo "✅ $tool: $(which $tool)"
    else
        echo "❌ $tool: TIDAK DITEMUKAN"
    fi
done
```

---

## 🏗️ Struktur Proyek

```
bug-bounty-hunter-pro/
├── api/
│   └── app.py              # Flask API backend (port 5000)
├── static/
│   ├── css/style.css       # Styling UI
│   └── js/app.js           # Frontend JavaScript
├── templates/
│   └── index.html          # Halaman utama UI
├── tools/                  # Script dari shuvonsec/claude-bug-bounty
│   └── claude-bug-bounty/
├── wordlists/              # Wordlist untuk ffuf
│   ├── common.txt
│   ├── api-endpoints.txt
│   └── raft-medium-dirs.txt
├── server.py               # Flask frontend server (port 8080)
├── nginx.conf              # Nginx reverse proxy config (port 3000)
├── start.sh                # Script startup semua service
└── README.md               # Dokumentasi ini
```

---

## 🛠️ Cara Penggunaan

### Dashboard (Full Scan)
1. Buka **http://localhost:3000**
2. Masukkan domain target (contoh: `example.com`)
3. Pilih mode: **Quick** atau **Full Scan**
4. Klik **Start Scan**
5. Pantau progress real-time via live log stream

### Tools Individual (Sidebar)

| Tool | Fungsi | Contoh Input |
|------|--------|--------------|
| DNS Recon | Record DNS lengkap | `example.com` |
| Port Scanner | Port terbuka + banner | `example.com` |
| Security Headers | Header keamanan HTTP | `https://example.com` |
| SSL/TLS | Sertifikat & cipher | `example.com` |
| CORS Tester | Misconfigurasi CORS | `https://example.com` |
| Tech Fingerprint | Stack teknologi | `https://example.com` |
| Path Discovery | Endpoint tersembunyi | `https://example.com` |
| XSS Scanner | Reflected XSS | `https://example.com/?q=test` |
| SQLi Scanner | SQL injection dasar | `https://example.com/?id=1` |
| HTTP Methods | Metode HTTP berbahaya | `https://example.com` |
| **WHOIS** | Info domain/registrar | `example.com` |
| **Subfinder** | Subdomain enumeration | `example.com` |
| **Amass** | Subdomain pasif | `example.com` |
| **Assetfinder** | Asset discovery | `example.com` |
| **WhatWeb** | Deteksi teknologi | `https://example.com` |
| **HTTPX Probe** | HTTP probing cepat | `example.com` |
| **DNSX** | DNS resolver detail | `example.com` |
| **GAU URLs** | URL dari arsip | `example.com` |
| **Wayback URLs** | URL Wayback Machine | `example.com` |
| **Katana** | Web crawler JS-aware | `https://example.com` |
| **Nikto** | Web vuln scanner | `https://example.com` |
| **ffuf Fuzzer** | Directory brute-force | `https://example.com` |
| **Nuclei** | Template vuln scan | `https://example.com` |
| **Dalfox XSS** | Advanced XSS + WAF bypass | `https://example.com/?q=test` |
| **SQLMap** | SQL injection mendalam | `https://example.com/?id=1` |
| **SecretFinder** | API key di JS | `https://example.com` |
| **LinkFinder** | Endpoint dari JS | `https://example.com` |
| **CVSS Calculator** | Hitung skor risiko | *(manual input)* |

---

## ⚙️ Konfigurasi

### Mengganti Port
Edit `nginx.conf`:
```nginx
server {
    listen 3000;   # Ganti dengan port yang diinginkan
    ...
}
```

Edit `server.py`:
```python
app.run(host='0.0.0.0', port=8080)  # Ganti port frontend
```

### Akses dari Jaringan Lain
Edit `nginx.conf`, ubah `listen 3000` menjadi `listen 0.0.0.0:3000`.

Atau ubah di `server.py`:
```python
app.run(host='0.0.0.0', port=8080)
```

---

## 🐛 Troubleshooting

### Port sudah dipakai
```bash
fuser -k 3000/tcp 5000/tcp 8080/tcp
./start.sh
```

### Tool tidak ditemukan
```bash
# Tambah Go bin ke PATH
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Nginx permission denied
```bash
# Pastikan log path di nginx.conf menggunakan /tmp
error_log /tmp/nginx_error.log warn;
access_log /tmp/nginx_access.log main;
```

### API 502 Bad Gateway
```bash
# Restart manual
pkill -f "api/app.py" && pkill -f "server.py"
cd /path/to/bug-bounty-hunter-pro
python3 -u api/app.py &
python3 -u server.py &
/usr/sbin/nginx -c nginx.conf
```

### Cek log
```bash
tail -f logs/api.log       # Log API backend
tail -f logs/frontend.log  # Log frontend
tail -f /tmp/nginx_error.log  # Log nginx
```

---

## 📌 Perintah Berguna

```bash
# Start semua service
./start.sh

# Stop semua service
pkill -f "api/app.py"; pkill -f "server.py"; /usr/sbin/nginx -s stop

# Cek health API
curl http://localhost:3000/api/health | python3 -m json.tool

# Update nuclei templates
nuclei -update-templates

# Test tool individual
curl -s -X POST http://localhost:3000/api/tools/subfinder \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

---

## 🔗 Referensi Tools

| Tool | Repository |
|------|-----------|
| subfinder | https://github.com/projectdiscovery/subfinder |
| httpx (PD) | https://github.com/projectdiscovery/httpx |
| nuclei | https://github.com/projectdiscovery/nuclei |
| katana | https://github.com/projectdiscovery/katana |
| dnsx | https://github.com/projectdiscovery/dnsx |
| dalfox | https://github.com/hahwul/dalfox |
| sqlmap | https://github.com/sqlmapproject/sqlmap |
| amass | https://github.com/owasp-amass/amass |
| ffuf | https://github.com/ffuf/ffuf |
| nikto | https://github.com/sullo/nikto |
| gau | https://github.com/lc/gau |
| waybackurls | https://github.com/tomnomnom/waybackurls |
| assetfinder | https://github.com/tomnomnom/assetfinder |
| SecretFinder | https://github.com/m4ll0k/SecretFinder |
| LinkFinder | https://github.com/GerbenJavado/LinkFinder |
| XSStrike | https://github.com/s0md3v/XSStrike |
| Inspirasi Pipeline | https://github.com/shuvonsec/claude-bug-bounty |

---

## ⚠️ Disclaimer

> Tool ini dibuat **hanya untuk tujuan edukasi dan pengujian keamanan yang sah (authorized penetration testing)**. Penggunaan tool ini pada sistem tanpa izin eksplisit dari pemilik adalah **ilegal**. Pengguna bertanggung jawab penuh atas semua aktivitas yang dilakukan menggunakan tool ini.

---

## 📄 License

MIT License — bebas digunakan dan dimodifikasi dengan menyertakan kredit.
