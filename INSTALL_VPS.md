# 🖥️ Panduan Instalasi di VPS — Bug Bounty Hunter Pro

> Panduan lengkap dari nol hingga aplikasi berjalan di VPS Ubuntu/Debian.  
> Cocok untuk: **Ubuntu 20.04, 22.04, 24.04 | Debian 11, 12 | Kali Linux**

---

## 📋 Daftar Isi

1. [Spesifikasi VPS yang Direkomendasikan](#spesifikasi-vps)
2. [Persiapan Awal VPS](#persiapan-awal-vps)
3. [Install Git & Clone Repo](#install-git--clone-repo)
4. [Jalankan Auto-Installer](#jalankan-auto-installer)
5. [Konfigurasi Nginx untuk Domain / IP Publik](#konfigurasi-nginx-untuk-domain--ip-publik)
6. [Setup Systemd (Auto-Start saat Reboot)](#setup-systemd-auto-start-saat-reboot)
7. [Setup SSL dengan Let's Encrypt (HTTPS)](#setup-ssl-dengan-lets-encrypt-https)
8. [Firewall & Keamanan](#firewall--keamanan)
9. [Push ke GitHub](#push-ke-github)
10. [Troubleshooting](#troubleshooting)
11. [Perintah Berguna Sehari-hari](#perintah-berguna-sehari-hari)

---

## 🖥️ Spesifikasi VPS

| Komponen | Minimum | Rekomendasi |
|----------|---------|-------------|
| **CPU** | 2 vCPU | 4 vCPU |
| **RAM** | 2 GB | 4 GB |
| **Storage** | 20 GB SSD | 40 GB SSD |
| **OS** | Ubuntu 20.04 | Ubuntu 22.04 LTS |
| **Koneksi** | 1 Mbps | 10 Mbps |
| **Port terbuka** | 22, 80, 443, 3000 | 22, 80, 443 |

> **Provider yang disarankan**: DigitalOcean, Vultr, Hetzner, AWS Lightsail, Contabo, IDCloudHost

---

## 🔧 Persiapan Awal VPS

### 1. Login ke VPS
```bash
ssh root@IP_VPS_ANDA
# Atau jika menggunakan user non-root:
ssh user@IP_VPS_ANDA
```

### 2. Update Sistem
```bash
apt-get update && apt-get upgrade -y
```

### 3. Buat User Non-Root (Opsional tapi Direkomendasikan)
```bash
# Buat user baru
adduser bugbounty

# Beri hak sudo
usermod -aG sudo bugbounty

# Pindah ke user baru
su - bugbounty
```

### 4. Pastikan Direktori Home Tersedia
```bash
echo $HOME
# Output: /home/bugbounty  (atau /root jika pakai root)
```

> ⚠️ **Penting**: Semua perintah selanjutnya dijalankan sebagai user yang akan menjalankan aplikasi (bukan root secara langsung, kecuali ada `sudo`).

---

## 📥 Install Git & Clone Repo

### 1. Install Git
```bash
sudo apt-get install -y git
```

### 2. Clone Repository
```bash
# Pindah ke direktori home
cd ~

# Clone repo
git clone https://github.com/pt-zenity/bug-bounty-hunter-pro.git

# Masuk ke folder project
cd bug-bounty-hunter-pro
```

### 3. Verifikasi File
```bash
ls -la
# Harus ada: install.sh, start.sh, api/, static/, templates/, nginx.conf
```

---

## ⚙️ Jalankan Auto-Installer

Auto-installer akan menginstall **semua** dependensi secara otomatis:

```bash
# Beri izin eksekusi
chmod +x install.sh start.sh

# Jalankan installer (butuh sudo untuk beberapa langkah)
# ⏱️ Proses ini memakan waktu 10-30 menit tergantung koneksi internet
./install.sh
```

### Yang Diinstall Otomatis:

| Kategori | Tools |
|----------|-------|
| **Sistem** | python3, pip3, git, curl, wget, nmap, nginx, whois, whatweb, nikto |
| **Go** | 1.22.5 (jika belum ada) |
| **Python packages** | flask, flask-cors, requests, dnspython, sqlmap, XSStrike, reportlab |
| **Go tools** | subfinder, httpx, dnsx, nuclei, katana, dalfox, gau, waybackurls, assetfinder, anew, gf, subjack, interactsh-client |
| **Binary tools** | ffuf v2.1.0, amass v4.2.0 |
| **Python tools** | SecretFinder, LinkFinder |
| **Wordlists** | common.txt, api-endpoints.txt, raft-medium-dirs.txt |

### Contoh Output Sukses:
```
[✓] Paket sistem terinstall
[✓] Go 1.22.5 berhasil diinstall
[✓] Python dependencies terinstall
[✓] subfinder
[✓] httpx
[✓] nuclei
...
🎉 Instalasi Selesai!
```

### Jika Ada Tool yang Gagal (Non-Fatal):
```bash
# Reload PATH dulu
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
source ~/.bashrc

# Install ulang tool yang gagal secara manual, contoh:
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## 🌐 Konfigurasi Nginx untuk Domain / IP Publik

### Opsi A: Akses via IP Publik + Port 3000

Ini cara paling simple, tidak perlu konfigurasi tambahan:

```bash
# Jalankan aplikasi
./start.sh

# Akses di browser:
# http://IP_VPS_ANDA:3000
```

Pastikan port 3000 terbuka di firewall:
```bash
sudo ufw allow 3000/tcp
```

---

### Opsi B: Akses via Domain di Port 80/443 (Rekomendasi untuk Production)

#### Langkah 1: Edit `nginx.conf` di folder project

```bash
nano nginx.conf
```

Ganti bagian `server` menjadi:

```nginx
server {
    listen 80;
    server_name domain-anda.com www.domain-anda.com;
    # Jika pakai IP publik langsung, ganti dengan IP:
    # server_name 123.456.789.0;

    # SSE support
    proxy_buffering off;
    proxy_cache off;

    # API routes
    location /api/ {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        add_header Access-Control-Allow-Origin "*" always;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS, DELETE" always;
        add_header Access-Control-Allow-Headers "Content-Type" always;
    }

    # Static files
    location /static/ {
        alias /home/NAMA_USER/bug-bounty-hunter-pro/static/;
        expires 1h;
        add_header Cache-Control "public";
    }

    # Frontend
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 60s;
    }
}
```

> ⚠️ Ganti `/home/NAMA_USER/` dengan path user Anda yang sebenarnya (contoh: `/home/bugbounty/` atau `/root/`)

#### Langkah 2: Update `start.sh` agar pakai port 80

Edit file `start.sh`, ganti bagian nginx:
```bash
nano start.sh
```

Ubah:
```bash
NGINX_BIN="/usr/sbin/nginx"
```
Dan ubah nginx.conf `listen 3000;` → `listen 80;`

#### Langkah 3: Jalankan
```bash
./start.sh
# Akses: http://domain-anda.com
```

---

## 🔄 Setup Systemd (Auto-Start saat Reboot)

Agar aplikasi otomatis jalan setelah VPS reboot:

### 1. Buat File Service

```bash
sudo nano /etc/systemd/system/bugbounty.service
```

Isi dengan:
```ini
[Unit]
Description=Bug Bounty Hunter Pro
After=network.target
Wants=network-online.target

[Service]
Type=forking
User=NAMA_USER
Group=NAMA_USER
WorkingDirectory=/home/NAMA_USER/bug-bounty-hunter-pro
ExecStart=/home/NAMA_USER/bug-bounty-hunter-pro/start.sh
ExecStop=/bin/bash -c "pkill -f api/app.py; pkill -f server.py; /usr/sbin/nginx -s stop -c /home/NAMA_USER/bug-bounty-hunter-pro/nginx.conf"
Restart=on-failure
RestartSec=10
Environment=PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/go/bin:/home/NAMA_USER/go/bin
StandardOutput=append:/home/NAMA_USER/bug-bounty-hunter-pro/logs/systemd.log
StandardError=append:/home/NAMA_USER/bug-bounty-hunter-pro/logs/systemd.log

[Install]
WantedBy=multi-user.target
```

> ⚠️ Ganti semua `NAMA_USER` dengan username Anda (contoh: `bugbounty` atau `root`)

### 2. Aktifkan Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (auto-start saat boot)
sudo systemctl enable bugbounty

# Start service sekarang
sudo systemctl start bugbounty

# Cek status
sudo systemctl status bugbounty
```

### 3. Perintah Systemd

```bash
sudo systemctl start bugbounty      # Start
sudo systemctl stop bugbounty       # Stop
sudo systemctl restart bugbounty    # Restart
sudo systemctl status bugbounty     # Cek status
sudo journalctl -u bugbounty -f     # Lihat log realtime
```

---

## 🔒 Setup SSL dengan Let's Encrypt (HTTPS)

Hanya jika menggunakan domain (bukan IP langsung):

### 1. Install Certbot

```bash
sudo apt-get install -y certbot python3-certbot-nginx
```

### 2. Hentikan Nginx Sementara

```bash
sudo systemctl stop bugbounty 2>/dev/null || true
pkill -f "nginx" 2>/dev/null || true
```

### 3. Dapatkan Sertifikat SSL

```bash
sudo certbot certonly --standalone -d domain-anda.com -d www.domain-anda.com \
  --email email@anda.com --agree-tos --no-eff-email
```

### 4. Update nginx.conf untuk HTTPS

```bash
nano nginx.conf
```

Tambahkan blok HTTPS:
```nginx
# Redirect HTTP ke HTTPS
server {
    listen 80;
    server_name domain-anda.com www.domain-anda.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS
server {
    listen 443 ssl;
    server_name domain-anda.com www.domain-anda.com;

    ssl_certificate /etc/letsencrypt/live/domain-anda.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/domain-anda.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # ... (sama seperti konfigurasi sebelumnya)
}
```

### 5. Auto-Renew SSL

```bash
# Test renewal
sudo certbot renew --dry-run

# Cron job untuk auto-renew
sudo crontab -e
# Tambahkan:
0 3 * * * certbot renew --quiet && pkill -HUP nginx
```

### 6. Restart Aplikasi

```bash
sudo systemctl start bugbounty
# Akses: https://domain-anda.com
```

---

## 🛡️ Firewall & Keamanan

### Setup UFW Firewall

```bash
# Install UFW
sudo apt-get install -y ufw

# Default policy
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Izinkan SSH (PENTING: jangan sampai terkunci!)
sudo ufw allow 22/tcp
sudo ufw allow OpenSSH

# Izinkan HTTP dan HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Izinkan port 3000 jika akses langsung (hapus jika pakai domain)
sudo ufw allow 3000/tcp

# Aktifkan firewall
sudo ufw enable

# Cek status
sudo ufw status verbose
```

### Proteksi SSH (Opsional tapi Sangat Disarankan)

```bash
# Ganti port SSH default
sudo nano /etc/ssh/sshd_config
# Ubah: Port 22 → Port 2222 (pilih port lain)
# Ubah: PermitRootLogin no
# Ubah: PasswordAuthentication no  (jika pakai SSH key)

sudo systemctl restart sshd
sudo ufw allow 2222/tcp
sudo ufw delete allow 22/tcp
```

### Install Fail2Ban (Cegah Brute Force)

```bash
sudo apt-get install -y fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

---

## 📤 Push ke GitHub

### Pertama Kali (Setup Remote)

```bash
cd ~/bug-bounty-hunter-pro

# Cek remote yang ada
git remote -v

# Jika belum ada remote, tambahkan:
git remote add origin https://github.com/USERNAME/REPO-NAME.git

# Atau jika mau ganti remote:
git remote set-url origin https://github.com/USERNAME/REPO-NAME.git
```

### Setup GitHub Credentials

**Cara 1: Personal Access Token (PAT) — Paling Mudah**

```bash
# 1. Buka GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
# 2. Generate token baru dengan scope: repo (full control)
# 3. Copy token tersebut

# Simpan credentials secara permanen
git config --global credential.helper store

# Saat pertama push, masukkan:
# Username: pt-zenity (username GitHub)
# Password: TOKEN_ANDA (bukan password GitHub!)

git push origin main
# Masukkan username dan token ketika diminta
```

**Cara 2: SSH Key (Lebih Aman)**

```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "email@anda.com"
# Tekan Enter untuk semua pertanyaan (atau isi passphrase)

# Lihat public key
cat ~/.ssh/id_ed25519.pub

# Copy isi output di atas
# Buka GitHub → Settings → SSH and GPG keys → New SSH key
# Paste public key, klik Add SSH key

# Ganti remote URL ke SSH
git remote set-url origin git@github.com:pt-zenity/bug-bounty-hunter-pro.git

# Test koneksi
ssh -T git@github.com
# Output: Hi pt-zenity! You've successfully authenticated...
```

### Setup Git Identity

```bash
git config --global user.name "Nama Anda"
git config --global user.email "email@anda.com"
```

### Push Perubahan ke GitHub

```bash
cd ~/bug-bounty-hunter-pro

# Cek status file yang berubah
git status

# Tambahkan semua perubahan
git add .

# Atau tambahkan file spesifik
git add static/js/app.js api/app.py

# Commit dengan pesan yang jelas
git commit -m "Deskripsi perubahan yang dilakukan"

# Push ke branch main
git push origin main

# Jika pertama kali push ke repo baru (force push):
git push -f origin main
```

### Workflow Git Sehari-hari

```bash
# Sebelum mulai kerja: sync dengan GitHub
git pull origin main

# Setelah selesai: commit dan push
git add .
git commit -m "feat: tambah fitur XYZ"
git push origin main
```

### .gitignore — File yang Tidak Dipush

File berikut sudah dikecualikan dari git (lihat `.gitignore`):
- `logs/*.log` — log file
- `__pycache__/` — Python cache
- `.env` — variabel environment sensitif
- `tools/XSStrike/`, `tools/SecretFinder/`, `tools/LinkFinder/` — tools besar (diinstall via install.sh)

---

## 🐛 Troubleshooting

### ❌ Port sudah dipakai

```bash
# Cek proses di port tertentu
sudo fuser -v 3000/tcp
sudo fuser -v 5000/tcp
sudo fuser -v 8080/tcp

# Kill proses di port tersebut
sudo fuser -k 3000/tcp
sudo fuser -k 5000/tcp
sudo fuser -k 8080/tcp

# Jalankan ulang
./start.sh
```

### ❌ Tool tidak ditemukan setelah install

```bash
# Tambah Go bin ke PATH
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Cek path tool
which subfinder
which nuclei

# Cek manual
ls ~/go/bin/
```

### ❌ `502 Bad Gateway` di browser

```bash
# Cek apakah Flask API jalan
curl -s http://localhost:5000/api/health

# Jika tidak ada response, start ulang API
pkill -f "api/app.py" 2>/dev/null || true
cd ~/bug-bounty-hunter-pro
nohup python3 -u api/app.py > logs/api.log 2>&1 &
sleep 3
curl -s http://localhost:5000/api/health
```

### ❌ Nginx gagal start

```bash
# Cek error nginx
cat /tmp/nginx_error.log

# Test konfigurasi
/usr/sbin/nginx -t -c ~/bug-bounty-hunter-pro/nginx.conf

# Masalah umum: path static files salah
# Pastikan path di nginx.conf sesuai:
# alias /home/NAMA_USER/bug-bounty-hunter-pro/static/;
```

### ❌ Python import error

```bash
# Install ulang dependencies
pip3 install flask flask-cors requests dnspython sqlmap reportlab

# Jika pip3 tidak ada
sudo apt-get install -y python3-pip
```

### ❌ SQLMap tidak ditemukan

```bash
# Cek lokasi sqlmap
which sqlmap
pip3 show sqlmap

# Install ulang
pip3 install sqlmap

# Buat wrapper manual jika perlu
SQLMAP_PY=$(find /usr/local/lib -name "sqlmap.py" 2>/dev/null | head -1)
echo "#!/bin/bash" | sudo tee /usr/local/bin/sqlmap
echo "python3 $SQLMAP_PY \"\$@\"" | sudo tee -a /usr/local/bin/sqlmap
sudo chmod +x /usr/local/bin/sqlmap
```

### ❌ Go tools tidak terinstall

```bash
# Cek Go terinstall
go version

# Jika tidak ada, install Go:
wget -q "https://go.dev/dl/go1.22.5.linux-amd64.tar.gz" -O /tmp/go.tar.gz
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc

# Install tool ulang
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hahwul/dalfox/v2@latest
```

### ❌ Permission denied

```bash
# Pastikan script bisa dieksekusi
chmod +x install.sh start.sh

# Jika ada error di nginx (listen port 80 butuh root):
# Gunakan port 3000 di nginx.conf (sudah default), ATAU:
sudo /usr/sbin/nginx -c ~/bug-bounty-hunter-pro/nginx.conf
```

---

## 💡 Perintah Berguna Sehari-hari

### Manajemen Service

```bash
# Start semua service
cd ~/bug-bounty-hunter-pro && ./start.sh

# Stop semua service
pkill -f "api/app.py"
pkill -f "server.py"
/usr/sbin/nginx -s stop -c ~/bug-bounty-hunter-pro/nginx.conf

# Restart cepat (stop + start)
pkill -f "api/app.py" && pkill -f "server.py" && /usr/sbin/nginx -s stop 2>/dev/null; sleep 2; cd ~/bug-bounty-hunter-pro && ./start.sh
```

### Monitoring Log

```bash
# Log API backend (real-time)
tail -f ~/bug-bounty-hunter-pro/logs/api.log

# Log frontend
tail -f ~/bug-bounty-hunter-pro/logs/frontend.log

# Log nginx error
tail -f /tmp/nginx_error.log

# Log nginx access
tail -f /tmp/nginx_access.log
```

### Cek Kesehatan Aplikasi

```bash
# Health check API
curl -s http://localhost:3000/api/health | python3 -m json.tool

# Cek port yang listening
ss -tlnp | grep -E "3000|5000|8080"

# Cek proses yang berjalan
ps aux | grep -E "app.py|server.py|nginx"
```

### Update Aplikasi dari GitHub

```bash
cd ~/bug-bounty-hunter-pro

# Pull perubahan terbaru
git pull origin main

# Restart service untuk apply perubahan
pkill -f "api/app.py" && pkill -f "server.py"
sleep 2
./start.sh
```

### Update Nuclei Templates

```bash
nuclei -update-templates
# Templates disimpan di: ~/.config/nuclei/templates/
```

### Test Tool via API

```bash
# Test DNS
curl -s -X POST http://localhost:3000/api/tools/dns \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}' | python3 -m json.tool

# Test SQLMap (streaming — lihat output langsung)
curl -N -X POST http://localhost:3000/api/tools/sqlmap/stream \
  -H "Content-Type: application/json" \
  -d '{"target":"http://testphp.vulnweb.com/listproducts.php?cat=1","level":1,"risk":1}'

# Test Subfinder
curl -s -X POST http://localhost:3000/api/tools/subfinder \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}' | python3 -m json.tool
```

---

## 📊 Ringkasan Arsitektur

```
Internet / Browser
      │
      ▼
   Port 3000 (Nginx)
      │
      ├──► /api/*  ──► Flask API (Port 5000) ──► Tools: sqlmap, nuclei, nmap...
      │
      ├──► /static/* ──► File statis langsung dari disk
      │
      └──► /* ──► Flask Frontend (Port 8080) ──► templates/index.html
```

### File Penting

| File | Fungsi |
|------|--------|
| `install.sh` | Auto-installer semua dependencies |
| `start.sh` | Start semua service |
| `nginx.conf` | Konfigurasi reverse proxy |
| `api/app.py` | Backend API Flask (port 5000) |
| `server.py` | Frontend Flask server (port 8080) |
| `static/js/app.js` | Frontend JavaScript utama |
| `templates/index.html` | Halaman HTML utama |
| `logs/api.log` | Log backend API |
| `logs/frontend.log` | Log frontend server |

---

## 🔗 Link Berguna

- **GitHub Repository**: https://github.com/pt-zenity/bug-bounty-hunter-pro
- **SQLMap**: https://github.com/sqlmapproject/sqlmap
- **Nuclei**: https://github.com/projectdiscovery/nuclei
- **ProjectDiscovery Tools**: https://github.com/projectdiscovery

---

## ⚠️ Disclaimer

> Tool ini dibuat **hanya untuk tujuan edukasi dan penetration testing yang sah (authorized)**. Pastikan selalu memiliki izin tertulis sebelum melakukan scanning terhadap target apapun. Pengguna bertanggung jawab penuh atas semua aktivitas yang dilakukan.
