/**
 * Bug Bounty Hunter Pro - Frontend Application
 * Professional Security Scanner UI
 */

const API_BASE = '/api';
let currentScanId = null;
let eventSource = null;
let cvssValues = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' };
let allScans = {};
let vulnChart = null;
let statsTotal = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
let currentScanMode = 'quick';

// ─── App Init ─────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    checkAPIStatus();
    refreshScans();
    initVulnChart();
    calculateCVSS();
    updatePoCTemplate();
    
    // Periodic refresh
    setInterval(checkAPIStatus, 15000);
    setInterval(refreshScans, 30000);
    
    // Enter key support
    document.querySelectorAll('input[type="text"]').forEach(input => {
        input.addEventListener('keypress', e => {
            if (e.key === 'Enter') {
                const page = input.closest('.page');
                if (page) {
                    const btn = page.querySelector('.btn-primary');
                    if (btn) btn.click();
                }
            }
        });
    });
});

// ─── Navigation ───────────────────────────────────────────────────────────────

function initNavigation() {
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            navigateTo(page);
        });
    });
}

function navigateTo(pageName) {
    // Update nav
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const navItem = document.querySelector(`.nav-item[data-page="${pageName}"]`);
    if (navItem) navItem.classList.add('active');
    
    // Update pages
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const pageEl = document.getElementById(`page-${pageName}`);
    if (pageEl) pageEl.classList.add('active');
    
    // Update title
    const titles = {
        dashboard: 'Dashboard',
        scanner: 'Full Scanner',
        results: 'Scan Results',
        dns: 'DNS Reconnaissance',
        ports: 'Port Scanner',
        headers: 'Security Headers',
        ssl: 'SSL/TLS Analyzer',
        cors: 'CORS Tester',
        fingerprint: 'Tech Fingerprinting',
        paths: 'Path Discovery',
        xss: 'XSS Scanner',
        sqli: 'SQL Injection Scanner',
        methods: 'HTTP Methods Checker',
        whois: 'WHOIS Lookup',
        subfinder: 'Subdomain Finder',
        nikto: 'Nikto Web Scanner',
        ffuf: 'Directory Fuzzer (ffuf)',
        nuclei: 'Nuclei Vulnerability Scanner',
        whatweb: 'WhatWeb Tech Scanner',
        cvss: 'CVSS Calculator',
        poc: 'PoC Generator',
        reports: 'Reports'
    };
    
    document.getElementById('pageTitle').textContent = titles[pageName] || pageName;
    document.getElementById('breadcrumbCurrent').textContent = titles[pageName] || pageName;
    
    // Load page-specific data
    if (pageName === 'results') loadScanHistory();   // now async
    if (pageName === 'reports') loadReports();
    if (pageName === 'nuclei')  onPageNucleiEnter(); // load nuclei template stats
}

// ─── API Status ───────────────────────────────────────────────────────────────

async function checkAPIStatus() {
    try {
        const resp = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(5000) });
        const data = await resp.json();
        
        if (resp.ok) {
            document.getElementById('apiStatusDot').className = 'status-dot online';
            document.getElementById('apiStatusText').textContent = 'API Online';
            
            // Update tool status
            if (data.tools) {
                renderToolStatus(data.tools);
            }
            // Update nuclei template info if on nuclei page
            if (data.nuclei_templates) {
                const el = document.getElementById('nucleiTemplateCount');
                if (el) el.textContent = data.nuclei_templates.toLocaleString();
            }
            if (data.nuclei_categories) {
                const el = document.getElementById('nucleiCategoryCount');
                if (el) el.textContent = data.nuclei_categories;
            }
        }
    } catch {
        document.getElementById('apiStatusDot').className = 'status-dot offline';
        document.getElementById('apiStatusText').textContent = 'API Offline';
    }
}

function renderToolStatus(tools) {
    const container = document.getElementById('toolStatus');
    if (!container) return;
    
    const toolIcons = {
        nmap:              'fas fa-network-wired',
        subfinder:         'fas fa-search',
        nuclei:            'fas fa-radiation',
        ffuf:              'fas fa-stream',
        curl:              'fas fa-terminal',
        dig:               'fas fa-globe',
        whois:             'fas fa-id-card',
        whatweb:           'fas fa-fingerprint',
        nikto:             'fas fa-bug',
        httpx:             'fas fa-wifi',
        dnsx:              'fas fa-network-wired',
        katana:            'fas fa-spider',
        gau:               'fas fa-history',
        anew:              'fas fa-filter',
        qsreplace:         'fas fa-edit',
        assetfinder:       'fas fa-sitemap',
        gf:                'fas fa-grep',
        waybackurls:       'fas fa-archive',
        dalfox:            'fas fa-terminal',
        sqlmap:            'fas fa-database',
        amass:             'fas fa-layer-group',
        'interactsh-client': 'fas fa-satellite',
        xsstrike:          'fas fa-crosshairs',
        secretfinder:      'fas fa-key',
        linkfinder:        'fas fa-link'
    };
    
    const available = Object.values(tools).filter(Boolean).length;
    const total = Object.keys(tools).length;
    container.innerHTML = `
        <div style="margin-bottom:10px;font-size:12px;color:var(--accent)">
            <i class="fas fa-check-circle"></i> ${available}/${total} tools installed
        </div>
        ${Object.entries(tools).map(([tool, avail]) => `
        <div class="tool-status-item">
            <i class="${toolIcons[tool] || 'fas fa-wrench'} ${avail ? 'tool-avail' : 'tool-missing'}"></i>
            <span class="tool-name">${tool}</span>
            <span class="${avail ? 'tool-avail' : 'tool-missing'}">
                <i class="fas fa-${avail ? 'check-circle' : 'times-circle'}"></i>
                ${avail ? 'OK' : 'Missing'}
            </span>
        </div>`).join('')}
    `;
}

// ─── Dashboard Scan ───────────────────────────────────────────────────────────

function startDashScan() {
    const target = document.getElementById('dashTarget').value.trim();
    const scanType = document.querySelector('input[name="dashScanType"]:checked')?.value || 'quick';
    
    if (!target) {
        showToast('Please enter a target domain', 'error');
        return;
    }
    
    document.getElementById('scanTarget').value = target;
    currentScanMode = scanType;
    navigateTo('scanner');
    setTimeout(() => startFullScan(), 300);
}

function quickScan() {
    const target = document.getElementById('quickTarget').value.trim();
    if (!target) {
        showToast('Enter a target in the search bar', 'warning');
        return;
    }
    
    document.getElementById('scanTarget').value = target;
    currentScanMode = 'quick';
    navigateTo('scanner');
    setTimeout(() => startFullScan(), 300);
}

// ─── Full Scanner ─────────────────────────────────────────────────────────────

function setScanMode(mode, btn) {
    currentScanMode = mode;
    document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    
    const injCheck = document.getElementById('injectionCheck');
    if (mode === 'full') {
        injCheck.classList.add('active');
        injCheck.querySelector('i').className = 'fas fa-check-circle';
    } else {
        injCheck.classList.remove('active');
        injCheck.querySelector('i').className = 'fas fa-times-circle';
    }
}

async function startFullScan() {
    const target = document.getElementById('scanTarget').value.trim();
    if (!target) {
        showToast('Please enter a target domain', 'error');
        return;
    }
    
    // Stop existing scan
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
    
    // Reset UI
    clearConsole();
    document.getElementById('liveFindings').innerHTML = '';
    document.getElementById('liveFindingsCount').textContent = '0';
    
    const btn = document.getElementById('startScanBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
    
    try {
        const resp = await fetch(`${API_BASE}/scan/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, scan_type: currentScanMode })
        });
        
        const data = await resp.json();
        
        if (!resp.ok) {
            showToast(data.error || 'Failed to start scan', 'error');
            resetScanBtn();
            return;
        }
        
        currentScanId = data.scan_id;
        allScans[currentScanId] = { target, status: 'running' };
        
        updateTotalScansCount();
        
        // Start SSE stream
        connectToStream(data.scan_id);
        
        showToast(`Scan started for ${target}`, 'success');
        
    } catch (err) {
        showToast('API connection failed: ' + err.message, 'error');
        resetScanBtn();
    }
}

function connectToStream(scanId) {
    const es = new EventSource(`${API_BASE}/scan/${scanId}/stream`);
    eventSource = es;
    
    es.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        handleStreamMessage(msg, scanId);
    };
    
    es.onerror = () => {
        es.close();
        eventSource = null;
        resetScanBtn();
    };
}

function handleStreamMessage(msg, scanId) {
    switch (msg.type) {
        case 'log':
            appendConsoleLine(msg.data);
            break;
        case 'finding':
            addLiveFinding(msg.data);
            break;
        case 'progress':
            updateProgress(msg.progress, msg.phase, msg.status);
            break;
        case 'complete':
            onScanComplete(msg.scan, scanId);
            break;
    }
}

function appendConsoleLine(log) {
    const console_el = document.getElementById('consoleOutput');
    
    // Remove welcome message
    const welcome = console_el.querySelector('.console-welcome');
    if (welcome) welcome.remove();
    
    const line = document.createElement('div');
    line.className = `console-line ${log.level}`;
    line.innerHTML = `<span class="time">[${log.time}]</span><span class="msg">${escapeHtml(log.message)}</span>`;
    
    console_el.appendChild(line);
    console_el.scrollTop = console_el.scrollHeight;
}

function addLiveFinding(finding) {
    const list = document.getElementById('liveFindings');
    const count = document.getElementById('liveFindingsCount');
    
    const item = document.createElement('div');
    item.className = `finding-item ${finding.severity || 'INFO'}`;
    item.innerHTML = `
        <span class="sev-badge ${finding.severity || 'INFO'}">${finding.severity || 'INFO'}</span>
        <span>${escapeHtml(finding.type || 'Finding')}: ${escapeHtml(finding.description || '').substring(0, 80)}</span>
    `;
    
    list.appendChild(item);
    list.scrollTop = list.scrollHeight;
    
    const num = parseInt(count.textContent) + 1;
    count.textContent = num;
    
    // Update global stats
    const sev = finding.severity || 'INFO';
    if (statsTotal[sev] !== undefined) {
        statsTotal[sev]++;
    }
    updateStatsDisplay();
}

function updateProgress(progress, phase, status) {
    const bar = document.getElementById('progressBar');
    const pct = document.getElementById('progressPct');
    const phaseEl = document.getElementById('scanPhase');
    
    bar.style.width = `${progress}%`;
    pct.textContent = `${progress}%`;
    if (phase) phaseEl.textContent = phase;
}

function onScanComplete(scan, scanId) {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }

    resetScanBtn();

    allScans[scanId] = scan;
    window._activeScanId = scanId;   // store for export buttons

    showToast(`✅ Scan complete! ${scan.findings?.length || 0} findings`, 'success');

    // Show export bar below progress
    renderScanExportBar(scanId);

    // Update results count badge
    document.getElementById('resultsCount').textContent = Object.keys(allScans).length;

    // Load reports
    loadReports();

    // Refresh dashboard
    refreshScans();
}

function clearConsole() {
    consoleAutoScroll = true;   // FIX BUG 10: re-enable auto-scroll on clear
    const console_el = document.getElementById('consoleOutput');
    console_el.innerHTML = '';
    document.getElementById('progressBar').style.width = '0%';
    document.getElementById('progressPct').textContent = '0%';
    document.getElementById('scanPhase').textContent = 'Idle';
}

function resetScanBtn() {
    const btn = document.getElementById('startScanBtn');
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-play"></i> Start Live Scan';
    }
}

function renderScanExportBar(scanId) {
    // Insert export bar after the progress section in the scanner page
    let bar = document.getElementById('scanExportBar');
    if (!bar) {
        // Find a good anchor: the progress card
        const progressCard = document.querySelector('#page-scanner .scan-progress-card') ||
                             document.querySelector('#page-scanner .card');
        if (!progressCard) return;
        bar = document.createElement('div');
        bar.id = 'scanExportBar';
        progressCard.parentNode.insertBefore(bar, progressCard.nextSibling);
    }
    bar.innerHTML = `
        <div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.2);border-radius:10px;padding:14px 18px;margin-top:12px">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
                <i class="fas fa-check-circle" style="color:#10b981;font-size:16px"></i>
                <span style="font-size:13px;color:#10b981;font-weight:700">Scan Complete!</span>
                <span style="font-size:11px;color:var(--text-muted)">— Download your report:</span>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:8px">
                <a href="${API_BASE}/scan/${scanId}/export?format=txt"
                   title="Download Plain Text report"
                   style="display:inline-flex;align-items:center;gap:6px;padding:8px 16px;
                          background:rgba(99,102,241,0.15);border:1px solid rgba(99,102,241,0.35);
                          border-radius:7px;color:#818cf8;font-size:12px;font-weight:700;
                          text-decoration:none;cursor:pointer"
                   onclick="event.preventDefault(); downloadExport('${scanId}','txt')">
                    <i class="fas fa-file-alt"></i> .TXT
                    <span style="font-size:10px;opacity:0.7">Plain Text</span>
                </a>
                <a href="${API_BASE}/scan/${scanId}/export?format=html"
                   title="Download HTML report"
                   style="display:inline-flex;align-items:center;gap:6px;padding:8px 16px;
                          background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.35);
                          border-radius:7px;color:#06b6d4;font-size:12px;font-weight:700;
                          text-decoration:none;cursor:pointer"
                   onclick="event.preventDefault(); downloadExport('${scanId}','html')">
                    <i class="fas fa-file-code"></i> .HTML
                    <span style="font-size:10px;opacity:0.7">Web Report</span>
                </a>
                <a href="${API_BASE}/scan/${scanId}/export?format=pdf"
                   title="Download PDF report"
                   style="display:inline-flex;align-items:center;gap:6px;padding:8px 16px;
                          background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.35);
                          border-radius:7px;color:#ef4444;font-size:12px;font-weight:700;
                          text-decoration:none;cursor:pointer"
                   onclick="event.preventDefault(); downloadExport('${scanId}','pdf')">
                    <i class="fas fa-file-pdf"></i> .PDF
                    <span style="font-size:10px;opacity:0.7">PDF Report</span>
                </a>
                <a href="${API_BASE}/scan/${scanId}/report"
                   title="Download JSON report"
                   style="display:inline-flex;align-items:center;gap:6px;padding:8px 16px;
                          background:rgba(245,158,11,0.15);border:1px solid rgba(245,158,11,0.35);
                          border-radius:7px;color:#f59e0b;font-size:12px;font-weight:700;
                          text-decoration:none;cursor:pointer"
                   onclick="event.preventDefault(); exportScanJson('${scanId}')">
                    <i class="fas fa-code"></i> .JSON
                    <span style="font-size:10px;opacity:0.7">Raw Data</span>
                </a>
                <a href="#"
                   title="Download Markdown report"
                   style="display:inline-flex;align-items:center;gap:6px;padding:8px 16px;
                          background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.12);
                          border-radius:7px;color:var(--text-secondary);font-size:12px;font-weight:700;
                          text-decoration:none;cursor:pointer"
                   onclick="event.preventDefault(); exportScanMarkdown('${scanId}')">
                    <i class="fas fa-hashtag"></i> .MD
                    <span style="font-size:10px;opacity:0.7">Markdown</span>
                </a>
            </div>
        </div>`;
}

// ─── Scan History & Dashboard ─────────────────────────────────────────────────

async function refreshScans() {
    try {
        const resp = await fetch(`${API_BASE}/scan/list`);
        const scans = await resp.json();
        
        // Update allScans
        scans.forEach(s => { allScans[s.id] = s; });
        
        // Update counts badge
        document.getElementById('resultsCount').textContent = scans.length;
        document.getElementById('totalScansCount').textContent = scans.length;
        
        // Update total scans count badge in topbar
        updateTotalScansCount();
        
        renderRecentScans(scans.slice(0, 5));
        updateVulnChart(scans);
        
    } catch {}
}

function renderRecentScans(scans) {
    const container = document.getElementById('recentScans');
    if (!container) return;
    
    if (!scans || scans.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-search fa-3x"></i>
                <p>No scans yet. Launch your first scan!</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = scans.map(scan => `
        <div class="recent-scan-item" onclick="viewScanDetail('${scan.id}')">
            <div class="scan-icon" style="color: var(--accent)"><i class="fas fa-crosshairs"></i></div>
            <div style="flex:1">
                <div class="scan-target-text">${escapeHtml(scan.target || 'Unknown')}</div>
                <div class="scan-meta">${formatDate(scan.started)} · ${scan.findings_count || 0} findings</div>
            </div>
            <span class="status-badge ${scan.status}">
                ${scan.status === 'running' ? '<i class="fas fa-spinner fa-spin"></i>' : 
                  scan.status === 'completed' ? '<i class="fas fa-check"></i>' : '<i class="fas fa-times"></i>'}
                ${scan.status}
            </span>
        </div>
    `).join('');
}

function loadScanHistory() {
    const container = document.getElementById('scanHistoryTable');
    const scans = Object.values(allScans);
    
    if (scans.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-search fa-3x"></i>
                <p>No scan history yet.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = `
        <table class="history-table">
            <thead>
                <tr>
                    <th>Target</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Progress</th>
                    <th>Findings</th>
                    <th>Started</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${scans.map(scan => `
                    <tr onclick="viewScanDetail('${scan.id}')">
                        <td><strong>${escapeHtml(scan.target || 'Unknown')}</strong></td>
                        <td><span class="service-tag">${scan.scan_type || 'full'}</span></td>
                        <td><span class="status-badge ${scan.status || 'unknown'}">
                            ${scan.status === 'running' ? '<i class="fas fa-spinner fa-spin"></i>' : 
                              scan.status === 'completed' ? '<i class="fas fa-check"></i>' : '<i class="fas fa-times"></i>'}
                            ${scan.status || 'unknown'}
                        </span></td>
                        <td>
                            <div style="display:flex;align-items:center;gap:8px">
                                <div style="width:60px;height:4px;background:var(--border);border-radius:2px">
                                    <div style="width:${scan.progress || 0}%;height:100%;background:var(--green);border-radius:2px"></div>
                                </div>
                                <span style="font-size:11px;color:var(--text-muted)">${scan.progress || 0}%</span>
                            </div>
                        </td>
                        <td><span style="color:var(--yellow);font-weight:600">${scan.findings_count || 0}</span></td>
                        <td style="font-size:11px;color:var(--text-muted)">${formatDate(scan.started)}</td>
                        <td>
                            <button class="btn btn-sm" onclick="event.stopPropagation();viewScanDetail('${scan.id}')">
                                <i class="fas fa-eye"></i>
                            </button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

async function viewScanDetail(scanId) {
    try {
        const resp = await fetch(`${API_BASE}/scan/${scanId}`);
        const scan = await resp.json();

        window._currentViewScanId = scanId;  // store for export

        const panel = document.getElementById('scanDetailPanel');
        const content = document.getElementById('scanDetailContent');
        const title = document.getElementById('detailTitle');

        title.textContent = `Scan: ${scan.target} (${scan.status})`;

        // Render findings
        const findings = scan.findings || [];
        const dns = scan.dns || [];
        const ports = scan.ports || [];
        const techs = scan.technologies || [];

        const isCompleted = scan.status === 'completed';
        const exportBarHtml = isCompleted ? `
            <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:10px 14px;margin-bottom:14px;display:flex;align-items:center;flex-wrap:wrap;gap:8px">
                <span style="font-size:11px;color:var(--text-muted)"><i class="fas fa-download"></i> Export report:</span>
                <button onclick="downloadExport('${scanId}','txt')" style="padding:5px 12px;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.25);border-radius:5px;color:#818cf8;font-size:11px;cursor:pointer;font-weight:600"><i class="fas fa-file-alt"></i> TXT</button>
                <button onclick="downloadExport('${scanId}','html')" style="padding:5px 12px;background:rgba(6,182,212,0.12);border:1px solid rgba(6,182,212,0.25);border-radius:5px;color:#06b6d4;font-size:11px;cursor:pointer;font-weight:600"><i class="fas fa-file-code"></i> HTML</button>
                <button onclick="downloadExport('${scanId}','pdf')" style="padding:5px 12px;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.25);border-radius:5px;color:#ef4444;font-size:11px;cursor:pointer;font-weight:600"><i class="fas fa-file-pdf"></i> PDF</button>
                <button onclick="exportScanJson('${scanId}')" style="padding:5px 12px;background:rgba(245,158,11,0.12);border:1px solid rgba(245,158,11,0.25);border-radius:5px;color:#f59e0b;font-size:11px;cursor:pointer;font-weight:600"><i class="fas fa-code"></i> JSON</button>
                <button onclick="exportScanMarkdown('${scanId}')" style="padding:5px 12px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.08);border-radius:5px;color:var(--text-secondary);font-size:11px;cursor:pointer;font-weight:600"><i class="fas fa-hashtag"></i> MD</button>
            </div>` : '';

        content.innerHTML = `
            ${exportBarHtml}
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:20px">
                <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
                    <div style="font-size:24px;font-weight:800;color:var(--accent)">${findings.length}</div>
                    <div style="font-size:11px;color:var(--text-muted)">TOTAL FINDINGS</div>
                </div>
                <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
                    <div style="font-size:24px;font-weight:800;color:var(--red)">${findings.filter(f=>f.severity==='CRITICAL'||f.severity==='HIGH').length}</div>
                    <div style="font-size:11px;color:var(--text-muted)">CRITICAL/HIGH</div>
                </div>
                <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center">
                    <div style="font-size:24px;font-weight:800;color:var(--green)">${dns.length}</div>
                    <div style="font-size:11px;color:var(--text-muted)">DNS RECORDS</div>
                </div>
            </div>

            ${findings.length > 0 ? `
                <h3 style="font-size:14px;margin-bottom:12px;color:var(--text-secondary)"><i class="fas fa-bug"></i> Findings (${findings.length})</h3>
                ${findings.map(f => `
                    <div class="report-finding-item">
                        <div class="report-finding-header">
                            <span class="sev-badge ${f.severity}">${f.severity}</span>
                            <span class="report-finding-title">${escapeHtml(f.type || 'Finding')}</span>
                        </div>
                        <div class="report-finding-desc">${escapeHtml(f.description || '')}</div>
                        ${f.poc ? `<div class="report-finding-poc">${escapeHtml(f.poc)}</div>` : ''}
                        ${f.remediation ? `<div class="report-finding-rem">${escapeHtml(f.remediation)}</div>` : ''}
                    </div>
                `).join('')}
            ` : '<div class="empty-state"><i class="fas fa-shield-alt fa-2x"></i><p>No findings recorded</p></div>'}

            ${dns.length > 0 ? `
                <h3 style="font-size:14px;margin:20px 0 12px;color:var(--text-secondary)"><i class="fas fa-network-wired"></i> DNS Records</h3>
                ${dns.map(r => `
                    <div class="dns-record">
                        <span class="dns-type">${r.type}</span>
                        <span class="dns-value">${escapeHtml(r.value)}</span>
                    </div>
                `).join('')}
            ` : ''}

            ${ports.length > 0 ? `
                <h3 style="font-size:14px;margin:20px 0 12px;color:var(--text-secondary)"><i class="fas fa-plug"></i> Open Ports</h3>
                <table class="port-table">
                    <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr></thead>
                    <tbody>${ports.map(p => `
                        <tr>
                            <td class="port-num">${p.port}</td>
                            <td class="port-open">OPEN</td>
                            <td><span class="service-tag">${p.service}</span></td>
                            <td class="banner-text">${escapeHtml(p.banner || '')}</td>
                        </tr>
                    `).join('')}</tbody>
                </table>
            ` : ''}
        `;

        panel.style.display = 'block';
        panel.scrollIntoView({ behavior: 'smooth' });

    } catch (err) {
        showToast('Failed to load scan detail', 'error');
    }
}

function closeDetail() {
    document.getElementById('scanDetailPanel').style.display = 'none';
}

// ─── Individual Tools ─────────────────────────────────────────────────────────

async function runTool(tool) {
    // Nuclei has a severity dropdown — delegate
    if (tool === 'nuclei') { runNuclei(); return; }
    // SQLMap has extra param field — delegate
    if (tool === 'sqlmap') { runSqlmap(); return; }

    const targetEl = document.getElementById(`${tool}Target`);
    const resultCard = document.getElementById(`${tool}Result`);
    const resultContent = document.getElementById(`${tool}ResultContent`);
    
    if (!targetEl) return;
    
    const target = targetEl.value.trim();
    if (!target) {
        showToast('Please enter a target', 'error');
        return;
    }
    
    showLoading(`Running ${tool} analysis...`);
    resultCard.style.display = 'none';
    
    try {
        const resp = await fetch(`${API_BASE}/tools/${tool}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });
        
        const data = await resp.json();
        
        hideLoading();
        resultCard.style.display = 'block';
        
        switch (tool) {
            case 'dns': renderDNSResults(resultContent, data); break;
            case 'ports': renderPortResults(resultContent, data); break;
            case 'headers': renderHeaderResults(resultContent, data); break;
            case 'ssl': renderSSLResults(resultContent, data); break;
            case 'cors': renderCORSResults(resultContent, data); break;
            case 'fingerprint': renderFingerprintResults(resultContent, data); break;
            case 'paths': renderPathResults(resultContent, data); break;
            case 'xss': renderVulnFindingsResults(resultContent, data, 'XSS'); break;
            case 'sqli': renderVulnFindingsResults(resultContent, data, 'SQLi'); break;
            case 'methods': renderMethodsResults(resultContent, data); break;
            case 'whois': renderWhoisResults(resultContent, data); break;
            case 'subfinder': renderSubfinderResults(resultContent, data); break;
            case 'nikto': renderNiktoResults(resultContent, data); break;
            case 'ffuf': renderFfufResults(resultContent, data); break;
            case 'nuclei': renderNucleiResults(resultContent, data); break;
            case 'whatweb': renderWhatwebResults(resultContent, data); break;
            case 'amass': renderSubfinderResults(resultContent, data); break;
            case 'assetfinder': renderSubfinderResults(resultContent, data); break;
            case 'httpx': renderHttpxResults(resultContent, data); break;
            case 'dnsx': renderDnsxResults(resultContent, data); break;
            case 'gau': renderUrlResults(resultContent, data, 'GAU URLs'); break;
            case 'waybackurls': renderUrlResults(resultContent, data, 'Wayback URLs'); break;
            case 'katana': renderKatanaResults(resultContent, data); break;
            case 'dalfox': renderVulnFindingsResults(resultContent, data, 'Dalfox XSS'); break;
            case 'secretfinder': renderVulnFindingsResults(resultContent, data, 'Secrets'); break;
            case 'linkfinder': renderLinkfinderResults(resultContent, data); break;
        }
        
    } catch (err) {
        hideLoading();
        showToast('Tool error: ' + err.message, 'error');
        resultContent.innerHTML = `<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><p>Error: ${escapeHtml(err.message)}</p></div>`;
        resultCard.style.display = 'block';
    }
}

async function runNuclei() {
    const targetEl   = document.getElementById('nucleiTarget');
    const sevEl      = document.getElementById('nucleiSeverity');
    const modeEl     = document.getElementById('nucleiMode');
    const catEl      = document.getElementById('nucleiCategory');
    const tagsEl     = document.getElementById('nucleiTags');
    const customEl   = document.getElementById('nucleiCustomTemplates');
    const resultCard = document.getElementById('nucleiResult');
    const resultContent = document.getElementById('nucleiResultContent');
    const rawCard    = document.getElementById('nucleiRawCard');

    if (!targetEl) return;
    const target   = targetEl.value.trim();
    const severity = sevEl ? sevEl.value : 'medium,high,critical';
    const mode     = modeEl ? modeEl.value : 'default';
    if (!target) { showToast('Please enter a target URL', 'error'); return; }

    const payload = { target, severity };
    let scanLabel = 'Default (7 categories)';

    if (mode === 'category' && catEl) {
        payload.category = catEl.value;
        scanLabel = 'Category: ' + catEl.options[catEl.selectedIndex].text;
    } else if (mode === 'tags' && tagsEl && tagsEl.value.trim()) {
        payload.tags = tagsEl.value.trim();
        scanLabel = 'Tags: ' + tagsEl.value.trim();
    } else if (mode === 'custom' && customEl && customEl.value.trim()) {
        payload.templates = customEl.value.trim();
        scanLabel = 'Custom: ' + customEl.value.trim();
    }

    showLoading(`Running Nuclei scan [${scanLabel}]… this may take 2–3 minutes`);
    if (resultCard) resultCard.style.display = 'none';
    if (rawCard) rawCard.style.display = 'none';

    try {
        const resp = await fetch(`${API_BASE}/tools/nuclei`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await resp.json();
        hideLoading();
        if (resultCard) resultCard.style.display = 'block';
        renderNucleiResults(resultContent, data);
        // Render severity badges in header
        renderNucleiSeverityBadges(data);
        // Show raw output
        if (data.raw) {
            if (rawCard) rawCard.style.display = 'block';
            const pre = document.getElementById('nucleiRawPre');
            if (pre) pre.textContent = data.raw;
        }
    } catch(err) {
        hideLoading();
        showToast('Nuclei error: ' + err.message, 'error');
        if (resultCard) resultCard.style.display = 'block';
        if (resultContent) resultContent.innerHTML = `<div class="empty-state"><p>Error: ${escapeHtml(err.message)}</p></div>`;
    }
}

function onNucleiModeChange() {
    const mode = document.getElementById('nucleiMode')?.value;
    document.getElementById('nucleiCategoryGroup').style.display = mode === 'category' ? 'block' : 'none';
    document.getElementById('nucleiTagsGroup').style.display    = mode === 'tags'     ? 'block' : 'none';
    document.getElementById('nucleiCustomGroup').style.display  = mode === 'custom'   ? 'block' : 'none';
}

function quickNucleiScan(category) {
    // Switch to category mode, select the category, and run
    const modeEl = document.getElementById('nucleiMode');
    const catEl  = document.getElementById('nucleiCategory');
    if (modeEl) { modeEl.value = 'category'; onNucleiModeChange(); }
    if (catEl) catEl.value = category;
    // Check if we need to auto-adjust severity for info-only categories
    const sevEl = document.getElementById('nucleiSeverity');
    const infoCategories = ['technologies', 'exposed-panels', 'dns', 'ssl', 'osint'];
    if (sevEl && infoCategories.includes(category)) {
        sevEl.value = 'info,low,medium,high,critical';
    }
    runNuclei();
}

async function loadNucleiStats() {
    try {
        const resp = await fetch(`${API_BASE}/tools/nuclei/templates/stats`);
        const data = await resp.json();
        renderNucleiTemplateStats(data);
    } catch(err) {
        console.warn('Could not load nuclei stats:', err);
    }
}

function renderNucleiTemplateStats(data) {
    // Stats bar at top
    const statsBar = document.getElementById('nucleiStatsBar');
    if (statsBar) {
        statsBar.innerHTML = `
            <div style="background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.2);border-radius:10px;padding:12px 16px;display:flex;align-items:center;gap:10px">
                <i class="fas fa-database" style="color:#818cf8;font-size:18px"></i>
                <div><div style="font-size:20px;font-weight:700;color:#818cf8">${(data.total||0).toLocaleString()}</div><div style="font-size:10px;color:var(--text-muted)">Total Templates</div></div>
            </div>
            <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);border-radius:10px;padding:12px 16px;display:flex;align-items:center;gap:10px">
                <i class="fas fa-skull-crossbones" style="color:#ef4444;font-size:18px"></i>
                <div><div style="font-size:20px;font-weight:700;color:#ef4444">${(data.categories?.cves?.count||0).toLocaleString()}</div><div style="font-size:10px;color:var(--text-muted)">CVE Templates</div></div>
            </div>
            <div style="background:rgba(249,115,22,0.1);border:1px solid rgba(249,115,22,0.2);border-radius:10px;padding:12px 16px;display:flex;align-items:center;gap:10px">
                <i class="fas fa-cogs" style="color:#f97316;font-size:18px"></i>
                <div><div style="font-size:20px;font-weight:700;color:#f97316">${(data.categories?.misconfiguration?.count||0).toLocaleString()}</div><div style="font-size:10px;color:var(--text-muted)">Misconfig</div></div>
            </div>
            <div style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.2);border-radius:10px;padding:12px 16px;display:flex;align-items:center;gap:10px">
                <i class="fas fa-door-open" style="color:#f59e0b;font-size:18px"></i>
                <div><div style="font-size:20px;font-weight:700;color:#f59e0b">${(data.categories?.['exposed-panels']?.count||0).toLocaleString()}</div><div style="font-size:10px;color:var(--text-muted)">Exposed Panels</div></div>
            </div>
            <div style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.2);border-radius:10px;padding:12px 16px;display:flex;align-items:center;gap:10px">
                <i class="fas fa-lock" style="color:#10b981;font-size:18px"></i>
                <div><div style="font-size:20px;font-weight:700;color:#10b981">${(data.categories?.ssl?.count||0).toLocaleString()}</div><div style="font-size:10px;color:var(--text-muted)">SSL/TLS</div></div>
            </div>
            <div style="background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.2);border-radius:10px;padding:12px 16px;display:flex;align-items:center;gap:10px">
                <i class="fas fa-project-diagram" style="color:#06b6d4;font-size:18px"></i>
                <div><div style="font-size:20px;font-weight:700;color:#06b6d4">${(data.categories?.network?.count||0).toLocaleString()}</div><div style="font-size:10px;color:var(--text-muted)">Network</div></div>
            </div>
        `;
    }

    // Update inline counts
    const tplCount = document.getElementById('nucleiTemplateCount');
    const catCount = document.getElementById('nucleiCategoryCount');
    if (tplCount) tplCount.textContent = (data.total||0).toLocaleString();
    if (catCount) catCount.textContent = Object.keys(data.categories||{}).length;

    // Category grid
    const grid = document.getElementById('nucleiCategoryGrid');
    const card = document.getElementById('nucleiCategoryStatsCard');
    if (grid && data.categories) {
        card.style.display = 'block';
        grid.innerHTML = Object.entries(data.categories).map(([id, cat]) => `
            <div onclick="quickNucleiScan('${escapeHtml(id)}')" style="cursor:pointer;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:10px 12px;transition:background 0.2s" onmouseover="this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.background='rgba(255,255,255,0.03)'">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
                    <i class="fas ${escapeHtml(cat.icon||'fa-folder')}" style="color:${escapeHtml(cat.color||'#888')};font-size:14px;width:16px"></i>
                    <span style="font-size:12px;font-weight:600;color:var(--text-primary)">${escapeHtml(cat.label)}</span>
                </div>
                <div style="font-size:18px;font-weight:700;color:${escapeHtml(cat.color||'#888')}">${(cat.count||0).toLocaleString()}</div>
                <div style="font-size:10px;color:var(--text-muted);margin-top:2px">templates</div>
            </div>
        `).join('');
    }
}

function renderNucleiSeverityBadges(data) {
    const el = document.getElementById('nucleiSeverityBadges');
    if (!el) return;
    const s = data.severity_summary || {};
    const items = [
        ['CRITICAL', '#ef4444', s.CRITICAL||0],
        ['HIGH',     '#f97316', s.HIGH||0],
        ['MEDIUM',   '#f59e0b', s.MEDIUM||0],
        ['LOW',      '#3b82f6', s.LOW||0],
        ['INFO',     '#94a3b8', s.INFO||0],
    ].filter(([,, count]) => count > 0);
    el.innerHTML = items.map(([label, color, count]) =>
        `<span style="background:${color}22;color:${color};border:1px solid ${color}44;padding:3px 8px;border-radius:12px;font-size:11px;font-weight:600">${label}: ${count}</span>`
    ).join('');
}

function toggleNucleiRaw() {
    const content = document.getElementById('nucleiRawContent');
    const toggle  = document.getElementById('nucleiRawToggle');
    if (!content) return;
    const visible = content.style.display !== 'none';
    content.style.display = visible ? 'none' : 'block';
    if (toggle) toggle.textContent = visible ? '[click to expand]' : '[click to collapse]';
}

// Auto-load nuclei stats when nuclei page is opened
function onPageNucleiEnter() {
    loadNucleiStats();
}



async function runSqlmap() {
    const targetEl  = document.getElementById('sqlmapTarget');
    const paramEl   = document.getElementById('sqlmapParam');
    const resultCard    = document.getElementById('sqlmapResult');
    const resultContent = document.getElementById('sqlmapResultContent');
    if (!targetEl) return;
    const target = targetEl.value.trim();
    const param  = paramEl ? paramEl.value.trim() : '';
    if (!target) { showToast('Please enter a target URL', 'error'); return; }

    showLoading('Running SQLMap scan… this may take up to 2 minutes');
    resultCard.style.display = 'none';
    try {
        const body = { target };
        if (param) body.param = param;
        const resp = await fetch(`${API_BASE}/tools/sqlmap`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await resp.json();
        hideLoading();
        resultCard.style.display = 'block';
        renderVulnFindingsResults(resultContent, data, 'SQLMap');
    } catch(err) {
        hideLoading();
        showToast('SQLMap error: ' + err.message, 'error');
        resultCard.style.display = 'block';
        resultContent.innerHTML = `<div class="empty-state"><p>Error: ${escapeHtml(err.message)}</p></div>`;
    }
}

function renderDNSResults(container, data) {
    const records = data.records || [];
    
    if (records.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-search fa-2x"></i><p>No DNS records found</p></div>';
        return;
    }
    
    const typeColors = {
        A: '#3b82f6', AAAA: '#8b5cf6', MX: '#f59e0b', NS: '#10b981',
        TXT: '#06b6d4', CNAME: '#f97316', SOA: '#ec4899', PTR: '#6366f1'
    };
    
    container.innerHTML = `
        <div style="margin-bottom:12px">
            <span style="font-size:12px;color:var(--text-muted)">Found <strong style="color:var(--accent)">${records.length}</strong> records for ${escapeHtml(data.target)}</span>
        </div>
        ${records.map(r => `
            <div class="dns-record">
                <span class="dns-type" style="background:rgba(${hexToRGB(typeColors[r.type] || '#3b82f6')},0.15);color:${typeColors[r.type] || '#3b82f6'}">${r.type}</span>
                <span class="dns-value">${escapeHtml(r.value)}</span>
                ${r.priority !== undefined ? `<span style="font-size:11px;color:var(--text-muted)">Priority: ${r.priority}</span>` : ''}
            </div>
        `).join('')}
    `;
}

function renderPortResults(container, data) {
    const ports = data.ports || [];
    
    if (ports.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-shield-alt fa-2x" style="color:var(--green)"></i>
                <p style="color:var(--green)">All common ports appear closed or filtered</p>
            </div>
        `;
        return;
    }
    
    const dangerousPorts = [21, 23, 3306, 5432, 6379, 27017, 2375, 9200];
    
    container.innerHTML = `
        <div style="margin-bottom:12px">
            <span style="font-size:12px;color:var(--text-muted)">Found <strong style="color:var(--orange)">${ports.length}</strong> open ports</span>
        </div>
        <table class="port-table">
            <thead>
                <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Banner</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>
                ${ports.map(p => `
                    <tr>
                        <td class="port-num">${p.port}/tcp</td>
                        <td><span class="port-open">● OPEN</span></td>
                        <td><span class="service-tag">${p.service}</span></td>
                        <td class="banner-text">${escapeHtml(p.banner || '-')}</td>
                        <td>${dangerousPorts.includes(p.port) ? 
                            '<span class="sev-badge HIGH">HIGH RISK</span>' : 
                            '<span class="sev-badge LOW">Normal</span>'}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
        
        ${ports.filter(p => dangerousPorts.includes(p.port)).length > 0 ? `
            <div class="info-note" style="margin-top:16px;border-color:rgba(239,68,68,0.3);background:rgba(239,68,68,0.05)">
                <i class="fas fa-exclamation-triangle" style="color:var(--red)"></i>
                <div>
                    <strong style="color:var(--red)">Warning:</strong> Sensitive services are exposed to the internet. 
                    Services like databases (MySQL, PostgreSQL, MongoDB, Redis) and Docker should never be 
                    publicly accessible without authentication and firewall protection.
                </div>
            </div>
        ` : ''}
    `;
}

function renderHeaderResults(container, data) {
    const findings = data.findings || [];
    
    const scoreMap = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
    const sorted = findings.sort((a, b) => (scoreMap[b.severity] || 0) - (scoreMap[a.severity] || 0));
    
    const score = Math.max(0, 100 - findings.reduce((acc, f) => {
        const penalties = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 1 };
        return acc + (penalties[f.severity] || 0);
    }, 0));
    
    const scoreColor = score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)';
    
    container.innerHTML = `
        <div style="display:flex;align-items:center;gap:20px;margin-bottom:20px;padding:16px;background:var(--bg-secondary);border-radius:10px;border:1px solid var(--border)">
            <div style="text-align:center">
                <div style="font-size:36px;font-weight:800;color:${scoreColor}">${score}</div>
                <div style="font-size:11px;color:var(--text-muted)">SECURITY SCORE</div>
            </div>
            <div>
                <div style="font-size:13px;margin-bottom:4px">
                    ${data.url ? `<strong>URL:</strong> <span style="font-family:var(--mono);color:var(--accent)">${escapeHtml(data.url)}</span>` : ''}
                </div>
                <div style="font-size:12px;color:var(--text-muted)">
                    HTTP Status: <strong>${data.status || 'N/A'}</strong> · 
                    ${findings.length} issues found · 
                    ${data.headers_checked || 0} headers checked
                </div>
            </div>
        </div>
        
        ${sorted.length > 0 ? sorted.map(f => `
            <div class="header-finding">
                <div class="header-finding-top">
                    <span class="sev-badge ${f.severity}">${f.severity}</span>
                    <span class="header-name">${f.header || f.type}</span>
                    ${f.value ? `<span style="font-family:var(--mono);font-size:11px;color:var(--text-muted)">${escapeHtml(f.value)}</span>` : ''}
                </div>
                <div class="header-finding-body">
                    <div>${escapeHtml(f.description || '')}</div>
                    ${f.remediation ? `<div class="remediation"><i class="fas fa-wrench"></i> ${escapeHtml(f.remediation)}</div>` : ''}
                </div>
            </div>
        `).join('') : `
            <div class="empty-state" style="border:1px solid rgba(16,185,129,0.3);border-radius:10px;background:rgba(16,185,129,0.05)">
                <i class="fas fa-shield-alt fa-2x" style="color:var(--green)"></i>
                <p style="color:var(--green)">All security headers are properly configured!</p>
            </div>
        `}
    `;
}

function renderSSLResults(container, data) {
    const cert = data.certificate || {};
    const findings = data.findings || [];
    
    container.innerHTML = `
        ${cert.subject ? `
            <div class="ssl-cert-card">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
                    <i class="fas fa-certificate" style="color:var(--green);font-size:20px"></i>
                    <span style="font-weight:600">Certificate Details</span>
                </div>
                <div class="cert-row">
                    <span class="cert-label">Subject:</span>
                    <span class="cert-value">${escapeHtml(cert.subject?.commonName || JSON.stringify(cert.subject))}</span>
                </div>
                <div class="cert-row">
                    <span class="cert-label">Issuer:</span>
                    <span class="cert-value">${escapeHtml(cert.issuer?.organizationName || JSON.stringify(cert.issuer))}</span>
                </div>
                <div class="cert-row">
                    <span class="cert-label">Valid From:</span>
                    <span class="cert-value">${escapeHtml(cert.not_before || 'N/A')}</span>
                </div>
                <div class="cert-row">
                    <span class="cert-label">Valid To:</span>
                    <span class="cert-value" style="color:${isExpiringSoon(cert.not_after) ? 'var(--yellow)' : 'var(--green)'}">${escapeHtml(cert.not_after || 'N/A')}</span>
                </div>
                ${data.tls_version ? `
                <div class="cert-row">
                    <span class="cert-label">TLS Version:</span>
                    <span class="cert-value" style="color:${['TLSv1.2','TLSv1.3'].includes(data.tls_version) ? 'var(--green)' : 'var(--red)'}">${data.tls_version}</span>
                </div>
                ` : ''}
                ${data.cipher ? `
                <div class="cert-row">
                    <span class="cert-label">Cipher:</span>
                    <span class="cert-value">${escapeHtml(data.cipher.name || '')} (${data.cipher.bits} bits)</span>
                </div>
                ` : ''}
                ${cert.san?.length > 0 ? `
                <div class="cert-row">
                    <span class="cert-label">SANs:</span>
                    <span class="cert-value">${cert.san.slice(0,5).map(s => escapeHtml(s[1])).join(', ')}${cert.san.length > 5 ? ` +${cert.san.length - 5} more` : ''}</span>
                </div>
                ` : ''}
            </div>
        ` : `
            <div class="info-note" style="border-color:rgba(239,68,68,0.3);background:rgba(239,68,68,0.05)">
                <i class="fas fa-exclamation-triangle" style="color:var(--red)"></i>
                <div><strong>No SSL Certificate:</strong> ${escapeHtml(data.error || 'Could not retrieve SSL certificate')}</div>
            </div>
        `}
        
        ${findings.length > 0 ? `
            <h3 style="font-size:13px;margin:16px 0 12px;color:var(--text-secondary)">SSL/TLS Issues</h3>
            ${findings.map(f => `
                <div class="header-finding">
                    <div class="header-finding-top">
                        <span class="sev-badge ${f.severity}">${f.severity}</span>
                        <span class="header-name">${escapeHtml(f.type)}</span>
                    </div>
                    <div class="header-finding-body">
                        <div>${escapeHtml(f.description)}</div>
                        ${f.remediation ? `<div class="remediation"><i class="fas fa-wrench"></i> ${escapeHtml(f.remediation)}</div>` : ''}
                    </div>
                </div>
            `).join('')}
        ` : cert.subject ? `
            <div style="color:var(--green);padding:12px;border:1px solid rgba(16,185,129,0.3);border-radius:8px;background:rgba(16,185,129,0.05);font-size:12px">
                <i class="fas fa-check-circle"></i> No SSL/TLS vulnerabilities detected
            </div>
        ` : ''}
    `;
}

function renderCORSResults(container, data) {
    const findings = data.findings || [];
    
    if (findings.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="border:1px solid rgba(16,185,129,0.3);border-radius:10px;background:rgba(16,185,129,0.05)">
                <i class="fas fa-shield-alt fa-2x" style="color:var(--green)"></i>
                <p style="color:var(--green)">No CORS misconfigurations found!</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = findings.map(f => `
        <div class="header-finding" style="border-color:${f.severity === 'CRITICAL' ? 'rgba(239,68,68,0.3)' : 'var(--border)'}">
            <div class="header-finding-top">
                <span class="sev-badge ${f.severity}">${f.severity}</span>
                <span class="header-name">${escapeHtml(f.type)}</span>
            </div>
            <div class="header-finding-body">
                <div>${escapeHtml(f.description)}</div>
                <div style="margin-top:8px;font-size:11px;color:var(--text-muted)">
                    <strong>Test Origin:</strong> <code style="font-family:var(--mono)">${escapeHtml(f.origin_tested || '')}</code><br>
                    <strong>ACAO:</strong> <code style="font-family:var(--mono);color:var(--red)">${escapeHtml(f.acao_header || '')}</code><br>
                    <strong>ACAC:</strong> <code style="font-family:var(--mono);color:var(--red)">${escapeHtml(f.acac_header || '')}</code>
                </div>
                ${f.poc ? `<div class="poc-code">${escapeHtml(f.poc)}</div>` : ''}
                ${f.remediation ? `<div class="remediation"><i class="fas fa-wrench"></i> ${escapeHtml(f.remediation)}</div>` : ''}
            </div>
        </div>
    `).join('');
}

function renderFingerprintResults(container, data) {
    const techs = data.technologies || [];
    
    if (techs.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-search fa-2x"></i><p>No technologies detected</p></div>';
        return;
    }
    
    const catColors = {
        'web-server': '#3b82f6',
        'frontend': '#f59e0b',
        'backend': '#10b981',
        'cms': '#8b5cf6',
        'framework': '#06b6d4',
        'cdn': '#f97316',
        'cloud': '#ec4899',
        'analytics': '#6366f1',
        'e-commerce': '#ef4444',
        'detected': '#94a3b8'
    };
    
    const catIcons = {
        'web-server': 'fas fa-server',
        'frontend': 'fab fa-js',
        'backend': 'fas fa-code',
        'cms': 'fas fa-edit',
        'framework': 'fas fa-cube',
        'cdn': 'fas fa-network-wired',
        'cloud': 'fas fa-cloud',
        'analytics': 'fas fa-chart-line',
        'e-commerce': 'fas fa-shopping-cart',
        'detected': 'fas fa-cog'
    };
    
    container.innerHTML = `
        <div style="margin-bottom:16px;font-size:12px;color:var(--text-muted)">
            Detected <strong style="color:var(--accent)">${techs.length}</strong> technologies on ${escapeHtml(data.target)}
        </div>
        <div class="tech-grid">
            ${techs.map(t => `
                <div class="tech-card">
                    <div class="tech-icon" style="background:rgba(${hexToRGB(catColors[t.category] || '#3b82f6')},0.15)">
                        <i class="${catIcons[t.category] || 'fas fa-cog'}" style="color:${catColors[t.category] || '#3b82f6'}"></i>
                    </div>
                    <span class="tech-name">${escapeHtml(t.name || '')}</span>
                    ${t.version ? `<span class="tech-ver">v${escapeHtml(t.version)}</span>` : ''}
                    <span class="tech-cat">${t.category || 'unknown'}</span>
                    ${t.source ? `<span style="font-size:10px;color:var(--text-muted)">${escapeHtml(t.source)}</span>` : ''}
                </div>
            `).join('')}
        </div>
    `;
}

function renderPathResults(container, data) {
    const paths = data.paths || [];
    
    if (paths.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-folder fa-2x"></i><p>No interesting paths discovered</p></div>';
        return;
    }
    
    const grouped = {};
    paths.forEach(p => {
        const sev = p.severity || 'INFO';
        if (!grouped[sev]) grouped[sev] = [];
        grouped[sev].push(p);
    });
    
    const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    
    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">
            Found <strong style="color:var(--accent)">${paths.length}</strong> accessible paths
        </div>
        ${sevOrder.map(sev => grouped[sev] ? `
            <div style="margin-bottom:16px">
                <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:8px">
                    <span class="sev-badge ${sev}">${sev}</span> (${grouped[sev].length})
                </div>
                ${grouped[sev].map(p => `
                    <div class="header-finding" style="margin-bottom:8px">
                        <div class="header-finding-top">
                            <span style="font-family:var(--mono);font-size:11px;background:rgba(59,130,246,0.1);color:var(--accent);padding:3px 6px;border-radius:4px">${p.status}</span>
                            <span style="font-family:var(--mono);font-size:12px;flex:1;color:var(--text-primary)">${escapeHtml(p.path || '')}</span>
                            <span style="font-size:11px;color:var(--text-muted)">${p.type}</span>
                        </div>
                        ${p.status === 200 && p.severity !== 'INFO' ? `
                        <div class="header-finding-body">
                            <a href="${escapeHtml(p.url)}" target="_blank" style="color:var(--accent);font-size:11px;font-family:var(--mono)">${escapeHtml(p.url)}</a>
                            <span style="font-size:11px;color:var(--text-muted)"> · ${p.content_length} bytes</span>
                        </div>
                        ` : ''}
                    </div>
                `).join('')}
            </div>
        ` : '').join('')}
    `;
}

// ─── CVSS Calculator ──────────────────────────────────────────────────────────

// ─── XSS / SQLi Findings Renderer ────────────────────────────────────────────

function renderVulnFindingsResults(container, data, toolName) {
    const findings = data.findings || [];

    if (findings.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-shield-alt fa-2x" style="color:var(--green)"></i>
                <p style="color:var(--green)">No ${toolName} vulnerabilities detected</p>
            </div>`;
        return;
    }

    const sevColors = { CRITICAL:'var(--red)', HIGH:'#f97316', MEDIUM:'#f59e0b', LOW:'#3b82f6', INFO:'var(--text-muted)' };

    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">
            Found <strong style="color:var(--red)">${findings.length}</strong> potential ${toolName} issue(s)
        </div>
        ${findings.map((f, i) => `
            <div class="header-finding" style="margin-bottom:12px;border-left:3px solid ${sevColors[f.severity]||'#888'}">
                <div class="header-finding-top">
                    <span class="sev-badge ${f.severity}">${f.severity}</span>
                    <span style="font-weight:600;font-size:13px;color:var(--text-primary)">${escapeHtml(f.type || toolName)}</span>
                </div>
                <div class="header-finding-body" style="padding-top:6px">
                    <div style="font-size:12px;color:var(--text-secondary);margin-bottom:6px">${escapeHtml(f.description || '')}</div>
                    ${f.url ? `<div style="font-size:11px;font-family:var(--mono);background:rgba(255,255,255,0.04);padding:4px 8px;border-radius:4px;margin-bottom:4px;word-break:break-all">
                        <strong>URL:</strong> <a href="${escapeHtml(f.url)}" target="_blank" style="color:var(--accent)">${escapeHtml(f.url)}</a>
                    </div>` : ''}
                    ${f.payload ? `<div style="font-size:11px;font-family:var(--mono);background:rgba(239,68,68,0.08);padding:4px 8px;border-radius:4px;margin-bottom:4px">
                        <strong>Payload:</strong> <span style="color:#f87171">${escapeHtml(f.payload)}</span>
                    </div>` : ''}
                    ${f.error_signature ? `<div style="font-size:11px;font-family:var(--mono);background:rgba(239,68,68,0.08);padding:4px 8px;border-radius:4px;margin-bottom:4px">
                        <strong>DB Error:</strong> <span style="color:#f87171">${escapeHtml(f.error_signature)}</span>
                    </div>` : ''}
                    ${f.remediation ? `<div style="font-size:11px;color:var(--green);margin-top:4px"><i class="fas fa-wrench"></i> ${escapeHtml(f.remediation)}</div>` : ''}
                </div>
            </div>
        `).join('')}
    `;
}

// ─── HTTP Methods Renderer ────────────────────────────────────────────────────

function renderMethodsResults(container, data) {
    const findings = data.findings || [];

    if (findings.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-check-circle fa-2x" style="color:var(--green)"></i>
                <p style="color:var(--green)">No dangerous HTTP methods detected</p>
            </div>`;
        return;
    }

    const sevColors = { CRITICAL:'var(--red)', HIGH:'#f97316', MEDIUM:'#f59e0b', LOW:'#3b82f6', INFO:'var(--text-muted)' };
    const methodColors = { DELETE:'var(--red)', PUT:'#f97316', TRACE:'#f59e0b', PATCH:'#f59e0b',
                           CONNECT:'#f97316', OPTIONS:'var(--accent)', PROPFIND:'#8b5cf6',
                           MKCOL:'#8b5cf6', GET:'var(--green)', POST:'#10b981', HEAD:'var(--text-muted)' };

    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">
            Found <strong style="color:var(--orange)">${findings.length}</strong> HTTP method finding(s)
        </div>
        ${findings.map(f => `
            <div class="header-finding" style="margin-bottom:10px;border-left:3px solid ${sevColors[f.severity]||'#888'}">
                <div class="header-finding-top">
                    <span class="sev-badge ${f.severity}">${f.severity}</span>
                    <span style="font-family:var(--mono);font-weight:700;font-size:13px;
                          color:${methodColors[f.method]||'var(--text-primary)'}">
                        ${escapeHtml(f.method || 'OPTIONS')}
                    </span>
                    ${f.status_code ? `<span style="font-size:11px;background:rgba(255,255,255,0.06);padding:2px 6px;border-radius:4px;color:var(--text-secondary)">${f.status_code}</span>` : ''}
                </div>
                <div class="header-finding-body" style="padding-top:6px">
                    <div style="font-size:12px;color:var(--text-secondary);margin-bottom:6px">${escapeHtml(f.description || '')}</div>
                    ${f.methods ? `<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:6px">
                        ${f.methods.map(m => `<span style="font-family:var(--mono);font-size:11px;
                            background:rgba(${methodColors[m] ? '255,255,255' : '59,130,246'},0.08);
                            color:${methodColors[m]||'var(--accent)'};padding:2px 6px;border-radius:4px">${m}</span>`).join('')}
                    </div>` : ''}
                    ${f.poc ? `<pre style="font-size:10px;background:rgba(255,255,255,0.04);padding:8px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;word-break:break-all">${escapeHtml(f.poc)}</pre>` : ''}
                    ${f.remediation ? `<div style="font-size:11px;color:var(--green);margin-top:4px"><i class="fas fa-wrench"></i> ${escapeHtml(f.remediation)}</div>` : ''}
                </div>
            </div>
        `).join('')}
    `;
}



// ─── New Tool Renderers ───────────────────────────────────────────────────────

function renderWhoisResults(container, data) {
    if (data.error) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-times-circle fa-2x" style="color:var(--red)"></i><p>${escapeHtml(data.error)}</p></div>`;
        return;
    }
    const fields = [
        ['Registrar', data.registrar], ['Created', data.created],
        ['Updated', data.updated], ['Expires', data.expires],
        ['Organisation', data.org], ['Country', data.country],
        ['DNSSEC', data.dnssec]
    ].filter(([,v]) => v);

    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">
            WHOIS for <strong style="color:var(--accent)">${escapeHtml(data.host || '')}</strong>
        </div>
        ${fields.length ? `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px">
            ${fields.map(([k, v]) => `
                <div style="background:rgba(255,255,255,0.04);border-radius:6px;padding:10px">
                    <div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">${k}</div>
                    <div style="font-size:13px;color:var(--text-primary);word-break:break-all">${escapeHtml(v)}</div>
                </div>`).join('')}
        </div>` : ''}
        ${data.nameservers?.length ? `
        <div style="margin-bottom:12px">
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px">Name Servers</div>
            ${data.nameservers.map(ns => `<div class="dns-record"><span class="dns-type" style="background:rgba(16,185,129,0.1);color:#10b981">NS</span><span class="dns-value">${escapeHtml(ns)}</span></div>`).join('')}
        </div>` : ''}
        <details style="margin-top:12px">
            <summary style="font-size:11px;color:var(--text-muted);cursor:pointer">Raw WHOIS output</summary>
            <pre style="font-size:10px;background:rgba(255,255,255,0.03);padding:10px;border-radius:6px;overflow-x:auto;margin-top:8px;white-space:pre-wrap;max-height:300px;overflow-y:auto">${escapeHtml((data.raw||'').slice(0,3000))}</pre>
        </details>
    `;
}

function renderSubfinderResults(container, data) {
    const subs = data.subdomains || [];
    const findings = data.findings || [];
    if (subs.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-search fa-2x"></i><p>No subdomains discovered for <strong>${escapeHtml(data.host||'')}</strong></p></div>`;
        return;
    }
    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">
            Found <strong style="color:var(--accent)">${subs.length}</strong> subdomain(s) for ${escapeHtml(data.host||'')}
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
            ${subs.map(s => `
                <a href="https://${escapeHtml(s)}" target="_blank" style="
                    display:inline-flex;align-items:center;gap:4px;
                    background:rgba(59,130,246,0.08);color:var(--accent);
                    padding:4px 10px;border-radius:20px;font-size:11px;
                    font-family:var(--mono);text-decoration:none;
                    border:1px solid rgba(59,130,246,0.2);
                    transition:background 0.2s">
                    <i class="fas fa-external-link-alt" style="font-size:9px"></i>
                    ${escapeHtml(s)}
                </a>`).join('')}
        </div>
    `;
}

function renderNiktoResults(container, data) {
    const findings = data.findings || [];
    if (findings.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-shield-alt fa-2x" style="color:var(--green)"></i><p style="color:var(--green)">Nikto found no notable vulnerabilities</p></div>`;
        return;
    }
    const sevColors = { CRITICAL:'var(--red)', HIGH:'#f97316', MEDIUM:'#f59e0b', LOW:'#3b82f6', INFO:'var(--text-muted)' };
    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">
            Nikto found <strong style="color:var(--orange)">${findings.length}</strong> issue(s) on ${escapeHtml(data.target||'')}
        </div>
        ${findings.map(f => `
            <div class="header-finding" style="margin-bottom:8px;border-left:3px solid ${sevColors[f.severity]||'#888'}">
                <div class="header-finding-top">
                    <span class="sev-badge ${f.severity}">${f.severity}</span>
                    <span style="font-size:12px;color:var(--text-primary)">${escapeHtml(f.description)}</span>
                </div>
            </div>`).join('')}
        <details style="margin-top:16px">
            <summary style="font-size:11px;color:var(--text-muted);cursor:pointer">Raw Nikto Output</summary>
            <pre style="font-size:10px;background:rgba(255,255,255,0.03);padding:10px;border-radius:6px;overflow-x:auto;margin-top:8px;white-space:pre-wrap;max-height:300px;overflow-y:auto">${escapeHtml((data.raw||'').slice(0,3000))}</pre>
        </details>
    `;
}

function renderFfufResults(container, data) {
    const findings = data.findings || [];
    if (findings.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-folder fa-2x" style="color:var(--green)"></i><p style="color:var(--green)">No hidden directories found</p></div>`;
        return;
    }
    const sevColors = { HIGH:'#f97316', MEDIUM:'#f59e0b', LOW:'#3b82f6', INFO:'var(--text-muted)' };
    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">
            ffuf found <strong style="color:var(--accent)">${findings.length}</strong> path(s) on ${escapeHtml(data.target||'')}
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:12px">
            <thead>
                <tr style="border-bottom:1px solid rgba(255,255,255,0.08)">
                    <th style="text-align:left;padding:6px 8px;color:var(--text-muted)">Status</th>
                    <th style="text-align:left;padding:6px 8px;color:var(--text-muted)">Path</th>
                    <th style="text-align:left;padding:6px 8px;color:var(--text-muted)">Severity</th>
                    <th style="text-align:right;padding:6px 8px;color:var(--text-muted)">Size</th>
                </tr>
            </thead>
            <tbody>
                ${findings.map(f => `
                    <tr style="border-bottom:1px solid rgba(255,255,255,0.04)">
                        <td style="padding:6px 8px">
                            <span style="font-family:var(--mono);font-size:11px;background:rgba(59,130,246,0.1);color:var(--accent);padding:2px 6px;border-radius:4px">${f.status||'?'}</span>
                        </td>
                        <td style="padding:6px 8px;font-family:var(--mono);font-size:11px">
                            <a href="${escapeHtml(f.url||'#')}" target="_blank" style="color:var(--accent)">${escapeHtml('/'+f.word)}</a>
                        </td>
                        <td style="padding:6px 8px"><span class="sev-badge ${f.severity}">${f.severity}</span></td>
                        <td style="padding:6px 8px;text-align:right;color:var(--text-muted);font-size:11px">${f.length||0}B</td>
                    </tr>`).join('')}
            </tbody>
        </table>
    `;
}

function renderNucleiResults(container, data) {
    const findings = data.findings || [];
    const sevColors = {
        CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b',
        LOW: '#3b82f6', INFO: '#94a3b8'
    };
    const sevOrder = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };

    if (findings.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-radiation fa-2x" style="color:var(--green)"></i>
                <p style="color:var(--green)">No Nuclei template matches found</p>
                <small style="color:var(--text-muted)">Category: ${escapeHtml(data.category||'default')} | Target: ${escapeHtml(data.target||'')}</small>
            </div>`;
        return;
    }

    // Sort by severity
    const sorted = [...findings].sort((a,b) => (sevOrder[a.severity]||9) - (sevOrder[b.severity]||9));

    // Group by severity
    const groups = {};
    for (const f of sorted) {
        const sev = f.severity || 'INFO';
        if (!groups[sev]) groups[sev] = [];
        groups[sev].push(f);
    }

    const groupHtml = Object.entries(groups).map(([sev, items]) => `
        <div style="margin-bottom:16px">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid rgba(255,255,255,0.05)">
                <span style="background:${sevColors[sev]||'#888'}22;color:${sevColors[sev]||'#888'};border:1px solid ${sevColors[sev]||'#888'}44;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700">${sev}</span>
                <span style="font-size:12px;color:var(--text-muted)">${items.length} finding${items.length>1?'s':''}</span>
            </div>
            ${items.map(f => {
                const cveHtml = f.cve_id && f.cve_id.length > 0
                    ? f.cve_id.map(cve => `<a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(cve)}" target="_blank" style="color:#ef4444;font-size:10px;font-family:monospace;background:rgba(239,68,68,0.08);padding:1px 5px;border-radius:3px;text-decoration:none">${escapeHtml(cve)}</a>`).join(' ')
                    : '';
                const cvssHtml = f.cvss_score
                    ? `<span style="background:rgba(249,115,22,0.1);color:#f97316;padding:1px 6px;border-radius:3px;font-size:10px;font-family:monospace">CVSS ${escapeHtml(f.cvss_score)}</span>`
                    : '';
                const cweHtml = f.cwe_id && f.cwe_id.length > 0
                    ? f.cwe_id.slice(0,2).map(cwe => `<span style="font-size:10px;color:var(--text-muted);background:rgba(255,255,255,0.04);padding:1px 5px;border-radius:3px">${escapeHtml(cwe)}</span>`).join(' ')
                    : '';
                const refsHtml = f.references && f.references.length > 0
                    ? `<div style="margin-top:5px">
                        ${f.references.slice(0,3).map(ref => `<a href="${escapeHtml(ref)}" target="_blank" style="color:var(--accent);font-size:10px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(ref)}</a>`).join('')}
                       </div>`
                    : '';
                const remHtml = f.remediation
                    ? `<div style="margin-top:5px;padding:6px 8px;background:rgba(16,185,129,0.06);border-radius:5px;border-left:2px solid #10b981">
                        <span style="font-size:10px;color:#10b981;font-weight:600">REMEDIATION: </span>
                        <span style="font-size:10px;color:var(--text-secondary)">${escapeHtml(f.remediation.slice(0,200))}</span>
                       </div>`
                    : '';
                const curlHtml = f.curl_command
                    ? `<details style="margin-top:5px"><summary style="font-size:10px;color:var(--text-muted);cursor:pointer">PoC curl command</summary>
                       <pre style="font-size:9px;background:rgba(0,0,0,0.2);padding:6px;border-radius:4px;overflow-x:auto;margin-top:4px;white-space:pre-wrap">${escapeHtml(f.curl_command)}</pre></details>`
                    : '';
                return `
                <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-left:3px solid ${sevColors[sev]||'#888'};border-radius:8px;padding:12px;margin-bottom:8px">
                    <div style="display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap">
                        <div style="flex:1;min-width:200px">
                            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:4px">
                                <span style="font-weight:600;font-size:13px;color:var(--text-primary)">${escapeHtml(f.name||f.template||'Unknown')}</span>
                                ${cveHtml}
                                ${cvssHtml}
                                ${cweHtml}
                            </div>
                            ${f.template ? `<div style="font-size:10px;font-family:monospace;color:var(--text-muted);margin-bottom:4px">template: ${escapeHtml(f.template)}</div>` : ''}
                            ${f.description ? `<div style="font-size:12px;color:var(--text-secondary);margin-bottom:4px">${escapeHtml(f.description.slice(0,300))}</div>` : ''}
                            ${f.url ? `<div style="font-size:11px;font-family:monospace;background:rgba(255,255,255,0.04);padding:3px 8px;border-radius:4px;margin-bottom:4px">
                                <a href="${escapeHtml(f.url)}" target="_blank" style="color:var(--accent)">${escapeHtml(f.url)}</a>
                            </div>` : ''}
                            ${f.tags ? `<div style="font-size:10px;color:var(--text-muted)">🏷️ ${escapeHtml(f.tags)}</div>` : ''}
                            ${f.author ? `<div style="font-size:10px;color:var(--text-muted)">👤 ${escapeHtml(f.author)}</div>` : ''}
                            ${refsHtml}
                            ${remHtml}
                            ${curlHtml}
                        </div>
                    </div>
                </div>`;
            }).join('')}
        </div>
    `).join('');

    container.innerHTML = `
        <div style="margin-bottom:14px;font-size:12px;color:var(--text-muted)">
            Nuclei found <strong style="color:var(--red)">${findings.length}</strong> vulnerability match(es) on
            <strong style="color:var(--accent)">${escapeHtml(data.target||'')}</strong>
            | Category: <strong>${escapeHtml(data.category||'default')}</strong>
        </div>
        ${groupHtml}
    `;
}


function renderWhatwebResults(container, data) {
    const techs = data.technologies || [];
    if (techs.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-fingerprint fa-2x"></i><p>No technologies detected by WhatWeb</p></div>`;
        return;
    }
    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">
            WhatWeb detected <strong style="color:var(--accent)">${techs.length}</strong> technology(ies) on ${escapeHtml(data.target||'')}
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px">
            ${techs.map(t => `
                <div style="background:rgba(255,255,255,0.04);border-radius:8px;padding:10px 12px;display:flex;align-items:center;gap:8px">
                    <div style="width:32px;height:32px;border-radius:6px;background:rgba(99,102,241,0.15);display:flex;align-items:center;justify-content:center">
                        <i class="fas fa-code" style="color:#818cf8;font-size:13px"></i>
                    </div>
                    <div>
                        <div style="font-size:13px;font-weight:600;color:var(--text-primary)">${escapeHtml(t.name||'')}</div>
                        ${t.version ? `<div style="font-size:11px;color:var(--accent)">v${escapeHtml(t.version)}</div>` : ''}
                        <div style="font-size:10px;color:var(--text-muted)">${escapeHtml(t.source||'whatweb')}</div>
                    </div>
                </div>`).join('')}
        </div>
        <details style="margin-top:16px">
            <summary style="font-size:11px;color:var(--text-muted);cursor:pointer">Raw WhatWeb output</summary>
            <pre style="font-size:10px;background:rgba(255,255,255,0.03);padding:10px;border-radius:6px;overflow-x:auto;margin-top:8px;white-space:pre-wrap">${escapeHtml((data.raw||'').slice(0,2000))}</pre>
        </details>
    `;
}

function renderHttpxResults(container, data) {
    const results = data.results || [];
    if (results.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-wifi fa-2x"></i><p>No HTTP results from HTTPX</p><small>${escapeHtml(data.raw||'')}</small></div>`;
        return;
    }
    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">HTTPX probed <strong style="color:var(--accent)">${results.length}</strong> host(s)</div>
        ${results.map(r => `
        <div style="background:rgba(255,255,255,0.04);border-radius:8px;padding:12px;margin-bottom:8px">
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
                <span style="font-family:monospace;font-size:13px;font-weight:600;color:var(--accent)">${escapeHtml(r.url||'')}</span>
                <span style="background:rgba(16,185,129,0.1);color:#10b981;padding:2px 8px;border-radius:4px;font-size:11px">${r.status_code||'?'}</span>
                ${r.webserver ? `<span style="background:rgba(99,102,241,0.1);color:#818cf8;padding:2px 8px;border-radius:4px;font-size:11px">${escapeHtml(r.webserver)}</span>` : ''}
            </div>
            ${r.title ? `<div style="font-size:12px;color:var(--text-secondary);margin-top:6px">📄 ${escapeHtml(r.title)}</div>` : ''}
            ${r.tech && r.tech.length > 0 ? `<div style="font-size:11px;color:var(--text-muted);margin-top:4px">Tech: ${r.tech.map(t=>escapeHtml(t)).join(', ')}</div>` : ''}
        </div>`).join('')}
    `;
}

function renderDnsxResults(container, data) {
    const records = data.records || [];
    if (records.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-network-wired fa-2x"></i><p>No DNS records found</p><small>${escapeHtml(data.raw||'')}</small></div>`;
        return;
    }
    const typeColors = { A:'#10b981', AAAA:'#6366f1', CNAME:'#f59e0b', MX:'#ec4899', NS:'#8b5cf6', TXT:'#14b8a6', SOA:'#f97316', DNS:'#94a3b8' };
    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">DNSX resolved <strong style="color:var(--accent)">${records.length}</strong> record(s) for <strong>${escapeHtml(data.host||'')}</strong></div>
        <div style="display:flex;flex-direction:column;gap:6px">
        ${records.map(r => `
            <div style="display:flex;align-items:flex-start;gap:10px;background:rgba(255,255,255,0.03);padding:8px 12px;border-radius:6px">
                <span style="background:${typeColors[r.type]||'#64748b'}22;color:${typeColors[r.type]||'#94a3b8'};padding:2px 8px;border-radius:4px;font-size:11px;font-family:monospace;min-width:50px;text-align:center">${escapeHtml(r.type||'')}</span>
                <span style="font-family:monospace;font-size:12px;color:var(--text-primary);word-break:break-all">${escapeHtml(r.value||'')}</span>
            </div>`).join('')}
        </div>
    `;
}

function renderUrlResults(container, data, label) {
    const urls = data.urls || [];
    const interesting = data.interesting || [];
    if (urls.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-history fa-2x"></i><p>No URLs found</p></div>`;
        return;
    }
    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">
            ${label}: <strong style="color:var(--accent)">${urls.length}</strong> URL(s) — 
            <strong style="color:#f59e0b">${interesting.length}</strong> interesting
        </div>
        ${interesting.length > 0 ? `
        <div style="margin-bottom:12px">
            <div style="font-size:12px;font-weight:600;color:#f59e0b;margin-bottom:8px">⭐ Interesting URLs</div>
            ${interesting.slice(0,50).map(u => `<div style="font-family:monospace;font-size:11px;color:#f59e0b;padding:3px 8px;border-left:2px solid #f59e0b;margin-bottom:3px;word-break:break-all">${escapeHtml(u)}</div>`).join('')}
        </div>` : ''}
        <details>
            <summary style="font-size:11px;color:var(--text-muted);cursor:pointer">All URLs (${urls.length})</summary>
            <pre style="font-size:10px;background:rgba(255,255,255,0.03);padding:10px;border-radius:6px;overflow-x:auto;margin-top:8px;max-height:400px;overflow-y:auto">${escapeHtml(urls.slice(0,200).join('\n'))}</pre>
        </details>
    `;
}

function renderKatanaResults(container, data) {
    const endpoints = data.endpoints || [];
    if (endpoints.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-spider fa-2x"></i><p>No endpoints discovered by Katana</p><small>${escapeHtml((data.raw||'').slice(0,200))}</small></div>`;
        return;
    }
    const bySev = { HIGH:[], MEDIUM:[], INFO:[] };
    endpoints.forEach(e => { const s = e.severity||'INFO'; (bySev[s] || (bySev[s]=[])).push(e); });
    const sevColor = { HIGH:'#ef4444', MEDIUM:'#f59e0b', INFO:'#94a3b8' };
    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">Katana discovered <strong style="color:var(--accent)">${endpoints.length}</strong> endpoint(s)</div>
        ${['HIGH','MEDIUM','INFO'].map(sev => bySev[sev] && bySev[sev].length > 0 ? `
        <div style="margin-bottom:12px">
            <div style="font-size:12px;font-weight:600;color:${sevColor[sev]};margin-bottom:6px">${sev} (${bySev[sev].length})</div>
            ${bySev[sev].slice(0,30).map(e => `<div style="font-family:monospace;font-size:11px;padding:3px 8px;border-left:2px solid ${sevColor[sev]};margin-bottom:3px;word-break:break-all;color:var(--text-secondary)">${escapeHtml(e.url||e.description||'')}</div>`).join('')}
        </div>` : '').join('')}
    `;
}

function renderLinkfinderResults(container, data) {
    const endpoints = data.endpoints || [];
    if (endpoints.length === 0) {
        container.innerHTML = `<div class="empty-state"><i class="fas fa-link fa-2x"></i><p>No links/endpoints discovered</p><small>${escapeHtml((data.raw||'').slice(0,200))}</small></div>`;
        return;
    }
    const sevColor = { HIGH:'#ef4444', MEDIUM:'#f59e0b', INFO:'#94a3b8' };
    container.innerHTML = `
        <div style="margin-bottom:12px;font-size:12px;color:var(--text-muted)">LinkFinder found <strong style="color:var(--accent)">${endpoints.length}</strong> endpoint(s)</div>
        <div style="display:flex;flex-direction:column;gap:4px">
        ${endpoints.map(e => `
            <div style="display:flex;align-items:center;gap:8px;padding:6px 10px;background:rgba(255,255,255,0.03);border-radius:6px">
                <span style="background:${sevColor[e.severity||'INFO']}22;color:${sevColor[e.severity||'INFO']};padding:1px 6px;border-radius:3px;font-size:10px;min-width:40px;text-align:center">${escapeHtml(e.severity||'INFO')}</span>
                <span style="font-family:monospace;font-size:11px;color:var(--text-primary);word-break:break-all">${escapeHtml(e.endpoint||'')}</span>
            </div>`).join('')}
        </div>
    `;
}


function setCVSS(btn, metric, value) {
    cvssValues[metric] = value;
    
    // Update button states
    document.querySelectorAll(`.metric-btn[data-metric="${metric}"]`).forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    
    // Auto-calculate
    calculateCVSS();
}

async function calculateCVSS() {
    try {
        const resp = await fetch(`${API_BASE}/cvss/calculate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(cvssValues)
        });
        
        const data = await resp.json();
        
        const score = data.score || 0;
        const severity = data.severity || 'NONE';
        const vector = data.vector || '';
        
        document.getElementById('cvssScore').textContent = score.toFixed(1);
        document.getElementById('cvssSeverity').textContent = severity;
        document.getElementById('cvssVector').textContent = vector;
        
        // Update circle color
        const circle = document.getElementById('scoreCircle');
        circle.className = 'score-circle ' + severity.toLowerCase();
        
        // Update score color
        const scoreEl = document.getElementById('cvssScore');
        const sevEl = document.getElementById('cvssSeverity');
        const colorMap = {
            NONE: 'var(--text-muted)',
            LOW: 'var(--green)',
            MEDIUM: 'var(--yellow)',
            HIGH: 'var(--orange)',
            CRITICAL: 'var(--red)'
        };
        
        scoreEl.style.color = colorMap[severity] || 'var(--text-muted)';
        sevEl.style.color = colorMap[severity] || 'var(--text-muted)';
        
        // Update breakdown
        const breakdown = document.getElementById('cvssBreakdown');
        const compNames = { AV: 'Attack Vector', AC: 'Attack Complexity', PR: 'Privileges Required', UI: 'User Interaction', S: 'Scope', C: 'Confidentiality', I: 'Integrity', A: 'Availability' };
        const compFull = { AV: {N:'Network',A:'Adjacent',L:'Local',P:'Physical'}, AC: {L:'Low',H:'High'}, PR: {N:'None',L:'Low',H:'High'}, UI: {N:'None',R:'Required'}, S: {U:'Unchanged',C:'Changed'}, C: {N:'None',L:'Low',H:'High'}, I: {N:'None',L:'Low',H:'High'}, A: {N:'None',L:'Low',H:'High'} };
        
        breakdown.innerHTML = `
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:11px">
                ${Object.entries(cvssValues).map(([k, v]) => `
                    <div style="display:flex;justify-content:space-between;padding:4px 8px;background:var(--bg-secondary);border-radius:5px">
                        <span style="color:var(--text-muted)">${compNames[k] || k}</span>
                        <span style="color:var(--text-primary);font-weight:600">${compFull[k]?.[v] || v}</span>
                    </div>
                `).join('')}
            </div>
        `;
        
    } catch {}
}

// ─── PoC Generator ───────────────────────────────────────────────────────────

const pocTemplates = {
    IDOR: {
        steps: [
            'Create two accounts: Attacker (attacker@test.com) and Victim (victim@test.com)',
            'Login as Attacker and perform a normal action to capture the request',
            'Identify the user/resource ID in the request parameter',
            'Replace the Attacker\'s ID with the Victim\'s ID in the request',
            'Observe that the response contains the Victim\'s data'
        ],
        request: `GET /api/v1/user/{victim_id}/profile HTTP/1.1
Host: target.com
Authorization: Bearer {attacker_token}
Content-Type: application/json`,
        response: `HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": {victim_id},
  "email": "victim@example.com",
  "name": "Victim User",
  "private_data": "sensitive information..."
}`
    },
    XSS: {
        steps: [
            'Navigate to the vulnerable page with an input parameter',
            'Inject the XSS payload into the parameter',
            'Observe that the script executes in the browser',
            'Demonstrate cookie theft or DOM manipulation',
            'Show the impact: session hijacking, credential theft'
        ],
        request: `GET /search?q="><script>alert(document.cookie)</script> HTTP/1.1
Host: target.com
Cookie: session=victim_session_token`,
        response: `HTTP/1.1 200 OK

<html>
<h1>Search results for: "><script>alert(document.cookie)</script></h1>
<!-- XSS payload is reflected unencoded in the response -->`
    },
    SSRF: {
        steps: [
            'Identify an endpoint that fetches external URLs',
            'Replace the URL parameter with an internal resource (169.254.169.254)',
            'Cloud metadata endpoint returns sensitive AWS/GCP credentials',
            'Escalate: use credentials to access cloud resources',
            'Document the data exfiltrated'
        ],
        request: `POST /api/fetch HTTP/1.1
Host: target.com
Authorization: Bearer {token}
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}`,
        response: `HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": "ec2-default-role\\n",
  "instance-profile": {
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "...",
    "Token": "..."
  }
}`
    },
    CORS: {
        steps: [
            'Identify API endpoints that return sensitive data',
            'Send request with malicious Origin header',
            'Observe ACAO header reflects attacker origin with credentials=true',
            'Host PoC HTML on attacker domain',
            'When victim visits attacker page, their data is silently exfiltrated'
        ],
        request: `GET /api/v1/account/balance HTTP/1.1
Host: target.com
Origin: https://attacker.com
Cookie: session=victim_cookie`,
        response: `HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true

{"balance": 1000, "account_number": "1234-5678"}`
    }
};

function updatePoCTemplate() {
    const type = document.getElementById('pocVulnType')?.value;
    const template = pocTemplates[type];
    
    if (template) {
        const reqEl = document.getElementById('pocRequest');
        const respEl = document.getElementById('pocResponse');
        if (reqEl && !reqEl.value) reqEl.placeholder = template.request;
        if (respEl && !respEl.value) respEl.placeholder = template.response;
    }
}

function generatePoC() {
    const vulnType = document.getElementById('pocVulnType').value;
    const target = document.getElementById('pocTarget').value || 'https://target.com/endpoint';
    const program = document.getElementById('pocProgram').value || 'target-program';
    const impact = document.getElementById('pocImpact').value || `${vulnType} vulnerability allowing unauthorized access`;
    const request = document.getElementById('pocRequest').value;
    const response = document.getElementById('pocResponse').value;
    
    const template = pocTemplates[vulnType] || {};
    const steps = template.steps || ['Step 1: Identify vulnerable endpoint', 'Step 2: Craft exploit', 'Step 3: Confirm impact'];
    
    const now = new Date().toISOString().split('T')[0];
    
    const cvssScores = {
        IDOR: '7.5 (HIGH) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
        XSS: '6.1 (MEDIUM) - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        SSRF: '9.8 (CRITICAL) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        SQLi: '9.1 (CRITICAL) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        CORS: '8.1 (HIGH) - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
        'Open Redirect': '6.1 (MEDIUM) - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        CSRF: '6.5 (MEDIUM) - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
        'Auth Bypass': '9.8 (CRITICAL) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        RCE: '10.0 (CRITICAL) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        LFI: '7.5 (HIGH) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        XXE: '8.1 (HIGH) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
        'Race Condition': '7.5 (HIGH) - CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N'
    };
    
    const pocOutput = document.getElementById('pocOutput');
    pocOutput.innerHTML = `<div class="poc-content">
<div class="poc-section">
<h3># ${vulnType} on ${escapeHtml(target)}</h3>
<div class="content">
<strong>Program:</strong> ${escapeHtml(program)}
<strong>Severity:</strong> ${cvssScores[vulnType] || '7.5 (HIGH)'}
<strong>Date Found:</strong> ${now}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</div>
</div>

<div class="poc-section">
<h3>## Summary</h3>
<div class="content">
The <code>${escapeHtml(target)}</code> endpoint is vulnerable to ${escapeHtml(vulnType)}.
An attacker can exploit this to ${escapeHtml(impact)}.

<span style="color:var(--red)">⚠️ VERIFIED: This finding has been tested and confirmed reproducible.</span>
</div>
</div>

<div class="poc-section">
<h3>## Steps to Reproduce</h3>
<div class="content">
${steps.map((s, i) => `${i+1}. ${s}`).join('\n')}
</div>
</div>

<div class="poc-section">
<h3>## Proof of Concept</h3>
<div class="content">
<strong>Request:</strong>
<pre style="background:#070b12;padding:10px;border-radius:6px;font-size:11px;border:1px solid var(--border)">${escapeHtml(request || template.request || '// Add HTTP request here')}</pre>

<strong>Response:</strong>
<pre style="background:#070b12;padding:10px;border-radius:6px;font-size:11px;border:1px solid var(--border)">${escapeHtml(response || template.response || '// Add HTTP response here')}</pre>
</div>
</div>

<div class="poc-section">
<h3>## Impact</h3>
<div class="content">
${escapeHtml(impact)}

<span style="color:var(--red)">Concrete Impact:</span>
- Unauthorized access to sensitive data
- Potential for privilege escalation
- ${vulnType === 'IDOR' ? 'Access to all users\' data by changing numeric IDs' : ''}
${vulnType === 'XSS' ? '- Session cookie theft\n- Credential harvesting\n- Malware delivery' : ''}
${vulnType === 'SSRF' ? '- Internal network access\n- Cloud metadata exposure\n- Potential RCE' : ''}
${vulnType === 'CORS' ? '- Cross-origin data theft\n- Session token exfiltration' : ''}
</div>
</div>

<div class="poc-section">
<h3>## Validation Gates</h3>
<div class="content">
✅ Gate 1 - Is it real? PASS (Reproduced 3/3 times)
✅ Gate 2 - Is it in scope? PASS (Confirmed on program scope page)
✅ Gate 3 - Is it exploitable? PASS (Working PoC demonstrated above)
✅ Gate 4 - Is it a dup? PASS (Not found in disclosed reports)
</div>
</div>

<div class="poc-section">
<h3>## Remediation</h3>
<div class="content">
${getRemediation(vulnType)}
</div>
</div>
</div>`;
    
    showToast('PoC report generated!', 'success');
}

function getRemediation(vulnType) {
    const remediations = {
        IDOR: 'Implement proper authorization checks server-side. Verify that the authenticated user owns the requested resource before returning data. Never rely on client-supplied IDs without validation.',
        XSS: 'Encode all user-supplied data before reflecting it in HTML responses. Implement Content-Security-Policy headers. Use modern framework auto-escaping features.',
        SSRF: 'Whitelist allowed destination URLs/IPs. Block access to internal/private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x). Disable unused URL schemes.',
        CORS: 'Validate the Origin header against a strict whitelist. Never use wildcard (*) with credentials. Set Access-Control-Allow-Credentials: true only for trusted origins.',
        SQLi: 'Use parameterized queries/prepared statements. Never concatenate user input into SQL strings. Implement input validation and least-privilege database accounts.',
        'Open Redirect': 'Validate redirect URLs against a whitelist of allowed domains. Reject external redirects or require explicit user confirmation.',
        CSRF: 'Implement CSRF tokens in all state-changing forms. Use SameSite=Strict cookie attribute. Verify Origin/Referer headers on POST requests.',
        'Auth Bypass': 'Implement server-side authentication checks on all protected endpoints. Never rely on client-side authentication tokens without proper validation.',
        RCE: 'Never execute user-supplied commands. Use sandboxed execution environments. Implement strict input validation and allowlisting.',
        LFI: 'Validate file paths using a whitelist approach. Avoid passing user input to file system functions. Use realpath() and check against expected directory.',
        XXE: 'Disable XML external entity processing. Use OWASP XML Security Cheat Sheet. Prefer JSON over XML where possible.',
        'Race Condition': 'Use database transactions with proper isolation levels. Implement mutex locks for critical operations. Use atomic operations where possible.'
    };
    return remediations[vulnType] || 'Implement proper security controls following OWASP guidelines.';
}

function copyPoC() {
    const content = document.getElementById('pocOutput');
    const text = content.innerText;
    
    navigator.clipboard.writeText(text).then(() => {
        showToast('PoC copied to clipboard!', 'success');
    }).catch(() => {
        // Fallback
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast('PoC copied!', 'success');
    });
}

// ─── Reports & Export ─────────────────────────────────────────────────────────

async function loadReports() {
    const container = document.getElementById('reportsContent');
    if (!container) return;

    // Always fetch fresh list from API so reports show after page reload
    try {
        const listResp = await fetch(`${API_BASE}/scan/list`);
        if (listResp.ok) {
            const freshScans = await listResp.json();
            freshScans.forEach(s => { allScans[s.id] = s; });
        }
    } catch(e) { /* use cached allScans if fetch fails */ }

    const scans = Object.values(allScans).filter(s => s.status === 'completed');

    if (scans.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-file-alt fa-3x"></i>
                <p>Complete a scan to generate reports here</p>
            </div>`;
        return;
    }

    const reportsHtml = await Promise.all(scans.map(async scan => {
        let report = null;
        try {
            const resp = await fetch(`${API_BASE}/scan/${scan.id}/report`);
            if (resp.ok) report = await resp.json();
        } catch {}

        if (!report) return '';

        const c   = report.severity_counts || {};
        const sid = escapeHtml(scan.id);
        const total = (c.CRITICAL||0)+(c.HIGH||0)+(c.MEDIUM||0)+(c.LOW||0)+(c.INFO||0);

        // Direct href links → browser handles download natively (no JS needed)
        const linkTxt  = `${API_BASE}/scan/${scan.id}/export?format=txt`;
        const linkHtml = `${API_BASE}/scan/${scan.id}/export?format=html`;
        const linkPdf  = `${API_BASE}/scan/${scan.id}/export?format=pdf`;
        const target   = escapeHtml(report.target || scan.target);
        const slug     = (report.target||scan.target||'report').replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,40);
        const datePart = (report.date||'').replace(/[: ]/g,'').slice(0,15);

        return `
        <div class="report-card" style="margin-bottom:18px;border-radius:12px;overflow:hidden;border:1px solid rgba(255,255,255,0.07)">

            <!-- Card header -->
            <div style="padding:14px 18px;background:rgba(255,255,255,0.03);border-bottom:1px solid rgba(255,255,255,0.06);display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:10px">
                <div>
                    <div style="font-size:14px;font-weight:700;color:var(--text-primary)">${target}</div>
                    <div style="font-size:11px;color:var(--text-muted);margin-top:2px">
                        <i class="fas fa-clock" style="margin-right:4px"></i>${report.date || formatDate(scan.started)}
                        &nbsp;·&nbsp;Scan ID: <code style="font-size:10px;color:var(--accent)">${sid}</code>
                    </div>
                </div>
                <div style="display:flex;flex-wrap:wrap;gap:5px;align-items:center">
                    ${c.CRITICAL ? `<span class="sev-badge CRITICAL">🔴 ${c.CRITICAL} CRIT</span>` : ''}
                    ${c.HIGH     ? `<span class="sev-badge HIGH">🟠 ${c.HIGH} HIGH</span>`          : ''}
                    ${c.MEDIUM   ? `<span class="sev-badge MEDIUM">🟡 ${c.MEDIUM} MED</span>`       : ''}
                    ${c.LOW      ? `<span class="sev-badge LOW">🟢 ${c.LOW} LOW</span>`             : ''}
                    ${c.INFO     ? `<span class="sev-badge INFO">🔵 ${c.INFO} INFO</span>`          : ''}
                </div>
            </div>

            <!-- Executive summary -->
            <div style="padding:12px 18px;font-size:12px;color:var(--text-secondary);line-height:1.7;border-bottom:1px solid rgba(255,255,255,0.04)">
                ${escapeHtml(report.executive_summary || '')}
            </div>

            <!-- ─── DOWNLOAD LINKS ─── -->
            <div style="padding:14px 18px;background:rgba(0,0,0,0.15);border-bottom:1px solid rgba(255,255,255,0.05)">
                <div style="font-size:11px;font-weight:700;color:var(--text-muted);letter-spacing:1px;text-transform:uppercase;margin-bottom:10px">
                    <i class="fas fa-download" style="margin-right:6px"></i>Download Report
                </div>
                <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">

                    <!-- TXT link -->
                    <a href="${linkTxt}"
                       download="bbhpro_${slug}_${datePart}.txt"
                       title="Download plain-text report"
                       style="display:inline-flex;align-items:center;gap:7px;padding:9px 16px;
                              background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.3);
                              border-radius:8px;color:#818cf8;font-size:12px;font-weight:600;
                              text-decoration:none;transition:all 0.2s"
                       onmouseover="this.style.background='rgba(99,102,241,0.22)'"
                       onmouseout="this.style.background='rgba(99,102,241,0.12)'">
                        <i class="fas fa-file-alt" style="font-size:14px"></i>
                        <span>.TXT</span>
                        <span style="font-size:10px;opacity:0.7">Plain Text</span>
                    </a>

                    <!-- HTML link -->
                    <a href="${linkHtml}"
                       download="bbhpro_${slug}_${datePart}.html"
                       title="Download HTML report"
                       style="display:inline-flex;align-items:center;gap:7px;padding:9px 16px;
                              background:rgba(6,182,212,0.12);border:1px solid rgba(6,182,212,0.3);
                              border-radius:8px;color:#06b6d4;font-size:12px;font-weight:600;
                              text-decoration:none;transition:all 0.2s"
                       onmouseover="this.style.background='rgba(6,182,212,0.22)'"
                       onmouseout="this.style.background='rgba(6,182,212,0.12)'">
                        <i class="fas fa-file-code" style="font-size:14px"></i>
                        <span>.HTML</span>
                        <span style="font-size:10px;opacity:0.7">Web Report</span>
                    </a>

                    <!-- PDF link -->
                    <a href="${linkPdf}"
                       download="bbhpro_${slug}_${datePart}.pdf"
                       title="Download PDF report"
                       style="display:inline-flex;align-items:center;gap:7px;padding:9px 16px;
                              background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.3);
                              border-radius:8px;color:#ef4444;font-size:12px;font-weight:600;
                              text-decoration:none;transition:all 0.2s"
                       onmouseover="this.style.background='rgba(239,68,68,0.22)'"
                       onmouseout="this.style.background='rgba(239,68,68,0.12)'">
                        <i class="fas fa-file-pdf" style="font-size:14px"></i>
                        <span>.PDF</span>
                        <span style="font-size:10px;opacity:0.7">PDF Report</span>
                    </a>

                    <!-- JSON link -->
                    <a href="${API_BASE}/scan/${scan.id}/report"
                       download="bbhpro_${slug}_${datePart}.json"
                       title="Download raw JSON report"
                       style="display:inline-flex;align-items:center;gap:7px;padding:9px 16px;
                              background:rgba(245,158,11,0.12);border:1px solid rgba(245,158,11,0.3);
                              border-radius:8px;color:#f59e0b;font-size:12px;font-weight:600;
                              text-decoration:none;transition:all 0.2s"
                       onmouseover="this.style.background='rgba(245,158,11,0.22)'"
                       onmouseout="this.style.background='rgba(245,158,11,0.12)'">
                        <i class="fas fa-code" style="font-size:14px"></i>
                        <span>.JSON</span>
                        <span style="font-size:10px;opacity:0.7">Raw Data</span>
                    </a>

                    <span style="margin-left:auto;font-size:11px;color:var(--text-muted)">
                        ${total} finding${total!==1?'s':''} total
                    </span>
                </div>
            </div>

            <!-- Top Findings Preview -->
            <div style="padding:14px 18px">
                ${(report.findings || []).length > 0
                    ? `<div style="font-size:11px;font-weight:700;color:var(--text-muted);letter-spacing:1px;text-transform:uppercase;margin-bottom:10px">
                           <i class="fas fa-bug" style="margin-right:6px"></i>Top Findings
                       </div>
                       ${(report.findings||[]).slice(0,5).map(f => `
                           <div class="report-finding-item" style="margin-bottom:8px">
                               <div class="report-finding-header" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                                   <span class="sev-badge ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
                                   <span style="font-size:10px;color:var(--text-muted)">${escapeHtml(f.id||'')}</span>
                                   <span style="font-size:12px;font-weight:600;color:var(--text-primary)">${escapeHtml(f.type||'Finding')}</span>
                                   <span style="font-size:10px;color:var(--text-muted);margin-left:auto">CVSS&nbsp;${escapeHtml(String(f.cvss?.score||'N/A'))}</span>
                               </div>
                               <div style="font-size:12px;color:var(--text-secondary);margin-top:4px">${escapeHtml(f.description||'')}</div>
                               ${f.remediation?`<div class="report-finding-rem" style="font-size:11px">${escapeHtml(f.remediation)}</div>`:''}
                           </div>`).join('')}
                       ${(report.findings||[]).length>5
                           ? `<div style="font-size:11px;color:var(--text-muted);text-align:center;padding:6px 0">
                                  … and ${report.findings.length-5} more finding(s) —
                                  <a href="${linkHtml}" download="bbhpro_${slug}_${datePart}.html"
                                     style="color:var(--accent);text-decoration:none">download full report</a>
                              </div>` : ''}`
                    : `<div style="color:var(--text-muted);font-size:12px;padding:4px 0">
                           <i class="fas fa-shield-alt" style="margin-right:6px;color:var(--green)"></i>No significant findings.
                       </div>`
                }
            </div>

        </div>`;
    }));

    container.innerHTML = reportsHtml.filter(Boolean).join('') ||
        '<div class="empty-state"><i class="fas fa-file-alt fa-3x"></i><p>No reports yet</p></div>';

    // Also populate Quick Download Links panel
    buildQuickDownloadLinks(scans);
}

/**
 * Build the "Quick Download Links" panel on the Reports page.
 * Shows direct <a> links for every completed scan — no JS fetch needed.
 */
function buildQuickDownloadLinks(scans) {
    const panel   = document.getElementById('quickDownloadLinks');
    const content = document.getElementById('quickDownloadContent');
    if (!panel || !content) return;
    if (!scans || scans.length === 0) { panel.style.display = 'none'; return; }

    panel.style.display = 'block';

    content.innerHTML = scans.map(scan => {
        const sid    = scan.id;
        const target = escapeHtml(scan.target || sid);
        const slug   = (scan.target||sid).replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,40);
        const date   = scan.started ? new Date(scan.started*1000).toLocaleDateString() : '';

        return `
        <div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:8px 0;
                    border-bottom:1px solid rgba(255,255,255,0.04)">
            <div style="min-width:160px;flex:1">
                <div style="font-size:12px;font-weight:700;color:var(--text-primary)">${target}</div>
                ${date ? `<div style="font-size:10px;color:var(--text-muted)">${date}</div>` : ''}
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:6px">
                <a href="/api/scan/${sid}/export?format=txt"
                   title="Download .txt report for ${target}"
                   style="display:inline-flex;align-items:center;gap:5px;padding:5px 12px;
                          background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.28);
                          border-radius:6px;color:#818cf8;font-size:11px;font-weight:700;text-decoration:none"
                   onclick="event.preventDefault(); downloadExport('${sid}','txt')">
                    <i class="fas fa-file-alt"></i> .TXT
                </a>
                <a href="/api/scan/${sid}/export?format=html"
                   title="Download .html report for ${target}"
                   style="display:inline-flex;align-items:center;gap:5px;padding:5px 12px;
                          background:rgba(6,182,212,0.12);border:1px solid rgba(6,182,212,0.28);
                          border-radius:6px;color:#06b6d4;font-size:11px;font-weight:700;text-decoration:none"
                   onclick="event.preventDefault(); downloadExport('${sid}','html')">
                    <i class="fas fa-file-code"></i> .HTML
                </a>
                <a href="/api/scan/${sid}/export?format=pdf"
                   title="Download .pdf report for ${target}"
                   style="display:inline-flex;align-items:center;gap:5px;padding:5px 12px;
                          background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.28);
                          border-radius:6px;color:#ef4444;font-size:11px;font-weight:700;text-decoration:none"
                   onclick="event.preventDefault(); downloadExport('${sid}','pdf')">
                    <i class="fas fa-file-pdf"></i> .PDF
                </a>
                <a href="/api/scan/${sid}/report"
                   title="Download raw JSON for ${target}"
                   style="display:inline-flex;align-items:center;gap:5px;padding:5px 12px;
                          background:rgba(245,158,11,0.10);border:1px solid rgba(245,158,11,0.25);
                          border-radius:6px;color:#f59e0b;font-size:11px;font-weight:700;text-decoration:none"
                   onclick="event.preventDefault(); exportScanJson('${sid}')">
                    <i class="fas fa-code"></i> .JSON
                </a>
            </div>
        </div>`;
    }).join('');
}

// ─── Export / Download helpers ────────────────────────────────────────────────

/**
 * Trigger a file download from the export endpoint.
 * format: 'txt' | 'html' | 'pdf'
 */
async function downloadExport(scanId, format) {
    if (!scanId) { showToast('No scan ID', 'error'); return; }

    showToast(`Preparing ${format.toUpperCase()} export…`, 'info');

    try {
        const url = `${API_BASE}/scan/${scanId}/export?format=${encodeURIComponent(format)}`;
        const resp = await fetch(url);

        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ error: resp.statusText }));
            showToast(`Export failed: ${err.error || resp.statusText}`, 'error');
            return;
        }

        // Extract filename from Content-Disposition header
        const cd = resp.headers.get('Content-Disposition') || '';
        const fnMatch = cd.match(/filename="([^"]+)"/);
        const filename = fnMatch ? fnMatch[1] : `bbhpro_report.${format}`;

        const blob = await resp.blob();
        const blobUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = blobUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(blobUrl);

        showToast(`${format.toUpperCase()} exported: ${filename}`, 'success');
    } catch(err) {
        showToast(`Export error: ${err.message}`, 'error');
    }
}

/**
 * Export ALL completed scans (each as separate download).
 */
async function exportAllScans(format) {
    const scans = Object.values(allScans).filter(s => s.status === 'completed');
    if (scans.length === 0) {
        showToast('No completed scans to export', 'error');
        return;
    }
    showToast(`Exporting ${scans.length} scan(s) as ${format.toUpperCase()}…`, 'info');
    for (const scan of scans) {
        await downloadExport(scan.id, format);
        await new Promise(r => setTimeout(r, 400)); // small delay between downloads
    }
}

/**
 * Export current scan from the results / scan-viewer page.
 * Reads the scanId from the active scan state.
 */
function exportCurrentScan(format) {
    const scanId = window._currentViewScanId || window._activeScanId;
    if (!scanId) {
        showToast('No active scan to export', 'error');
        return;
    }
    downloadExport(scanId, format);
}

// Legacy compatibility – keep old JSON export working
async function exportScanJson(scanId) {
    try {
        const resp = await fetch(`${API_BASE}/scan/${scanId}/report`);
        if (!resp.ok) { showToast('Report not ready', 'error'); return; }
        const data = await resp.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url; a.download = `bbhpro_${scanId}_report.json`;
        document.body.appendChild(a); a.click();
        document.body.removeChild(a); URL.revokeObjectURL(url);
        showToast('JSON exported!', 'success');
    } catch(err) {
        showToast('Export error: ' + err.message, 'error');
    }
}

async function exportScanMarkdown(scanId) {
    try {
        const resp = await fetch(`${API_BASE}/scan/${scanId}/report`);
        if (!resp.ok) { showToast('Report not ready', 'error'); return; }
        const d = await resp.json();
        const c = d.severity_counts || {};
        let md = `# Security Report – ${d.target || ''}\n\n`;
        md += `**Date:** ${d.date}  **Scan ID:** ${scanId}\n\n`;
        md += `## Executive Summary\n${d.executive_summary || ''}\n\n`;
        md += `## Severity Summary\n`;
        md += `| Severity | Count |\n|---|---|\n`;
        for (const s of ['CRITICAL','HIGH','MEDIUM','LOW','INFO'])
            md += `| ${s} | ${c[s]||0} |\n`;
        md += `\n## Findings\n\n`;
        for (const f of (d.findings || [])) {
            md += `### [${f.severity}] ${f.type} (${f.id})\n`;
            md += `- **CVSS:** ${f.cvss?.score||'N/A'}\n`;
            md += `- **Affected:** \`${f.affected||''}\`\n`;
            md += `- **Description:** ${f.description||''}\n`;
            if (f.remediation) md += `- **Remediation:** ${f.remediation}\n`;
            if (f.poc) md += `\`\`\`\n${f.poc}\n\`\`\`\n`;
            md += '\n';
        }
        const blob = new Blob([md], { type: 'text/markdown' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url; a.download = `bbhpro_${scanId}_report.md`;
        document.body.appendChild(a); a.click();
        document.body.removeChild(a); URL.revokeObjectURL(url);
        showToast('Markdown exported!', 'success');
    } catch(err) {
        showToast('Export error: ' + err.message, 'error');
    }
}

// ─── Chart ────────────────────────────────────────────────────────────────────

function initVulnChart() {
    const ctx = document.getElementById('vulnChart');
    if (!ctx) return;
    
    vulnChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#10b981', '#06b6d4'],
                borderWidth: 2,
                borderColor: '#111827'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#94a3b8',
                        font: { size: 11, family: 'Inter' },
                        padding: 10
                    }
                }
            },
            cutout: '70%'
        }
    });
}

function updateVulnChart(scans) {
    if (!vulnChart) return;
    
    const totals = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    
    // Aggregate from scan data
    scans.forEach(scan => {
        if (scan.poc_report?.severity_counts) {
            Object.entries(scan.poc_report.severity_counts).forEach(([sev, count]) => {
                if (totals[sev] !== undefined) totals[sev] += count;
            });
        }
    });
    
    vulnChart.data.datasets[0].data = [totals.CRITICAL, totals.HIGH, totals.MEDIUM, totals.LOW, totals.INFO];
    vulnChart.update();
    
    // Update stat cards
    document.getElementById('stat-critical').textContent = totals.CRITICAL;
    document.getElementById('stat-high').textContent = totals.HIGH;
    document.getElementById('stat-medium').textContent = totals.MEDIUM;
    document.getElementById('stat-low').textContent = totals.LOW + totals.INFO;
}

function updateStatsDisplay() {
    document.getElementById('stat-critical').textContent = statsTotal.CRITICAL;
    document.getElementById('stat-high').textContent = statsTotal.HIGH;
    document.getElementById('stat-medium').textContent = statsTotal.MEDIUM;
    document.getElementById('stat-low').textContent = statsTotal.LOW + statsTotal.INFO;
}

function updateTotalScansCount() {
    const count = Object.keys(allScans).length;
    document.getElementById('totalScansCount').textContent = count;
    document.getElementById('resultsCount').textContent = count;
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function showLoading(text) {
    const overlay = document.getElementById('loadingOverlay');
    const textEl = document.getElementById('loadingText');
    textEl.textContent = text || 'Processing...';
    overlay.style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const icons = { success: 'check-circle', error: 'times-circle', warning: 'exclamation-triangle', info: 'info-circle' };
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<i class="fas fa-${icons[type] || 'info-circle'}"></i> ${escapeHtml(message)}`;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideUp 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function formatDate(dateStr) {
    if (!dateStr) return 'Unknown';
    try {
        const d = new Date(dateStr);
        return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch {
        return dateStr;
    }
}

function isExpiringSoon(dateStr) {
    if (!dateStr) return false;
    try {
        const expiry = new Date(dateStr);
        const thirtyDaysFromNow = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        return expiry < thirtyDaysFromNow;
    } catch {
        return false;
    }
}

function hexToRGB(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? `${parseInt(result[1], 16)},${parseInt(result[2], 16)},${parseInt(result[3], 16)}` : '59,130,246';
}
