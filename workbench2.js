/**
 * Network Workbench 2.0 — Client Enhancements
 * Network Troubleshooting and Firewall Policy Analyzer for Small Networks
 */

(function () {
  'use strict';

  // Backend state
  let backendOnline = false;
  let demoServerRunning = false;
  let activePolicy = [];
  let lastDiagnosticResult = null;
  let lastAnalyzerResult = null;
  let lastComparisonResult = null;

  // Preset policies for the Firewall Analyzer
  const PRESET_POLICIES = {
    baseline: {
      name: 'Recommended 3-Tier Baseline (Secure)',
      description: 'Standard least-privilege three-tier policy. Client enters Web :443, Web calls App :5000, App queries Database :3306. All other cross-tier connections denied.',
      rules: [
        { id: 'R-01', source: '192.168.1.0/24', destination: '10.0.1.10', port: '443', protocol: 'TCP', action: 'ALLOW', comment: 'Client HTTPS to Web' },
        { id: 'R-02', source: '192.168.1.0/24', destination: '10.0.2.10', port: '5000', protocol: 'TCP', action: 'DENY', comment: 'Block client direct App bypass' },
        { id: 'R-03', source: '192.168.1.0/24', destination: '10.0.3.10', port: '3306', protocol: 'TCP', action: 'DENY', comment: 'Block client direct DB bypass' },
        { id: 'R-04', source: '10.0.1.10', destination: '10.0.2.10', port: '5000', protocol: 'TCP', action: 'ALLOW', comment: 'Web calls App API' },
        { id: 'R-05', source: '10.0.1.10', destination: '10.0.3.10', port: '3306', protocol: 'TCP', action: 'DENY', comment: 'Block Web direct DB bypass' },
        { id: 'R-06', source: '10.0.2.10', destination: '10.0.3.10', port: '3306', protocol: 'TCP', action: 'ALLOW', comment: 'App queries Database' },
        { id: 'R-07', source: 'ANY', destination: 'ANY', port: '*', protocol: 'ANY', action: 'DENY', comment: 'Explicit Default Deny' }
      ]
    },
    teacher_client_db: {
      name: "Teacher Demo: Client Directly Accessing Database (Security Hazard)",
      description: "Demonstration requested by the teacher: Rule R-03 is modified to ALLOW direct client connection to MySQL :3306. Demonstrates architecture bypass, lack of input validation, and WAN database exposure.",
      rules: [
        { id: 'R-01', source: '192.168.1.0/24', destination: '10.0.1.10', port: '443', protocol: 'TCP', action: 'ALLOW', comment: 'Client HTTPS to Web' },
        { id: 'R-02', source: '192.168.1.0/24', destination: '10.0.2.10', port: '5000', protocol: 'TCP', action: 'DENY', comment: 'Block client direct App bypass' },
        { id: 'R-03', source: '192.168.1.0/24', destination: '10.0.3.10', port: '3306', protocol: 'TCP', action: 'ALLOW', comment: 'HAZARD: Client directly accesses MySQL Database' },
        { id: 'R-04', source: '10.0.1.10', destination: '10.0.2.10', port: '5000', protocol: 'TCP', action: 'ALLOW', comment: 'Web calls App API' },
        { id: 'R-05', source: '10.0.1.10', destination: '10.0.3.10', port: '3306', protocol: 'TCP', action: 'DENY', comment: 'Block Web direct DB bypass' },
        { id: 'R-06', source: '10.0.2.10', destination: '10.0.3.10', port: '3306', protocol: 'TCP', action: 'ALLOW', comment: 'App queries Database' },
        { id: 'R-07', source: 'ANY', destination: 'ANY', port: '*', protocol: 'ANY', action: 'DENY', comment: 'Explicit Default Deny' }
      ]
    },
    vulnerable_lab: {
      name: 'Vulnerable Lab / Small Office Perimeter',
      description: 'Common small office misconfigurations: Remote management (SSH :22) and Database (:3306, :5432) left open to 0.0.0.0/0.',
      rules: [
        { id: 'R-01', source: '0.0.0.0/0', destination: '10.0.1.10', port: '80-443', protocol: 'TCP', action: 'ALLOW', comment: 'Public Web traffic' },
        { id: 'R-02', source: '0.0.0.0/0', destination: '10.0.1.10', port: '22', protocol: 'TCP', action: 'ALLOW', comment: 'CRITICAL: SSH exposed to Internet' },
        { id: 'R-03', source: '0.0.0.0/0', destination: '10.0.3.10', port: '3306', protocol: 'TCP', action: 'ALLOW', comment: 'CRITICAL: MySQL exposed to Internet' },
        { id: 'R-04', source: '192.168.1.0/24', destination: '10.0.2.10', port: '3389', protocol: 'TCP', action: 'ALLOW', comment: 'RDP Remote Desktop' },
        { id: 'R-05', source: 'ANY', destination: 'ANY', port: '*', protocol: 'ANY', action: 'DENY', comment: 'Default Deny' }
      ]
    },
    shadowed_conflict: {
      name: 'Conflicting Rules & Order Hazards (Dead Code)',
      description: 'Demonstrates rule-ordering problems: an early broad rule shadows a specific deny, and an early default-deny turns subsequent rules into dead code.',
      rules: [
        { id: 'R-01', source: '10.0.0.0/8', destination: '10.0.1.10', port: '80', protocol: 'TCP', action: 'ALLOW', comment: 'Broad 10.0.0.0/8 allow' },
        { id: 'R-02', source: '10.0.1.5', destination: '10.0.1.10', port: '80', protocol: 'TCP', action: 'DENY', comment: 'SHADOWED: Specific deny is never reached' },
        { id: 'R-03', source: '10.0.1.6', destination: '10.0.1.10', port: '80', protocol: 'TCP', action: 'ALLOW', comment: 'REDUNDANT: Already covered by R-01' },
        { id: 'R-04', source: 'ANY', destination: 'ANY', port: '*', protocol: 'ANY', action: 'DENY', comment: 'HAZARD: Early Default Deny' },
        { id: 'R-05', source: '192.168.1.0/24', destination: '10.0.1.10', port: '443', protocol: 'TCP', action: 'ALLOW', comment: 'DEAD CODE: Placed after default deny' }
      ]
    },
    wildcard_permissive: {
      name: 'Overly Broad Wildcard (ANY-ANY)',
      description: 'Severe perimeter misconfiguration with wildcard source and port.',
      rules: [
        { id: 'R-01', source: 'ANY', destination: 'ANY', port: '*', protocol: 'ANY', action: 'ALLOW', comment: 'CRITICAL: Full perimeter bypass' },
        { id: 'R-02', source: 'ANY', destination: 'ANY', port: '*', protocol: 'ANY', action: 'DENY', comment: 'Default Deny (Never reached)' }
      ]
    }
  };

  // Helper DOM shortcuts
  const $ = id => document.getElementById(id);

  // Initialize Workbench 2.0 when DOM is loaded
  document.addEventListener('DOMContentLoaded', () => {
    initBackendConnection();
    initDiagnosticsTab();
    initPolicyAnalyzerTab();
    initTroubleshootingTab();
    initReportsAndHistoryTab();
    initTeacherDemoQuickActions();
  });

  // ==========================================================================
  // Backend Connection Management
  // ==========================================================================

  async function initBackendConnection() {
    const pill = $('backendStatusPill');
    if (!pill) return;

    try {
      const resp = await fetch('/api/status', { cache: 'no-store' });
      if (resp.ok) {
        const data = await resp.json();
        backendOnline = true;
        demoServerRunning = !!data.demo_server?.running;
        pill.className = 'backend-status-pill online';
        pill.innerHTML = `<span class="status-dot"></span><span>Python Backend: Online (:5000)</span>`;
        updateDemoServerUI(demoServerRunning, data.demo_server?.port || 8080);
      } else {
        setBackendOfflineUI(pill);
      }
    } catch (err) {
      setBackendOfflineUI(pill);
    }
  }

  function setBackendOfflineUI(pill) {
    backendOnline = false;
    pill.className = 'backend-status-pill offline';
    pill.innerHTML = `<span class="status-dot"></span><span>Backend: Offline (Browser Simulation Mode)</span>`;
    pill.title = 'Start `python app.py` in your terminal to enable live sockets and real TCP checks.';
  }

  // ==========================================================================
  // Diagnostics Tab
  // ==========================================================================

  function initDiagnosticsTab() {
    const runBtn = $('runDiagnosticsBtn');
    const toggleDemoBtn = $('toggleDemoServerBtn');
    if (!runBtn) return;

    // Preset target buttons
    document.querySelectorAll('.diag-preset').forEach(btn => {
      btn.addEventListener('click', () => {
        $('diagHost').value = btn.dataset.host;
        $('diagPort').value = btn.dataset.port;
        if (btn.dataset.allowPublic) {
          $('diagAllowPublic').checked = true;
        }
      });
    });

    // Run diagnostics
    runBtn.addEventListener('click', runDiagnostics);

    // Toggle demo server
    if (toggleDemoBtn) {
      toggleDemoBtn.addEventListener('click', toggleDemoServer);
    }
  }

  async function toggleDemoServer() {
    const btn = $('toggleDemoServerBtn');
    btn.disabled = true;

    if (!backendOnline) {
      demoServerRunning = !demoServerRunning;
      updateDemoServerUI(demoServerRunning, 8080);
      btn.disabled = false;
      return;
    }

    try {
      const resp = await fetch('/api/demo-server/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: demoServerRunning ? 'stop' : 'start' })
      });
      const data = await resp.json();
      demoServerRunning = data.running;
      updateDemoServerUI(demoServerRunning, data.port);
    } catch (err) {
      alert('Failed to toggle demo server: ' + err.message);
    } finally {
      btn.disabled = false;
    }
  }

  function updateDemoServerUI(running, port) {
    const badge = $('demoServerStatus');
    const btn = $('toggleDemoServerBtn');
    if (!badge || !btn) return;

    if (running) {
      badge.textContent = `LISTENING ON :${port}`;
      badge.style.color = '#147238';
      btn.textContent = 'Stop Demo Server';
      btn.className = 'secondary-button btn-sm';
    } else {
      badge.textContent = 'STOPPED (PORT CLOSED)';
      badge.style.color = '#ac4625';
      btn.textContent = 'Start Demo Server on :8080';
      btn.className = 'primary-button btn-sm';
    }
  }

  async function runDiagnostics() {
    const host = ($('diagHost').value || '127.0.0.1').trim();
    const port = parseInt($('diagPort').value, 10);
    const timeout = parseFloat($('diagTimeout')?.value || 3.0);
    const allowPublic = !!$('diagAllowPublic')?.checked;
    const runBtn = $('runDiagnosticsBtn');

    if (!port || port < 1 || port > 65535) {
      alert('Please enter a valid port number between 1 and 65535.');
      return;
    }

    runBtn.disabled = true;
    runBtn.innerHTML = `Running Real Probes...`;

    const resultsArea = $('diagnosticResults');
    resultsArea.hidden = false;
    resultsArea.innerHTML = `<div class="wb-card"><p style="color:var(--muted);font-family:var(--mono);">[1/2] Resolving DNS for ${host}...<br>[2/2] Attempting TCP 3-way handshake on ${host}:${port}...</p></div>`;

    let data = null;

    if (backendOnline) {
      try {
        const resp = await fetch('/api/diagnostics/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host, port, timeout, allow_public: allowPublic })
        });
        data = await resp.json();
      } catch (err) {
        data = { error: 'Network error communicating with backend: ' + err.message };
      }
    } else {
      // Mock diagnostic fallback for standalone browser view
      await new Promise(r => setTimeout(r, 600));
      data = mockBrowserDiagnostic(host, port, allowPublic);
    }

    runBtn.disabled = false;
    runBtn.innerHTML = `Run Real Network Diagnostics <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12h16m-6-6 6 6-6 6"/></svg>`;

    lastDiagnosticResult = data;
    renderDiagnosticResult(data);
  }

  function mockBrowserDiagnostic(host, port, allowPublic) {
    const isLocal = ['127.0.0.1', 'localhost'].includes(host);
    const isMockOpen = isLocal && port === 8080 && demoServerRunning;
    const status = isMockOpen ? 'REACHABLE' : (port === 3306 || port === 8080 ? 'UNREACHABLE' : 'TIMED_OUT');
    const code = isMockOpen ? 'OPEN' : (status === 'UNREACHABLE' ? 'REFUSED' : 'TIMEOUT');

    return {
      timestamp: new Date().toISOString(),
      target: { host, port, probe_ip: isLocal ? '127.0.0.1' : '192.168.1.1', category: 'STANDALONE_MOCK' },
      dns: {
        success: true,
        latency_ms: 1.2,
        ips: [isLocal ? '127.0.0.1' : '192.168.1.1'],
        canonical_name: host
      },
      tcp: {
        status,
        code,
        latency_ms: isMockOpen ? 0.8 : 2000,
        state_label: isMockOpen ? 'Reachable (Port Open)' : (code === 'REFUSED' ? 'Connection Refused (RST)' : 'Timed Out (Filtered / Dropped)'),
        message: isMockOpen ? `TCP connection established to ${host}:${port}.` : (code === 'REFUSED' ? `Connection refused by ${host}:${port} (RST returned).` : `Connection to ${host}:${port} timed out.`),
        explanation: isMockOpen
          ? 'SYN/ACK received: Active service listening.'
          : (code === 'REFUSED'
            ? 'Operating system actively returned RST packet. Service is stopped or not listening. The firewall did NOT block this packet.'
            : 'No response received. Packet dropped by firewall filter or host down.')
      },
      summary: {
        status,
        state_label: isMockOpen ? 'Reachable (Port Open)' : (code === 'REFUSED' ? 'Connection Refused (RST)' : 'Timed Out (Filtered)'),
        overall_reachable: isMockOpen,
        dns_resolved: true,
        total_latency_ms: isMockOpen ? 2.0 : 2001
      },
      limitations: [
        'Browser standalone simulation: Start `python app.py` for actual operating system socket calls.',
        'TCP probe proves port state, but does not execute application payload.'
      ]
    };
  }

  function renderDiagnosticResult(res) {
    const area = $('diagnosticResults');
    if (!area) return;

    if (res.blocked_by_safety) {
      area.innerHTML = `
        <div class="wb-card">
          <span class="status-badge-lg timed_out">PROBE BLOCKED BY SAFETY GUARD</span>
          <h3>Authorization Required</h3>
          <p style="color:var(--muted);">${res.error}</p>
        </div>
      `;
      return;
    }

    if (res.error && !res.tcp) {
      area.innerHTML = `
        <div class="wb-card">
          <span class="status-badge-lg timed_out">DIAGNOSTIC ERROR</span>
          <p style="color:var(--orange);">${res.error}</p>
        </div>
      `;
      return;
    }

    const tcp = res.tcp || {};
    const dns = res.dns || {};
    const badgeClass = tcp.status === 'REACHABLE' ? 'reachable' : (tcp.code === 'REFUSED' ? 'refused' : 'timed_out');

    area.innerHTML = `
      <div class="wb-card">
        <div class="wb-card-header">
          <div>
            <span class="status-badge-lg ${badgeClass}">${tcp.state_label || tcp.status}</span>
            <h2>${res.target.host} : ${res.target.port}</h2>
          </div>
          <span style="font-family:var(--mono);font-size:12px;color:var(--muted);">${res.target.category || 'DIAGNOSTIC'}</span>
        </div>

        <div class="metric-row">
          <div class="metric-box">
            <div class="label">DNS Resolution</div>
            <div class="value">${dns.success ? `${dns.latency_ms} ms` : 'FAILED'}</div>
          </div>
          <div class="metric-box">
            <div class="label">TCP Handshake Latency</div>
            <div class="value">${tcp.status === 'REACHABLE' ? `${tcp.latency_ms} ms` : (tcp.code === 'REFUSED' ? `${tcp.latency_ms} ms` : 'TIMEOUT')}</div>
          </div>
          <div class="metric-box">
            <div class="label">TCP 3-Way Handshake</div>
            <div class="value" style="font-size:15px;color:${tcp.status === 'REACHABLE' ? '#147238' : '#ac4625'};">${tcp.code || tcp.status}</div>
          </div>
        </div>

        <div style="background:var(--soft);padding:14px;border-radius:4px;font-size:13px;margin-bottom:16px;">
          <strong style="font-family:var(--mono);color:var(--muted);font-size:11px;display:block;margin-bottom:4px;">NETWORK PATH RESOLUTION:</strong>
          Target: <code>${res.target.host}</code> &rarr; Resolved IP(s): <code>${dns.ips && dns.ips.length ? dns.ips.join(', ') : 'None'}</code>
        </div>

        <div class="insight-callout ${tcp.status === 'REACHABLE' ? 'success' : 'warning'}">
          <h4>Networking Diagnosis & Root Cause</h4>
          <p><strong>${tcp.message}</strong></p>
          <p style="margin-top:6px;">${tcp.explanation}</p>
        </div>

        <div style="margin-top:18px;border-top:1px solid var(--soft);padding-top:12px;font-size:12px;color:var(--muted);">
          <strong style="color:var(--ink);">Methodological Limitations:</strong>
          <ul style="margin:4px 0 0 18px;padding:0;">
            ${(res.limitations || []).map(lim => `<li>${lim}</li>`).join('')}
          </ul>
        </div>
      </div>
    `;
  }

  // ==========================================================================
  // Firewall Policy Analyzer Tab
  // ==========================================================================

  function initPolicyAnalyzerTab() {
    const presetSelect = $('policyPresetSelect');
    const analyzeBtn = $('runAnalyzerBtn');
    const addRuleBtn = $('addAnalyzerRuleBtn');
    const exportJsonBtn = $('exportPolicyJsonBtn');
    const importJsonInput = $('importPolicyJsonInput');

    if (!presetSelect) return;

    // Load initial preset
    loadPolicyPreset('baseline');

    presetSelect.addEventListener('change', () => {
      loadPolicyPreset(presetSelect.value);
    });

    if (analyzeBtn) {
      analyzeBtn.addEventListener('click', runPolicyAnalysis);
    }

    if (addRuleBtn) {
      addRuleBtn.addEventListener('click', addNewPolicyRule);
    }

    if (exportJsonBtn) {
      exportJsonBtn.addEventListener('click', () => {
        const jsonStr = JSON.stringify(activePolicy, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `firewall-policy-${Date.now()}.json`;
        a.click();
      });
    }

    if (importJsonInput) {
      importJsonInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (event) => {
          try {
            const imported = JSON.parse(event.target.result);
            if (Array.isArray(imported)) {
              activePolicy = imported;
              renderPolicyEditor();
              runPolicyAnalysis();
            } else {
              alert('Invalid policy JSON format: root must be an array of rules.');
            }
          } catch (err) {
            alert('Failed to parse JSON file: ' + err.message);
          }
        };
        reader.readAsText(file);
      });
    }
  }

  function loadPolicyPreset(key) {
    const preset = PRESET_POLICIES[key];
    if (!preset) return;

    activePolicy = JSON.parse(JSON.stringify(preset.rules));
    const descEl = $('policyPresetDescription');
    if (descEl) descEl.textContent = preset.description;

    renderPolicyEditor();
    runPolicyAnalysis();
  }

  function renderPolicyEditor() {
    const tbody = $('analyzerRulesTableBody');
    if (!tbody) return;

    tbody.innerHTML = activePolicy.map((rule, idx) => `
      <tr data-rule-id="${rule.id || `R-${idx+1}`}">
        <td><input type="text" class="wb-input rule-edit-field" data-field="id" value="${rule.id || `R-${idx+1}`}" style="width:75px;padding:4px 6px;font-family:var(--mono);font-size:12px;"></td>
        <td><input type="text" class="wb-input rule-edit-field" data-field="source" value="${rule.source}" style="padding:4px 6px;font-size:12px;"></td>
        <td><input type="text" class="wb-input rule-edit-field" data-field="destination" value="${rule.destination}" style="padding:4px 6px;font-size:12px;"></td>
        <td><input type="text" class="wb-input rule-edit-field" data-field="port" value="${rule.port}" style="width:85px;padding:4px 6px;font-size:12px;"></td>
        <td>
          <select class="wb-select rule-edit-field" data-field="protocol" style="padding:4px 6px;font-size:12px;">
            <option value="TCP"${rule.protocol === 'TCP' ? ' selected' : ''}>TCP</option>
            <option value="UDP"${rule.protocol === 'UDP' ? ' selected' : ''}>UDP</option>
            <option value="ANY"${rule.protocol === 'ANY' ? ' selected' : ''}>ANY</option>
          </select>
        </td>
        <td>
          <select class="wb-select rule-edit-field" data-field="action" style="padding:4px 6px;font-size:12px;font-weight:600;color:${rule.action === 'ALLOW' ? '#147238' : '#ac4625'};">
            <option value="ALLOW"${rule.action === 'ALLOW' ? ' selected' : ''}>ALLOW</option>
            <option value="DENY"${rule.action === 'DENY' ? ' selected' : ''}>DENY</option>
          </select>
        </td>
        <td><input type="text" class="wb-input rule-edit-field" data-field="comment" value="${rule.comment || ''}" style="padding:4px 6px;font-size:12px;" placeholder="Optional note"></td>
        <td><button type="button" class="delete-rule-btn" data-index="${idx}" style="background:none;border:none;color:var(--orange);cursor:pointer;font-weight:bold;">&times;</button></td>
      </tr>
    `).join('');

    // Attach change handlers
    tbody.querySelectorAll('.rule-edit-field').forEach(input => {
      input.addEventListener('change', (e) => {
        const row = e.target.closest('tr');
        const idx = Array.from(tbody.children).indexOf(row);
        const field = e.target.dataset.field;
        if (activePolicy[idx]) {
          activePolicy[idx][field] = e.target.value;
        }
      });
    });

    tbody.querySelectorAll('.delete-rule-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const idx = parseInt(e.target.dataset.index, 10);
        activePolicy.splice(idx, 1);
        renderPolicyEditor();
        runPolicyAnalysis();
      });
    });
  }

  function addNewPolicyRule() {
    const newId = `R-${String(activePolicy.length + 1).padStart(2, '0')}`;
    activePolicy.push({
      id: newId,
      source: '192.168.1.0/24',
      destination: '10.0.1.10',
      port: '8080',
      protocol: 'TCP',
      action: 'ALLOW',
      comment: 'Custom lab rule'
    });
    renderPolicyEditor();
  }

  async function runPolicyAnalysis() {
    const container = $('analyzerFindingsContainer');
    if (!container) return;

    container.innerHTML = `<p style="color:var(--muted);font-family:var(--mono);">Running rule-order, shadowing, and least-privilege analysis...</p>`;

    let report = null;

    if (backendOnline) {
      try {
        const resp = await fetch('/api/analyzer/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rules: activePolicy, name: $('policyPresetSelect')?.selectedOptions[0]?.text || 'Custom Policy' })
        });
        report = await resp.json();
      } catch (err) {
        report = { error: 'Backend error: ' + err.message };
      }
    } else {
      // Mock client analysis
      report = mockClientPolicyAnalysis(activePolicy);
    }

    lastAnalyzerResult = report;
    renderAnalyzerFindings(report);
  }

  function mockClientPolicyAnalysis(rules) {
    const findings = [];
    let hasDefaultDeny = false;

    rules.forEach((r, idx) => {
      const src = (r.source || '').toUpperCase();
      const dst = (r.destination || '').toUpperCase();
      const port = (r.port || '');
      const act = (r.action || '').toUpperCase();

      if ((src === 'ANY' || src === '0.0.0.0/0') && port === '*' && act === 'DENY') {
        hasDefaultDeny = true;
      }

      // Check client to database bypass (Teacher's Scenario)
      if ((src.includes('CLIENT') || src.includes('192.168.1')) && (dst.includes('DATA') || dst.includes('10.0.3') || port === '3306') && act === 'ALLOW') {
        findings.push({
          rule_id: r.id || `R-${idx+1}`,
          severity: 'CRITICAL',
          category: 'TIER_BYPASS',
          title: 'Direct Client Database Access Bypass (Teacher Scenario)',
          description: `Rule ${r.id} allows direct client network access to the private database tier (port ${port}). In three-tier architecture, direct database exposure circumvents application security logic.`,
          remediation: 'Change rule to DENY. All database access must be initiated exclusively from the Application Tier (10.0.2.10).'
        });
      }

      // Check ANY-ANY
      if ((src === 'ANY' || src === '0.0.0.0/0') && port === '*' && act === 'ALLOW') {
        findings.push({
          rule_id: r.id || `R-${idx+1}`,
          severity: 'CRITICAL',
          category: 'UNRESTRICTED_ALLOW',
          title: 'Unrestricted ANY-ANY Allow Rule',
          description: `Rule ${r.id} permits all traffic unconditionally, bypassing perimeter security.`,
          remediation: 'Restrict source IP ranges and specify explicit destination service ports.'
        });
      }

      // Check SSH or DB to ANY
      if ((src === 'ANY' || src === '0.0.0.0/0') && ['22', '3306', '3389'].includes(port) && act === 'ALLOW') {
        findings.push({
          rule_id: r.id || `R-${idx+1}`,
          severity: 'HIGH',
          category: 'SENSITIVE_PORT_EXPOSURE',
          title: `Sensitive Service Exposed: Port ${port}`,
          description: `Rule ${r.id} permits unrestricted incoming access to management/database port ${port}.`,
          remediation: 'Restrict access to trusted administrative VPN or private subnets.'
        });
      }
    });

    if (!hasDefaultDeny) {
      findings.push({
        rule_id: 'GLOBAL',
        severity: 'WARNING',
        category: 'MISSING_DEFAULT_DENY',
        title: 'Missing Explicit Default-Deny Rule',
        description: 'No terminal DENY-ALL rule found. Insecure if default fallback allows unmatched traffic.',
        remediation: 'Append ANY -> ANY : ANY -> DENY at the bottom of the table.'
      });
    }

    return {
      timestamp: new Date().toISOString(),
      rule_count: rules.length,
      summary: {
        critical: findings.filter(f => f.severity === 'CRITICAL').length,
        warning: findings.filter(f => f.severity === 'HIGH' || f.severity === 'WARNING').length,
        info: findings.filter(f => f.severity === 'INFO').length,
        total_findings: findings.length
      },
      findings,
      disclaimer: 'Findings reflect static policy analysis, not proof of active hardware exploit.'
    };
  }

  function renderAnalyzerFindings(report) {
    const container = $('analyzerFindingsContainer');
    if (!container) return;

    if (report.error) {
      container.innerHTML = `<div class="wb-card"><p style="color:var(--orange);">${report.error}</p></div>`;
      return;
    }

    const { summary, findings, disclaimer } = report;

    container.innerHTML = `
      <div class="wb-card">
        <div class="wb-card-header">
          <div>
            <h2>Policy Audit Summary</h2>
            <p style="font-size:13px;color:var(--muted);margin-top:4px;">${report.rule_count} rules analyzed against least-privilege & architectural standards</p>
          </div>
          <span style="font-family:var(--mono);font-size:12px;font-weight:bold;color:${summary.critical > 0 ? '#d92d20' : '#147238'};">
            ${summary.critical > 0 ? `${summary.critical} CRITICAL ISSUES` : 'NO CRITICAL FLAWS'}
          </span>
        </div>

        <div class="metric-row">
          <div class="metric-box">
            <div class="label" style="color:#d92d20;">Critical Findings</div>
            <div class="value" style="color:#d92d20;">${summary.critical}</div>
          </div>
          <div class="metric-box">
            <div class="label" style="color:#b54708;">Warnings / High</div>
            <div class="value" style="color:#b54708;">${summary.warning}</div>
          </div>
          <div class="metric-box">
            <div class="label" style="color:#0284c7;">Optimization (Info)</div>
            <div class="value" style="color:#0284c7;">${summary.info}</div>
          </div>
        </div>

        <div class="findings-list">
          ${findings.length === 0 ? '<p style="color:#147238;font-weight:500;">✓ Excellent! No rule conflicts, shadowing, or least-privilege violations detected.</p>' : ''}
          ${findings.map(f => `
            <div class="finding-card">
              <div class="finding-header">
                <span class="severity-pill ${f.severity.toLowerCase()}">${f.severity}</span>
                <span style="font-family:var(--mono);font-size:12px;color:var(--muted);">${f.rule_id}</span>
              </div>
              <h3 class="finding-title">${f.title}</h3>
              <p class="finding-desc">${f.description}</p>
              <div class="finding-remediation">
                <b>Recommended Fix:</b> ${f.remediation}
              </div>
            </div>
          `).join('')}
        </div>

        <div style="margin-top:20px;padding:12px;background:var(--soft);border-radius:4px;font-size:12px;color:var(--muted);">
          <em>${disclaimer || 'Findings reflect static policy analysis.'}</em>
        </div>
      </div>
    `;
  }

  // ==========================================================================
  // Troubleshooting & Comparison Mode
  // ==========================================================================

  function initTroubleshootingTab() {
    const compareBtn = $('runComparisonBtn');
    const flowSelect = $('troubleshootFlowSelect');
    if (!compareBtn) return;

    if (flowSelect) {
      flowSelect.addEventListener('change', () => {
        const val = flowSelect.value;
        if (val === 'client-db') {
          $('troubleshootSimDecision').value = 'DENY';
          $('troubleshootRealHost').value = '127.0.0.1';
          $('troubleshootRealPort').value = '3306';
        } else if (val === 'client-web') {
          $('troubleshootSimDecision').value = 'ALLOW';
          $('troubleshootRealHost').value = '127.0.0.1';
          $('troubleshootRealPort').value = '8080';
        } else if (val === 'web-app') {
          $('troubleshootSimDecision').value = 'ALLOW';
          $('troubleshootRealHost').value = '127.0.0.1';
          $('troubleshootRealPort').value = '5000';
        }
      });
    }

    compareBtn.addEventListener('click', runComparisonAnalysis);
  }

  async function runComparisonAnalysis() {
    const flowSelect = $('troubleshootFlowSelect');
    const flowName = flowSelect?.selectedOptions[0]?.text || 'Selected Tier Flow';
    const simDecision = $('troubleshootSimDecision').value;
    const realHost = ($('troubleshootRealHost').value || '127.0.0.1').trim();
    const realPort = parseInt($('troubleshootRealPort').value, 10);
    const resultBox = $('comparisonResultsBox');

    if (!realPort) {
      alert('Please enter a valid numeric port.');
      return;
    }

    resultBox.hidden = false;
    resultBox.innerHTML = `<p style="font-family:var(--mono);color:var(--muted);">Executing live network socket probe and correlating with simulated policy model...</p>`;

    let realData = null;
    if (backendOnline) {
      try {
        const resp = await fetch('/api/diagnostics/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host: realHost, port: realPort, timeout: 3.0, allow_public: true })
        });
        realData = await resp.json();
      } catch (err) {
        realData = { error: err.message };
      }
    } else {
      await new Promise(r => setTimeout(r, 500));
      realData = mockBrowserDiagnostic(realHost, realPort, true);
    }

    const tcp = realData.tcp || {};
    const realStatus = tcp.status || 'UNKNOWN';
    const realCode = tcp.code || 'UNKNOWN';

    // Correlate results
    let correlationTitle = '';
    let correlationInsight = '';
    let verdictClass = 'insight-callout';

    if (simDecision === 'ALLOW' && realStatus === 'REACHABLE') {
      correlationTitle = 'Consistent Reachability (Policy & Host Aligned)';
      correlationInsight = 'Both the simulated firewall policy permits the packet and the real target host is listening with an active service. Connection fully established.';
      verdictClass += ' success';
    } else if (simDecision === 'ALLOW' && realCode === 'REFUSED') {
      correlationTitle = 'Crucial Networking Lesson: Service Stopped vs Firewall Drop';
      correlationInsight = `
        <strong>The simulated policy allows this traffic, but the real connection failed with TCP RST (Connection Refused).</strong><br>
        <em>Key Takeaway:</em> A failed connection does <strong>NOT</strong> prove a firewall blocked it. The target machine is reachable, but no process is bound to port ${realPort}. If a firewall had dropped it, you would see a timeout, not an RST packet!
      `;
      verdictClass += ' warning';
    } else if (simDecision === 'DENY' && realStatus === 'REACHABLE') {
      correlationTitle = 'Critical Policy Drift / Security Gap';
      correlationInsight = `
        <strong>The simulated 3-tier policy model dictates that this cross-tier access should be BLOCKED, but the real network probe found port ${realPort} OPEN and reachable.</strong><br>
        In a production environment, this indicates unintended exposure or lack of network boundary segmentation.
      `;
      verdictClass += ' warning';
    } else if (simDecision === 'DENY' && (realCode === 'REFUSED' || realStatus === 'TIMED_OUT')) {
      correlationTitle = 'Access Prohibited (Policy & Transport Blocked)';
      correlationInsight = 'The architectural policy denies this direct route, and the real target port is currently unreachable or closed.';
    } else {
      correlationTitle = 'Timeout / Unreachable Transport';
      correlationInsight = 'Traffic is timed out or unrouted on the network. Without a response, packets may be dropped silently by a firewall filter or intermediate router.';
    }

    lastComparisonResult = {
      flowName,
      simDecision,
      realHost,
      realPort,
      realStatus,
      realCode,
      correlationTitle,
      correlationInsight,
      realData
    };

    resultBox.innerHTML = `
      <div class="comparison-container">
        <div class="comparison-box simulated">
          <div class="box-tag">Three-Tier Architecture Model</div>
          <h3>${flowName}</h3>
          <p><strong>Simulated Policy Decision:</strong> <span style="color:${simDecision === 'ALLOW' ? '#147238' : '#ac4625'};font-weight:700;">${simDecision}</span></p>
          <p style="font-size:13px;color:var(--muted);margin-top:8px;">
            ${simDecision === 'ALLOW' ? 'The logical rules permit this cross-tier connection.' : 'Baseline least-privilege policy blocks this cross-tier shortcut to protect internal tiers.'}
          </p>
        </div>

        <div class="comparison-box real">
          <div class="box-tag">Actual Network Probe</div>
          <h3>${realHost}:${realPort}</h3>
          <p><strong>Real Socket State:</strong> <span style="font-weight:700;color:${realStatus === 'REACHABLE' ? '#147238' : '#ac4625'};">${tcp.state_label || realStatus}</span></p>
          <p style="font-size:13px;color:var(--muted);margin-top:8px;">
            Latency: <code>${tcp.latency_ms || 0} ms</code> &bull; Response: <code>${realCode}</code>
          </p>
        </div>
      </div>

      <div class="${verdictClass}">
        <h4>${correlationTitle}</h4>
        <div>${correlationInsight}</div>
      </div>
    `;
  }

  // ==========================================================================
  // Teacher Quick Action: Client Direct Database Access Scenario
  // ==========================================================================

  function initTeacherDemoQuickActions() {
    const teacherBtnSim = $('teacherDemoSimBtn');
    const teacherBtnAnalyzer = $('teacherDemoAnalyzerBtn');

    if (teacherBtnSim) {
      teacherBtnSim.addEventListener('click', () => {
        // Switch to Simulate tab and set Client -> Database :3306
        if (typeof window.setScenario === 'function') {
          window.setScenario('client', 'database', 3306);
        } else {
          $('sourceSelect').value = 'client';
          $('destinationSelect').value = 'database';
          $('portSelect').value = '3306';
        }
        // Change rule 2 (R-03) to ALLOW to demonstrate what happens when client CAN access DB
        if (typeof window.changeRule === 'function') {
          window.changeRule(2, 'ALLOW');
          if (typeof window.renderRules === 'function') window.renderRules();
        }
        // Navigate to simulate section
        location.hash = '#simulate';
        // Auto start simulation
        if (typeof window.startSimulation === 'function') {
          window.startSimulation();
        }
      });
    }

    if (teacherBtnAnalyzer) {
      teacherBtnAnalyzer.addEventListener('click', () => {
        location.hash = '#analyzer';
        $('policyPresetSelect').value = 'teacher_client_db';
        loadPolicyPreset('teacher_client_db');
      });
    }
  }

  // ==========================================================================
  // Reports & History Tab
  // ==========================================================================

  function initReportsAndHistoryTab() {
    const generateReportBtn = $('generateReportBtn');
    const printReportBtn = $('printReportBtn');
    const downloadReportBtn = $('downloadReportHtmlBtn');
    const refreshHistoryBtn = $('refreshHistoryBtn');
    const clearHistoryBtn = $('clearHistoryBtn');

    if (generateReportBtn) {
      generateReportBtn.addEventListener('click', generateFullDiagnosticReport);
    }

    if (printReportBtn) {
      printReportBtn.addEventListener('click', () => window.print());
    }

    if (downloadReportBtn) {
      downloadReportBtn.addEventListener('click', downloadReportHtml);
    }

    if (refreshHistoryBtn) {
      refreshHistoryBtn.addEventListener('click', loadHistoryData);
    }

    if (clearHistoryBtn) {
      clearHistoryBtn.addEventListener('click', clearHistoryData);
    }

    // Load initial history
    loadHistoryData();
  }

  async function loadHistoryData() {
    const tbody = $('historyTableBody');
    if (!tbody) return;

    if (!backendOnline) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:16px;">Backend offline. Start <code>python app.py</code> to record and view SQLite history logs.</td></tr>`;
      return;
    }

    try {
      const resp = await fetch('/api/history');
      const data = await resp.json();
      const tests = data.tests || [];

      if (tests.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:16px;">No diagnostic tests recorded yet. Run a check to populate history.</td></tr>`;
        return;
      }

      tbody.innerHTML = tests.map(t => `
        <tr>
          <td><code>${new Date(t.timestamp).toLocaleTimeString()}</code></td>
          <td><strong>${t.host}</strong></td>
          <td><code>:${t.port}</code></td>
          <td><span class="severity-pill ${t.status === 'REACHABLE' ? 'info' : 'critical'}">${t.status}</span></td>
          <td><code>${t.latency_ms || 0} ms</code></td>
          <td><button type="button" class="secondary-button btn-sm retest-btn" data-host="${t.host}" data-port="${t.port}">Re-test</button></td>
        </tr>
      `).join('');

      tbody.querySelectorAll('.retest-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          location.hash = '#diagnostics';
          $('diagHost').value = btn.dataset.host;
          $('diagPort').value = btn.dataset.port;
          runDiagnostics();
        });
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="6" style="color:var(--orange);">Failed to load history: ${err.message}</td></tr>`;
    }
  }

  async function clearHistoryData() {
    if (!confirm('Are you sure you want to clear diagnostic test history in SQLite?')) return;
    try {
      await fetch('/api/history/clear', { method: 'POST' });
      loadHistoryData();
    } catch (err) {
      alert('Error clearing history: ' + err.message);
    }
  }

  function generateFullDiagnosticReport() {
    const reportArea = $('reportPreviewArea');
    if (!reportArea) return;

    const diag = lastDiagnosticResult || {
      target: { host: '127.0.0.1', port: 8080, category: 'DEMO' },
      summary: { status: 'NOT_RUN_YET', total_latency_ms: 0 },
      tcp: { state_label: 'Pending Run', message: 'No live test has been executed in this session yet.' },
      dns: { success: true, ips: ['127.0.0.1'] },
      limitations: ['Run a live test in Diagnostics tab to populate live data.']
    };

    const analyzer = lastAnalyzerResult || {
      rule_count: activePolicy.length,
      summary: { critical: 0, warning: 0, info: 0 },
      findings: []
    };

    const comp = lastComparisonResult || {
      flowName: 'Client to Database :3306',
      simDecision: 'DENY',
      realStatus: 'UNREACHABLE',
      correlationTitle: 'Standard Baseline Comparison',
      correlationInsight: 'Simulated baseline blocks client direct access to DB. Real port is closed.'
    };

    const timestamp = new Date().toLocaleString();

    reportArea.hidden = false;
    reportArea.innerHTML = `
      <div class="report-paper">
        <div style="border-bottom:2px solid var(--ink);padding-bottom:16px;margin-bottom:24px;display:flex;justify-content:space-between;align-items:flex-end;">
          <div>
            <h1 style="font-size:24px;margin:0;">Network Troubleshooting & Firewall Policy Report</h1>
            <p style="color:var(--muted);font-size:13px;margin-top:4px;">Network Workbench 2.0 &bull; Small Network Security & Diagnostic Assessment</p>
          </div>
          <div style="text-align:right;font-family:var(--mono);font-size:12px;color:var(--muted);">
            <div>${timestamp}</div>
            <div>STATUS: OFFICIAL REPORT</div>
          </div>
        </div>

        <div class="report-meta-grid">
          <div class="report-meta-item">
            <strong>Target Host / Destination</strong>
            ${diag.target.host} (Port ${diag.target.port})
          </div>
          <div class="report-meta-item">
            <strong>Network Environment</strong>
            ${diag.target.category || 'Local Lab Subnet'}
          </div>
          <div class="report-meta-item">
            <strong>Resolved IP Address</strong>
            ${diag.dns?.ips?.join(', ') || 'None'}
          </div>
          <div class="report-meta-item">
            <strong>Connectivity Status</strong>
            ${diag.tcp?.state_label || diag.summary?.status}
          </div>
        </div>

        <section style="margin-bottom:28px;">
          <h2 style="font-size:16px;border-bottom:1px solid var(--line);padding-bottom:6px;margin-bottom:12px;">1. Real Network Transport & DNS Assessment</h2>
          <p style="font-size:13px;color:var(--ink);"><strong>Diagnosis:</strong> ${diag.tcp?.message || 'N/A'}</p>
          <p style="font-size:13px;color:var(--muted);margin-top:6px;">${diag.tcp?.explanation || ''}</p>
          <div style="margin-top:10px;font-size:12px;font-family:var(--mono);background:var(--soft);padding:8px 12px;border-radius:4px;">
            DNS Latency: ${diag.dns?.latency_ms || 0}ms &bull; TCP Latency: ${diag.tcp?.latency_ms || 0}ms
          </div>
        </section>

        <section style="margin-bottom:28px;">
          <h2 style="font-size:16px;border-bottom:1px solid var(--line);padding-bottom:6px;margin-bottom:12px;">2. Firewall Policy & Rule Logic Audit</h2>
          <p style="font-size:13px;color:var(--ink);"><strong>Rules Evaluated:</strong> ${analyzer.rule_count} rules &bull; <strong>Findings:</strong> ${analyzer.summary.critical} Critical, ${analyzer.summary.warning} Warnings</p>
          ${analyzer.findings.length === 0 ? '<p style="font-size:13px;color:#147238;">No security violations or rule order hazards detected in policy.</p>' : ''}
          ${analyzer.findings.map(f => `
            <div style="border-left:3px solid ${f.severity === 'CRITICAL' ? '#d92d20' : '#b54708'};padding-left:12px;margin-top:12px;">
              <div style="font-size:13px;font-weight:600;">[${f.severity}] ${f.rule_id}: ${f.title}</div>
              <div style="font-size:12px;color:var(--muted);margin:3px 0;">${f.description}</div>
              <div style="font-size:12px;color:var(--teal);"><strong>Action Item:</strong> ${f.remediation}</div>
            </div>
          `).join('')}
        </section>

        <section style="margin-bottom:28px;">
          <h2 style="font-size:16px;border-bottom:1px solid var(--line);padding-bottom:6px;margin-bottom:12px;">3. Architecture Model vs Real-World Correlation</h2>
          <p style="font-size:13px;color:var(--ink);"><strong>Hop Analyzed:</strong> ${comp.flowName}</p>
          <p style="font-size:13px;color:var(--muted);"><strong>Model Decision:</strong> ${comp.simDecision} &bull; <strong>Real Socket State:</strong> ${comp.realStatus}</p>
          <div style="font-size:13px;margin-top:8px;background:var(--soft);padding:12px;border-radius:4px;">
            <strong>${comp.correlationTitle}:</strong> ${comp.correlationInsight}
          </div>
        </section>

        <section style="margin-bottom:28px;">
          <h2 style="font-size:16px;border-bottom:1px solid var(--line);padding-bottom:6px;margin-bottom:12px;">4. Recommended Next Steps for Network Administrator</h2>
          <ol style="font-size:13px;color:var(--ink);line-height:1.7;margin-left:18px;padding:0;">
            <li>Enforce strict ingress filtering: eliminate any wildcard <code>0.0.0.0/0</code> allow rules on sensitive ports (SSH 22, MySQL 3306, RDP 3389).</li>
            <li>Maintain three-tier segmentation: ensure clients never communicate directly with internal databases. Direct database connectivity should be blocked at the boundary firewall.</li>
            <li>Verify server daemon state: when an RST packet is returned, confirm whether the service was intentionally stopped or unexpectedly crashed.</li>
            <li>Append an explicit catch-all <code>DENY ALL</code> rule at the end of the rule chain to eliminate implicit permissive defaults.</li>
          </ol>
        </section>

        <section style="border-top:1px solid var(--line);padding-top:14px;font-size:11px;color:var(--muted);">
          <strong>Methodological Disclaimers & Limitations:</strong>
          Findings are derived from static rule analysis and non-intrusive TCP socket handshakes. Probes determine transport accessibility without compromising host security or modifying remote network configuration.
        </section>
      </div>
    `;

    // Scroll report into view
    reportArea.scrollIntoView({ behavior: 'smooth' });
  }

  function downloadReportHtml() {
    const reportHtml = $('reportPreviewArea')?.innerHTML;
    if (!reportHtml) {
      alert('Please click "Generate Assessment Report" first.');
      return;
    }

    const fullDoc = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Workbench 2.0 Diagnostic Report</title>
<style>
body { font-family: system-ui, -apple-system, sans-serif; background: #faf9f6; color: #25241f; padding: 40px; margin: 0; }
.report-paper { max-width: 860px; margin: auto; background: white; padding: 40px; border: 1px solid #d3d0c7; box-shadow: 0 4px 16px rgba(0,0,0,0.06); }
.report-meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; border-top: 1px solid #302e28; border-bottom: 1px solid #302e28; padding: 14px 0; margin: 18px 0; }
code { font-family: monospace; font-size: 12px; background: #f4f1e9; padding: 2px 4px; border-radius: 3px; }
@media print { body { background: white; padding: 0; } .report-paper { box-shadow: none; border: none; padding: 0; } }
</style>
</head>
<body>
${reportHtml}
</body>
</html>`;

    const blob = new Blob([fullDoc], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `network-workbench-report-${Date.now()}.html`;
    a.click();
  }

})();
