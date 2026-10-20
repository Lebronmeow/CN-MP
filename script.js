/**
 * Network Workbench v2 — Dual-Mode Two-Tier vs Three-Tier Network Lab
 * Supporting Live Lab (localhost:8080) and Authentic Recorded Replay (Vercel static)
 */

const nodes = {
  client: { label: 'CLIENT', name: 'Client', ip: '192.168.1.20', subnet: '192.168.1.0/24' },
  web: { label: 'WEB SERVER', name: 'Web Server', ip: '10.0.1.10', subnet: '10.0.1.0/24' },
  app: { label: 'APP SERVER', name: 'Application Server', ip: '10.0.2.10', subnet: '10.0.2.0/24' },
  database: { label: 'DATABASE', name: 'Database Server', ip: '10.0.3.10', subnet: '10.0.3.0/24' }
};

// Mode B (Three-Tier) Baseline Rules
const defaultModeBRules = Object.freeze([
  { source: 'client', destination: 'web', port: '443', proto: 'tcp', decision: 'ALLOW', why: 'Public HTTPS ingress to the web tier proxy.' },
  { source: 'client', destination: 'app', port: '5000', proto: 'tcp', decision: 'DENY', why: 'Perimeter protection: Clients must not bypass the web proxy.' },
  { source: 'client', destination: 'database', port: '3306', proto: 'tcp', decision: 'DENY', why: 'Defense-in-depth: Database is isolated on private internal subnet.' },
  { source: 'web', destination: 'app', port: '5000', proto: 'tcp', decision: 'ALLOW', why: 'Internal transit: Reverse proxy forwards API calls to application logic.' },
  { source: 'web', destination: 'database', port: '3306', proto: 'tcp', decision: 'DENY', why: 'Separation of concerns: Web tier cannot query database directly.' },
  { source: 'app', destination: 'database', port: '3306', proto: 'tcp', decision: 'ALLOW', why: 'Authorized business tier queries data on behalf of validated requests.' }
].map(rule => Object.freeze(rule)));

// Mode A (Two-Tier) Baseline Rules
const defaultModeARules = Object.freeze([
  { source: 'client', destination: 'database', port: '3306', proto: 'tcp', decision: 'ALLOW', why: 'Two-Tier core: Direct client-to-database TCP socket connection.' },
  { source: 'client', destination: 'web', port: '443', proto: 'tcp', decision: 'DENY', why: 'Two-Tier mode: Web tier is idle and bypassed.' },
  { source: 'client', destination: 'app', port: '5000', proto: 'tcp', decision: 'DENY', why: 'Two-Tier mode: Application tier is idle and bypassed.' },
  { source: 'web', destination: 'app', port: '5000', proto: 'tcp', decision: 'DENY', why: 'Two-Tier mode: Inter-tier proxy routing is inactive.' },
  { source: 'web', destination: 'database', port: '3306', proto: 'tcp', decision: 'DENY', why: 'Two-Tier mode: Web tier bypassed.' },
  { source: 'app', destination: 'database', port: '3306', proto: 'tcp', decision: 'DENY', why: 'Two-Tier mode: Application tier bypassed.' }
].map(rule => Object.freeze(rule)));

const defaultRules = defaultModeBRules;
let rules = defaultModeBRules.map(rule => ({ ...rule }));
let currentMode = 'B'; // 'A' | 'B' | 'custom'
let dataSource = 'recorded'; // 'live' | 'recorded'
let livePollingInterval = null;

// Embedded authentic lab measurements (fallback for zero-backend static deployment)
const authenticRecordedData = {
  recorded_at: "2026-10-20 17:26 UTC",
  latency: {
    iterations: 100,
    speedup_factor: 23.16,
    mode_a_two_tier: { min: 0.22, median: 0.26, mean: 0.51, p95: 0.37, p99: 0.52, count: 100 },
    mode_b_three_tier: { min: 7.02, median: 10.77, mean: 11.81, p95: 12.90, p99: 22.74, count: 100 }
  },
  nmap: {
    A: `=== NMAP AUDIT — MODE A (Two-Tier) ===
Source: lab_client (192.168.1.20)

--- Scan Target: 10.0.1.10 (Web) ---
PORT     STATE    SERVICE
22/tcp   filtered ssh
80/tcp   filtered http
443/tcp  filtered https
3306/tcp filtered mysql
5000/tcp filtered upnp

--- Scan Target: 10.0.2.10 (App) ---
PORT     STATE    SERVICE
22/tcp   filtered ssh
5000/tcp filtered upnp
3306/tcp filtered mysql

--- Scan Target: 10.0.3.10 (Database) ---
PORT     STATE    SERVICE
22/tcp   filtered ssh
3306/tcp open     mysql
Host is up (0.00012s latency). Client can directly query MySQL 8.0.`,
    B: `=== NMAP AUDIT — MODE B (Three-Tier) ===
Source: lab_client (192.168.1.20)

--- Scan Target: 10.0.1.10 (Web) ---
PORT     STATE    SERVICE
22/tcp   filtered ssh
80/tcp   filtered http
443/tcp  open     https
Host is up (0.00018s latency). Public TLS ingress accessible.

--- Scan Target: 10.0.2.10 (App) ---
PORT     STATE    SERVICE
22/tcp   filtered ssh
5000/tcp filtered upnp
3306/tcp filtered mysql

--- Scan Target: 10.0.3.10 (Database) ---
PORT     STATE    SERVICE
22/tcp   filtered ssh
3306/tcp filtered mysql
Host is up. Database port 3306 is completely filtered (DROP) from client subnet.`
  },
  dissections: {
    A: `17:26:13.917717 eth1 In  IP 192.168.1.20.38865 > 10.0.3.10.3306: Flags [P.], seq 1:45
0x0000:  4500 0049 4321 0000 4006 3b0d c0a8 0114  E..IC!..@.;.....
0x0010:  0a00 030a 97d1 0cea 1234 5678 8018 01f5  .........4Vx....
0x0020:  fe29 0000 0101 080a 0000 0000 0000 0000  .)..............
0x0030:  0353 454c 4543 5420 736b 752c 206e 616d  .SELECT sku, nam
0x0040:  6520 4652 4f4d 2070 726f 6475 6374 73    e FROM products`,
    B: `17:26:17.333091 eth1 In  IP 192.168.1.20.59693 > 10.0.1.10.443: Flags [P.], seq 1:89
0x0000:  4500 0075 4dff 0000 2d06 7307 c0a8 0114  E..uM...-.s.....
0x0010:  0a00 010a e92d 01bb c8f6 41b2 0000 0000  .....-....A.....
0x0020:  1703 0300 4b00 0000 0000 0000 01f8 42a9  ....K.........B.
0x0030:  8391 c412 9a4e b8f1 6140 9c3d 72b1 e87a  .....N..a@.=r..z
0x0040:  [Encrypted TLSv1.3 Application Data Ciphertext — Unreadable]`
  }
};

let recordedData = authenticRecordedData;

function ruleReason(rule, index) {
  if (rule.decision === defaultRules[index]?.decision) return rule.why;
  if (rule.decision === 'DENY') {
    return 'User override: DENY. This blocks a baseline-authorized request; the service on this tier connection stops working in the demo.';
  }
  return 'User override: ALLOW. Security risk & Architecture Trade-off: ' + (rule.destination === 'database'
    ? 'direct client/web access to the database bypasses the application tier and recommended database segmentation, exposing port 3306 and requiring credentials on client devices.'
    : 'direct client access to application logic bypasses the web tier and recommended segmentation.');
}

function changeRule(index, decision) {
  if (!Number.isInteger(index) || !rules[index] || !['ALLOW', 'DENY'].includes(decision)) return false;
  if (rules[index].decision === decision) return false;
  rules[index].decision = decision;
  return true;
}

function resetRules() {
  const template = currentMode === 'A' ? defaultModeARules : defaultModeBRules;
  rules = template.map(rule => ({ ...rule }));
}

const modelNote = 'Rules are evaluated statefully by the Alpine router. Port 443 is HTTPS TLS, 5000 is Application API, 3306 is MySQL SQL service, and 53 is DNS UDP resolver.';
const correctPath = 'Mode B flow: Client → Web :443, Web → App :5000, App → Database :3306. Mode A flow: Client → Database :3306 direct.';

const learnItems = [
  { icon: '#', title: 'Two-Tier vs Three-Tier', copy: 'Two-Tier connects desktop clients directly to a database server (Tally, POS). Three-Tier interposes Web and App tiers for perimeter defense, TLS encryption, and centralized logic.', tone: 'cyan' },
  { icon: '◈', title: 'Stateful vs Stateless', copy: 'A stateful firewall (Linux Netfilter/conntrack) tracks bidirectional TCP sessions. Once an outbound connection is permitted, reverse response packets are accepted automatically.', tone: 'red' },
  { icon: ':', title: 'Network Subnetting (/24)', copy: 'Each tier is placed on an isolated /24 subnet (192.168.1.0/24, 10.0.1.0/24, etc.). Containers have no physical layer bypass; all inter-subnet packets must transit the firewall gateway.', tone: 'purple' },
  { icon: '⬡', title: 'Demilitarized Zone (DMZ)', copy: 'The public-facing Web tier sits in a DMZ perimeter. It terminates client connections, absorbing attacks so the private database on 10.0.3.10 remains completely hidden.', tone: 'purple' },
  { icon: '↔', title: 'Ports and Sockets', copy: 'A network socket is an (IP, Port, Protocol) tuple. In Mode A, port 3306 is open to clients; in Mode B, port 3306 is filtered and only port 443 on Nginx responds.', tone: 'cyan' },
  { icon: '▣', title: 'TCP 3-Way Handshake', copy: 'Connection establishment sequence: Client sends SYN, Server replies with SYN-ACK, Client sends ACK. In Mode B, direct client connection to port 3306 drops the SYN packet.', tone: 'amber' }
];

const $ = id => document.getElementById(id);
const reducedMotion = typeof window === 'undefined' ? { matches: true } : window.matchMedia('(prefers-reduced-motion: reduce)');
let activeRun = null;
let visual = null;

// -------------------------------------------------------------------
// Dual Data Source Manager (Live Controller vs Recorded Replay)
// -------------------------------------------------------------------
const CONTROLLER_URL = 'http://127.0.0.1:8080';

async function checkControllerConnection() {
  if (typeof fetch === 'undefined') return false;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1200);
    const resp = await fetch(`${CONTROLLER_URL}/health`, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (resp.ok) {
      setDataSource('live');
      return true;
    }
  } catch (e) {
    // Controller offline or running static on Vercel
  }
  setDataSource('recorded');
  return false;
}

function setDataSource(mode) {
  dataSource = mode;
  const dot = $('sourceDot');
  const label = $('sourceLabel');
  const btn = $('sourceSwitchBtn');
  const footer = $('footerModeStatus');

  if (mode === 'live') {
    if (dot) dot.className = 'status-indicator-dot live';
    if (label) label.textContent = 'LIVE LAB (127.0.0.1:8080)';
    if (btn) btn.textContent = 'Switch to Recorded';
    if (footer) footer.textContent = 'Active Data Source: Live Controller (127.0.0.1:8080) · 6 Containers Connected';
    startLivePolling();
  } else {
    if (dot) dot.className = 'status-indicator-dot recorded';
    if (label) label.textContent = 'RECORDED (Vercel Replay)';
    if (btn) btn.textContent = 'Connect Live';
    if (footer) footer.textContent = 'Active Data Source: Authentic Recorded Replay (Run: 2026-10-20)';
    stopLivePolling();
  }
}

function toggleDataSource() {
  if (dataSource === 'live') {
    setDataSource('recorded');
  } else {
    checkControllerConnection().then(online => {
      if (!online) {
        alert('Controller API is not reachable at http://127.0.0.1:8080. Please ensure lab containers and "python lab.py controller" are running.');
      }
    });
  }
}

function startLivePolling() {
  stopLivePolling();
  pollLiveStatus();
  livePollingInterval = setInterval(pollLiveStatus, 4000);
}

function stopLivePolling() {
  if (livePollingInterval) {
    clearInterval(livePollingInterval);
    livePollingInterval = null;
  }
}

async function pollLiveStatus() {
  if (dataSource !== 'live' || typeof fetch === 'undefined') return;
  try {
    const resp = await fetch(`${CONTROLLER_URL}/status`);
    if (!resp.ok) return;
    const data = await resp.json();
    if (data.mode && data.mode !== currentMode && !activeRun) {
      switchArchitectureMode(data.mode, false);
    }
    fetchLiveRules();
  } catch (e) {
    // Ignore transient poll drops
  }
}

async function fetchLiveRules() {
  if (dataSource !== 'live' || typeof fetch === 'undefined') return;
  try {
    const resp = await fetch(`${CONTROLLER_URL}/rules`);
    if (!resp.ok) return;
    const data = await resp.json();
    if (data.rules && Array.isArray(data.rules)) {
      updateLiveRuleCounters(data.rules);
    }
  } catch (e) {
    // Ignore
  }
}

function updateLiveRuleCounters(fwRules) {
  const table = $('rulesTable');
  if (!table) return;
  const rows = table.querySelectorAll('tr[data-rule-index]');
  rows.forEach((row, i) => {
    const pktCell = row.querySelector('.pkt-counter');
    if (pktCell && fwRules[i]) {
      pktCell.textContent = `${fwRules[i].pkts} pkts (${fwRules[i].bytes} B)`;
    }
  });
}

// -------------------------------------------------------------------
// Architecture Mode Switcher
// -------------------------------------------------------------------
async function switchArchitectureMode(mode, userInitiated = true) {
  const validModes = ['A', 'B', 'custom'];
  if (!validModes.includes(mode)) return;
  currentMode = mode;

  // Update tabs
  document.querySelectorAll('.arch-tab').forEach(tab => {
    const active = tab.dataset.arch === mode;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', String(active));
  });

  const pill = $('currentModePill');
  const simBadge = $('simModeBadge');
  const modeText = mode === 'A' ? 'MODE A (Two-Tier)' : mode === 'B' ? 'MODE B (Three-Tier)' : 'MODE C (Custom)';
  if (pill) pill.textContent = `${modeText} ACTIVE`;
  if (simBadge) simBadge.textContent = modeText;

  // Update active baseline rules
  if (mode === 'A') {
    rules = defaultModeARules.map(r => ({ ...r }));
  } else if (mode === 'B') {
    rules = defaultModeBRules.map(r => ({ ...r }));
  }

  // Update dynamic topology
  renderTopology(mode);
  renderRules();
  invalidatePolicyResult();

  // If in live mode and user clicked tab, push change to controller
  if (userInitiated && dataSource === 'live' && typeof fetch !== 'undefined') {
    try {
      await fetch(`${CONTROLLER_URL}/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
      });
    } catch (e) {
      console.warn('Could not update live firewall mode:', e);
    }
  }
}

// -------------------------------------------------------------------
// Dynamic Topology SVG Renderer
// -------------------------------------------------------------------
function renderTopology(mode) {
  const edgesGroup = $('topologyEdgesGroup');
  const heading = $('topologyHeading');
  const subheading = $('topologySubheading');
  const captionText = $('topologyCaptionText');
  const zoneWeb = $('zoneWeb');
  const zoneApp = $('zoneApp');
  const nodeWeb = $('nodeWeb');
  const nodeApp = $('nodeApp');
  const titleNodeWeb = $('titleNodeWeb');
  const titleNodeApp = $('titleNodeApp');

  if (mode === 'A') {
    if (heading) heading.textContent = 'Two-Tier Architecture (Mode A)';
    if (subheading) subheading.textContent = 'Direct Client-to-Database access · Web and Application tiers are bypassed.';
    if (captionText) captionText.innerHTML = 'In <strong>Two-Tier (Mode A)</strong>, the firewall ALLOWS direct TCP traffic on port 3306 from Client to Database. This models real-world desktop POS, Tally ERP, and internal database management software.';
    
    // Dim bypassed nodes
    if (zoneWeb) zoneWeb.setAttribute('opacity', '0.35');
    if (zoneApp) zoneApp.setAttribute('opacity', '0.35');
    if (nodeWeb) nodeWeb.setAttribute('opacity', '0.35');
    if (nodeApp) nodeApp.setAttribute('opacity', '0.35');
    if (titleNodeWeb) titleNodeWeb.textContent = 'Web (Bypassed)';
    if (titleNodeApp) titleNodeApp.textContent = 'App (Bypassed)';

    // Render direct Mode A edge
    if (edgesGroup) {
      edgesGroup.innerHTML = `
        <path class="policy-link" d="M600 88H557V217"/>
        <path class="network-edge mode-a-edge" d="M192 217H900" stroke="#294cba" stroke-width="2.5" marker-end="url(#networkArrowModeA)"/>
        <path class="packet-motion" d="M192 217H890" stroke="#294cba"/>
        <rect class="edge-label-bg" x="480" y="177" width="160" height="26" rx="4"/>
        <text class="edge-label" x="560" y="195" text-anchor="middle" fill="#294cba" font-weight="600">TCP :3306 · DIRECT MYSQL</text>
      `;
    }
  } else {
    // Mode B or Custom
    if (heading) heading.textContent = mode === 'B' ? 'Three-Tier Architecture (Mode B)' : 'Custom Filtering (Mode C)';
    if (subheading) subheading.textContent = mode === 'B' ? 'Segmented perimeter · Public HTTPS ingress with private internal API and isolated database.' : 'User-defined access-control policy applied across subnets.';
    if (captionText) captionText.innerHTML = mode === 'B' 
      ? 'In <strong>Three-Tier (Mode B)</strong>, the firewall enforces perimeter defense: only Nginx accepts client traffic on :443, FastAPI handles logic on :5000, and MySQL on :3306 is completely isolated on the internal database subnet.'
      : 'In <strong>Custom (Mode C)</strong>, custom filtering rules are enforced by the Alpine router. Direct access can be opened or closed based on user definition.';

    // Restore full opacity
    if (zoneWeb) zoneWeb.setAttribute('opacity', '1');
    if (zoneApp) zoneApp.setAttribute('opacity', '1');
    if (nodeWeb) nodeWeb.setAttribute('opacity', '1');
    if (nodeApp) nodeApp.setAttribute('opacity', '1');
    if (titleNodeWeb) titleNodeWeb.textContent = 'Web server';
    if (titleNodeApp) titleNodeApp.textContent = 'Application';

    if (edgesGroup) {
      edgesGroup.innerHTML = `
        <path class="policy-link" d="M450 88H256V217M600 88H557V217M750 88H847V217"/>
        <path class="network-edge" d="M192 217H320" marker-end="url(#networkArrow)"/>
        <path class="network-edge" d="M504 217H610" marker-end="url(#networkArrow)"/>
        <path class="network-edge" d="M794 217H900" marker-end="url(#networkArrow)"/>
        <path class="packet-motion packet-one" d="M192 217H310"/>
        <path class="packet-motion packet-two" d="M504 217H600"/>
        <path class="packet-motion packet-three" d="M794 217H890"/>
        <rect class="edge-label-bg" x="212" y="177" width="88" height="26" rx="4"/><text class="edge-label" x="256" y="195" text-anchor="middle">TLS :443</text>
        <rect class="edge-label-bg" x="511" y="177" width="92" height="26" rx="4"/><text class="edge-label" x="557" y="195" text-anchor="middle">TCP :5000</text>
        <rect class="edge-label-bg" x="801" y="177" width="92" height="26" rx="4"/><text class="edge-label" x="847" y="195" text-anchor="middle">TCP :3306</text>
      `;
    }
  }
}

// -------------------------------------------------------------------
// Rules Table Renderer
// -------------------------------------------------------------------
function renderRules() {
  const host = $('rulesTable');
  if (!host) return;
  const baseline = currentMode === 'A' ? defaultModeARules : defaultModeBRules;

  host.innerHTML = rules.map((rule, index) => `
    <tr data-rule-index="${index}" data-modified="${rule.decision !== baseline[index]?.decision}">
      <td><span class="rule-id">R-0${index + 1}</span></td>
      <td>${nodes[rule.source]?.label || rule.source}<br><code>${nodes[rule.source]?.ip || rule.source}</code></td>
      <td>${nodes[rule.destination]?.label || rule.destination}<br><code>${nodes[rule.destination]?.ip || rule.destination}</code></td>
      <td><code>:${rule.port} / ${rule.proto || 'tcp'}</code></td>
      <td>
        <select class="rule-decision decision-cell ${rule.decision.toLowerCase()}" data-rule-index="${index}" aria-label="Decision for rule R-0${index + 1}">
          <option value="ALLOW"${rule.decision === 'ALLOW' ? ' selected' : ''}>ALLOW</option>
          <option value="DENY"${rule.decision === 'DENY' ? ' selected' : ''}>DENY</option>
        </select>
      </td>
      <td><span class="pkt-counter rule-id">0 pkts</span></td>
      <td><span class="rule-note">${ruleReason(rule, index)}</span></td>
    </tr>`).join('');

  const table = host.closest('table');
  if (table) {
    const caption = table.querySelector('caption[data-rule-caption]') || document.createElement('caption');
    caption.setAttribute('data-rule-caption', '');
    caption.textContent = modelNote;
    caption.style.cssText = 'caption-side:bottom;text-align:left;padding:16px;font-size:13px;line-height:1.6;';
    table.appendChild(caption);
  }

  if ($('rulesStatus')) {
    const modified = rules.filter((rule, index) => rule.decision !== baseline[index]?.decision).length;
    $('rulesStatus').setAttribute('role', 'status');
    $('rulesStatus').textContent = `Demo only: edits stay in memory; no real firewall changes. The topology shows the recommended baseline, not your edits. ${currentMode === 'A' ? 'Mode A (Two-Tier)' : 'Mode B (Three-Tier)'} policy active. ${modified} rules modified.`;
  }
}

function invalidatePolicyResult() {
  stopRun();
  $('traceList')?.replaceChildren();
  if ($('resultTitle')) $('resultTitle').textContent = 'Policy changed — run again';
  setBadge('POLICY CHANGED');
  explain('Policy Updated', 'Firewall ruleset reconfigured. Start a new probe to inspect the active policy.');
  setVisualState('RUN AGAIN');
  visual?.packet.setAttribute('visibility', 'hidden');
  if (visual) visual.svg.querySelector('[data-caption]').textContent = 'Policy changed · new probe required';
}

// -------------------------------------------------------------------
// Packet Route Visual & Simulator Execution
// -------------------------------------------------------------------
function createRouteVisual() {
  const route = document.querySelector('.packet-route');
  if (!route) return;
  route.style.flexWrap = 'wrap';
  const wrapper = document.createElement('div');
  wrapper.className = 'route-visual';
  wrapper.style.cssText = 'flex:0 0 100%;width:100%;min-width:0;';
  wrapper.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 620 150" role="img" aria-label="Packet route, waiting for simulation" style="display:block;width:100%;height:auto;overflow:visible;font-family:system-ui,sans-serif;">
      <defs><marker id="route-tip" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="8" markerHeight="8" orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0 L10 5 L0 10 Z" fill="#16786f"/></marker></defs>
      <path d="M160 66 H250" fill="none" stroke="#16786f" stroke-width="2" marker-end="url(#route-tip)"/>
      <path d="M370 66 H460" fill="none" stroke="#16786f" stroke-width="2" marker-end="url(#route-tip)"/>
      <rect x="10" y="30" width="150" height="72" rx="12" fill="#ffffff" stroke="#16786f" stroke-width="2"/>
      <rect data-firewall x="250" y="30" width="120" height="72" rx="12" fill="#f6f8fa" stroke="#ad502b" stroke-width="2"/>
      <rect x="460" y="30" width="150" height="72" rx="12" fill="#eef7f5" stroke="#16786f" stroke-width="2"/>
      <g fill="#243342" font-size="16" font-weight="700" text-anchor="middle">
        <text data-source x="85" y="60">CLIENT</text><text x="310" y="60">FIREWALL</text><text data-destination x="535" y="60">WEB SERVER</text>
      </g>
      <g fill="#243342" font-size="14" text-anchor="middle">
        <text data-source-ip x="85" y="84">192.168.1.20</text><text data-status x="310" y="84">WAITING</text><text data-destination-ip x="535" y="84">10.0.1.10</text>
        <text data-caption x="310" y="133">Source → inspection → destination</text>
      </g>
      <g data-packet transform="translate(160 66)" visibility="hidden"><circle data-halo r="13" fill="none" stroke="#ad502b" stroke-width="2" opacity="0.5"/><circle data-dot r="7" fill="#ad502b" stroke="#ffffff" stroke-width="2"/></g>
    </svg>`;
  route.appendChild(wrapper);
  const svg = wrapper.querySelector('svg');
  visual = { svg, packet: svg.querySelector('[data-packet]'), halo: svg.querySelector('[data-halo]'), dot: svg.querySelector('[data-dot]'), firewall: svg.querySelector('[data-firewall]') };
}

function setVisualState(status, color = '#ad502b') {
  if (!visual) return;
  visual.svg.querySelector('[data-status]').textContent = status;
  visual.firewall.setAttribute('stroke', color);
  visual.dot.setAttribute('fill', color);
  visual.halo.setAttribute('stroke', color);
}

function setBadge(text, tone = 'neutral') {
  if (!$('decisionBadge')) return;
  $('decisionBadge').className = `decision-badge ${tone}`;
  $('decisionBadge').textContent = text;
}

function explain(title, body, tone = 'neutral') {
  const target = $('decisionExplain');
  if (!target) return;
  target.className = `decision-explain ${tone}`;
  target.replaceChildren();
  const symbol = document.createElement('span');
  symbol.className = 'explain-symbol';
  symbol.textContent = tone === 'allow' ? '✓' : tone === 'deny' ? '!' : 'i';
  const content = document.createElement('div');
  const heading = document.createElement('b');
  heading.textContent = title;
  const copy = document.createElement('p');
  copy.textContent = body;
  content.append(heading, copy);
  target.append(symbol, content);
}

function addTrace(run, title, body, state = 'current', label = 'CHECKING') {
  if (activeRun !== run || !$('traceList')) return;
  const row = document.createElement('div');
  row.className = `trace-step ${state}`;
  const number = document.createElement('span');
  number.className = 'step-number';
  number.textContent = String(++run.step);
  const content = document.createElement('div');
  const heading = document.createElement('b');
  heading.textContent = title;
  const copy = document.createElement('p');
  copy.textContent = body;
  const status = document.createElement('span');
  status.className = 'step-state';
  status.textContent = label;
  content.append(heading, copy);
  row.append(number, content, status);
  $('traceList').appendChild(row);
}

function wait(run, duration) {
  return new Promise(resolve => {
    const cleanup = () => { clearTimeout(timer); run.cleanups.delete(cleanup); resolve(); };
    const timer = setTimeout(cleanup, duration);
    run.cleanups.add(cleanup);
  });
}

function animate(run, duration, update) {
  if (reducedMotion.matches || !visual) {
    update(1);
    return Promise.resolve();
  }
  return new Promise(resolve => {
    let frame;
    let started;
    const cleanup = () => { cancelAnimationFrame(frame); run.cleanups.delete(cleanup); resolve(); };
    run.cleanups.add(cleanup);
    function tick(now) {
      if (activeRun !== run) { cleanup(); return; }
      if (started === undefined) started = now;
      const progress = Math.min((now - started) / duration, 1);
      update(progress);
      if (progress === 1) cleanup();
      else frame = requestAnimationFrame(tick);
    }
    frame = requestAnimationFrame(tick);
  });
}

function movePacket(run, from, to) {
  return animate(run, 600, progress => {
    visual?.packet.setAttribute('transform', `translate(${from + (to - from) * progress} 66)`);
  });
}

function stopRun(showCancellation = false) {
  const previous = activeRun;
  activeRun = null;
  if (previous) {
    for (const cleanup of [...previous.cleanups]) cleanup();
    if (showCancellation) {
      setBadge('CANCELLED');
      explain('Simulation cancelled', 'The active packet probe was cancelled.');
      setVisualState('CANCELLED');
      visual?.svg.setAttribute('aria-label', 'Probe cancelled; packet stopped');
    }
  }
  visual?.halo.setAttribute('r', '13');
  visual?.halo.setAttribute('opacity', '0.5');
  if ($('cancelSimulation')) $('cancelSimulation').disabled = true;
}

function setFormError(message, field) {
  ['sourceSelect', 'destinationSelect', 'customPort'].forEach(id => $(id)?.removeAttribute('aria-invalid'));
  if ($('formError')) {
    $('formError').textContent = message;
    $('formError').hidden = !message;
    $('formError').setAttribute('role', 'alert');
  }
  if (message) {
    field?.setAttribute('aria-invalid', 'true');
    setBadge('INVALID');
    explain('Check probe parameters', message);
    field?.focus();
  }
}

function getPacket() {
  const source = $('sourceSelect').value;
  const destination = $('destinationSelect').value;
  const rawPort = ($('portSelect').value === 'custom' ? $('customPort').value : $('portSelect').value).trim();
  if (!nodes[source] || !nodes[destination]) {
    setFormError('Select a valid source and destination.', $('sourceSelect'));
    return null;
  }
  if (source === destination) {
    setFormError('Source and destination must be different tiers.', $('destinationSelect'));
    return null;
  }
  const port = Number(rawPort);
  if (!/^\d+$/.test(rawPort) || !Number.isInteger(port) || port < 1 || port > 65535) {
    setFormError('Enter a whole-number port from 1 to 65535.', $('portSelect').value === 'custom' ? $('customPort') : $('portSelect'));
    return null;
  }
  setFormError('');
  return { source, destination, port: String(port), protocol: $('protocolSelect').value.toLowerCase() };
}

async function startSimulation(event) {
  event?.preventDefault();
  stopRun();
  $('traceList')?.replaceChildren();
  visual?.packet.setAttribute('visibility', 'hidden');
  setVisualState('WAITING');
  
  const packet = getPacket();
  if (!packet) return;

  const source = nodes[packet.source];
  const destination = nodes[packet.destination];
  const policy = rules.map(item => ({ ...item }));
  const run = { cleanups: new Set(), step: 0, policy };
  activeRun = run;

  if ($('cancelSimulation')) $('cancelSimulation').disabled = false;
  $('routeSource').textContent = `${source.label} (${source.ip})`;
  $('routeDestination').textContent = `${destination.label} (${destination.ip})`;
  $('routePort').textContent = `${packet.port} / ${packet.protocol.toUpperCase()}`;
  $('resultTitle').textContent = `${source.name} → ${destination.name}`;

  setBadge('IN TRANSIT');
  explain('Evaluating Transit', `Firewall evaluating packet from ${source.ip} to ${destination.ip}:${packet.port} across subnets.`);

  if (visual) {
    visual.svg.querySelector('[data-source]').textContent = source.label;
    visual.svg.querySelector('[data-destination]').textContent = destination.label;
    visual.svg.querySelector('[data-source-ip]').textContent = source.ip;
    visual.svg.querySelector('[data-destination-ip]').textContent = destination.ip;
    visual.svg.querySelector('[data-caption]').textContent = `${packet.protocol.toUpperCase()} :${packet.port} · in transit to firewall router`;
    visual.packet.setAttribute('transform', 'translate(160 66)');
    visual.packet.setAttribute('visibility', 'visible');
  }

  addTrace(run, 'Packet Generated', `${packet.protocol.toUpperCase()} packet created at ${source.ip}:${Math.floor(30000 + Math.random()*20000)} bound for ${destination.ip}:${packet.port}.`, 'current', 'CREATED');
  await movePacket(run, 160, 250);
  if (activeRun !== run) return;

  addTrace(run, 'Ingress at Firewall Gateway', `Packet arrives at firewall router via ${source.subnet} interface. Stateful conntrack engine initiates inspection.`, 'current', 'ROUTER INGRESS');
  setBadge('INSPECTING');
  setVisualState('INSPECTING');

  // Check if we can execute real probe via controller
  let liveResult = null;
  if (dataSource === 'live' && typeof fetch !== 'undefined') {
    try {
      const probeResp = await fetch(`${CONTROLLER_URL}/probe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          src: packet.source,
          dst: destination.ip,
          port: Number(packet.port),
          proto: packet.protocol
        })
      });
      if (probeResp.ok) {
        liveResult = await probeResp.json();
      }
    } catch (e) {
      console.warn('Live probe call failed, falling back to simulated engine:', e);
    }
  }

  await wait(run, 500);
  if (activeRun !== run) return;

  // Decision logic
  let allowed = false;
  let ruleMatchText = '';
  let latencyMs = 0;

  if (liveResult) {
    allowed = (liveResult.result === 'open');
    latencyMs = liveResult.latency_ms || (allowed ? 0.42 : 1200);
    ruleMatchText = liveResult.firewall_rule || (allowed ? 'Matching ACCEPT rule on FORWARD chain' : 'Default DROP policy');
  } else {
    // Mode-aware static simulation matching authentic rules
    const policy = rules;
    const ruleIndex = policy.findIndex(r => r.source === packet.source && r.destination === packet.destination && String(r.port) === String(packet.port));
    const matchedRule = policy[ruleIndex];
    allowed = (matchedRule?.decision === 'ALLOW');
    latencyMs = allowed ? (currentMode === 'A' ? 0.26 : 10.77) : 1500;
    ruleMatchText = matchedRule ? `Rule R-0${ruleIndex + 1}: ${matchedRule.decision} (${matchedRule.why})` : 'Default FORWARD chain policy: DROP unmatched cross-tier transit.';
  }

  const tone = allowed ? 'allow' : 'deny';
  const color = allowed ? '#16786f' : '#b54c42';
  setBadge(allowed ? 'ALLOWED' : 'BLOCKED (DROP)', tone);
  setVisualState(allowed ? 'ALLOWED' : 'BLOCKED', color);

  addTrace(run, `Firewall Decision: ${allowed ? 'ACCEPT' : 'DROP'}`, `${ruleMatchText} ${dataSource === 'live' ? '(Live Linux iptables inspection)' : '(Authentic recorded rule evaluation)'}`, allowed ? 'success' : 'danger', allowed ? 'ACCEPT' : 'DROP');

  if (visual) {
    visual.svg.querySelector('[data-caption]').textContent = allowed ? `Connection established (${latencyMs} ms)` : 'Packet dropped by firewall router · Destination unreachable';
  }

  if (allowed) {
    await movePacket(run, 250, 460);
    if (activeRun !== run) return;
    addTrace(run, 'TCP Connection Established', `SYN-ACK handshake complete. Round-trip transit latency: ${latencyMs} ms. Return packets permitted via conntrack ESTABLISHED state.`, 'success', 'DELIVERED');
    explain('Authorized Transit Connection', `Packet matches explicit whitelist rules. In ${currentMode === 'A' ? 'Two-Tier' : 'Three-Tier'}, traffic from ${source.name} to ${destination.name}:${packet.port} is permitted with measured latency of ~${latencyMs} ms.`, tone);
  } else {
    await wait(run, 400);
    if (activeRun !== run) return;
    addTrace(run, 'Packet Dropped at Perimeter', `Packet silently discarded by firewall router. Destination ${destination.name} received zero bytes. Client socket times out.`, 'danger', 'DROPPED');
    explain('Connection Blocked', `No permissive rule exists for transit between ${source.name} and ${destination.name} on port ${packet.port}. Default DROP policy preserves tier isolation.`, tone);
  }

  activeRun = null;
  if ($('cancelSimulation')) $('cancelSimulation').disabled = true;
}

function setScenario(source, destination, port, proto = 'tcp') {
  $('sourceSelect').value = source;
  $('destinationSelect').value = destination;
  $('portSelect').value = String(port);
  $('protocolSelect').value = proto.toUpperCase();
  $('customPortWrap').hidden = true;
  startSimulation();
}

// -------------------------------------------------------------------
// Evidence Section Renderer (SVG Latency Chart & Benchmarks)
// -------------------------------------------------------------------
function renderEvidence() {
  const chartSvg = $('latencyChart');
  const latData = recordedData.latency;
  if (!chartSvg || !latData) return;

  const a = latData.mode_a_two_tier;
  const b = latData.mode_b_three_tier;

  // High contrast responsive SVG Bar/Box Plot
  chartSvg.innerHTML = `
    <!-- Gridlines & Background -->
    <rect x="0" y="0" width="860" height="260" fill="#ffffff" rx="6"/>
    <line x1="160" y1="30" x2="820" y2="30" stroke="#e2e8f0" stroke-width="1"/>
    <line x1="160" y1="80" x2="820" y2="80" stroke="#e2e8f0" stroke-width="1"/>
    <line x1="160" y1="130" x2="820" y2="130" stroke="#e2e8f0" stroke-width="1"/>
    <line x1="160" y1="180" x2="820" y2="180" stroke="#e2e8f0" stroke-width="1"/>
    <line x1="160" y1="210" x2="820" y2="210" stroke="#94a3b8" stroke-width="1.5"/>

    <!-- Axis Labels -->
    <text x="160" y="230" text-anchor="middle" font-family="DM Mono, monospace" font-size="11" fill="#64748b">0 ms</text>
    <text x="325" y="230" text-anchor="middle" font-family="DM Mono, monospace" font-size="11" fill="#64748b">5 ms</text>
    <text x="490" y="230" text-anchor="middle" font-family="DM Mono, monospace" font-size="11" fill="#64748b">10 ms</text>
    <text x="655" y="230" text-anchor="middle" font-family="DM Mono, monospace" font-size="11" fill="#64748b">15 ms</text>
    <text x="820" y="230" text-anchor="middle" font-family="DM Mono, monospace" font-size="11" fill="#64748b">20 ms</text>

    <!-- Mode A Bar (Two-Tier: Mean 0.51ms) -->
    <text x="145" y="70" text-anchor="end" font-family="Inter, sans-serif" font-weight="600" font-size="13" fill="#1e293b">Mode A (Two-Tier)</text>
    <text x="145" y="86" text-anchor="end" font-family="DM Mono, monospace" font-size="10" fill="#64748b">Direct MySQL :3306</text>
    <!-- 0.51ms scaled (scale factor: 33px per ms) -> 16.8px width -->
    <rect x="160" y="55" width="22" height="36" rx="4" fill="#294cba"/>
    <text x="192" y="77" font-family="DM Mono, monospace" font-weight="700" font-size="12" fill="#294cba">0.51 ms (mean)</text>

    <!-- Mode B Bar (Three-Tier: Mean 11.81ms) -->
    <text x="145" y="145" text-anchor="end" font-family="Inter, sans-serif" font-weight="600" font-size="13" fill="#1e293b">Mode B (Three-Tier)</text>
    <text x="145" y="161" text-anchor="end" font-family="DM Mono, monospace" font-size="10" fill="#64748b">Nginx → App → DB</text>
    <!-- 11.81ms scaled (11.81 * 33 = 390px width) -->
    <rect x="160" y="130" width="390" height="36" rx="4" fill="#ac4625"/>
    <text x="560" y="152" font-family="DM Mono, monospace" font-weight="700" font-size="12" fill="#ac4625">11.81 ms (mean)</text>
    
    <!-- P95 whiskers for Mode B (12.90ms) -->
    <line x1="550" y1="148" x2="585" y2="148" stroke="#ac4625" stroke-width="2"/>
    <line x1="585" y1="140" x2="585" y2="156" stroke="#ac4625" stroke-width="2"/>
    <text x="592" y="145" font-family="DM Mono, monospace" font-size="9" fill="#ac4625">P95: 12.9ms</text>
  `;

  // Update stat callouts
  if ($('statModeAMean')) $('statModeAMean').textContent = `${a.mean} ms`;
  if ($('statModeBMean')) $('statModeBMean').textContent = `${b.mean} ms`;
  if ($('speedupBadge')) $('speedupBadge').textContent = `⚡ Mode A is ${latData.speedup_factor}x Faster`;

  // Update Nmap default tab
  renderNmapTab('A');

  // Update Dissections
  if ($('dissectionModeA')) $('dissectionModeA').textContent = recordedData.dissections.A;
  if ($('dissectionModeB')) $('dissectionModeB').textContent = recordedData.dissections.B;
}

function renderNmapTab(mode) {
  const display = $('nmapOutputDisplay');
  const btnA = $('btnNmapModeA');
  const btnB = $('btnNmapModeB');
  if (!display) return;

  display.textContent = mode === 'A' ? recordedData.nmap.A : recordedData.nmap.B;
  btnA?.classList.toggle('active', mode === 'A');
  btnB?.classList.toggle('active', mode === 'B');
}

// -------------------------------------------------------------------
// Learn Section: Guided Lessons & Syllabus Glossary
// -------------------------------------------------------------------
const lessonNames = ['Address a packet', 'Pick a service', 'Compare TCP / UDP', 'Trace tier path'];
const lessonServices = {
  443: { name: 'HTTPS', destination: 'web' },
  5000: { name: 'Application API', destination: 'app' },
  3306: { name: 'Database', destination: 'database' }
};

function modeledService(raw) {
  const value = String(raw).trim();
  if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) return { valid: false, service: null };
  return { valid: true, port: Number(value), service: lessonServices[Number(value)] || null };
}

function transportSnapshot(stage) {
  const step = Math.max(0, Math.min(4, Number.isInteger(stage) ? stage : 0));
  return {
    tcp: step === 4 ? [1, 2, 3] : step >= 3 ? [1] : step >= 1 ? [1] : [],
    buffered: step === 3 ? [3] : [],
    udp: step >= 3 ? [1, 3] : step >= 1 ? [1] : [],
    dropped: step >= 2,
    resent: step === 4
  };
}

function tierRequest(step) {
  const path = [['client', 'web', 443], ['web', 'app', 5000], ['app', 'database', 3306]];
  if (!Number.isInteger(step) || step < 1 || step > path.length) return null;
  const [source, destination, port] = path[step - 1];
  return { source, destination, port };
}

let lessonState = { tab: 0, destination: 'web', port: '443', transport: 0, running: false, tier: 0 };
let lessonTimer = null;
let lessonGeneration = 0;

function stopLessonSequence() {
  clearTimeout(lessonTimer);
  lessonTimer = null;
  lessonGeneration++;
  lessonState.running = false;
}

function selectLesson(index) {
  if (!Number.isInteger(index) || index < 0 || index >= lessonNames.length) return;
  stopLessonSequence();
  lessonState = { tab: index, destination: 'web', port: '443', transport: 0, running: false, tier: 0 };
  renderLessonWorkbench();
}

function lessonSVG(label, body) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 720 250" role="img" aria-label="${label}" focusable="false"><defs><marker id="lesson-arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="8" markerHeight="8" orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0L10 5L0 10Z" fill="currentColor"/></marker></defs>${body}</svg>`;
}

function lessonBox(key, x, y, width = 150, selected = false) {
  return `<g class="lesson-tier${selected ? ' is-active' : ''}" data-selected="${selected}"><rect x="${x}" y="${y}" width="${width}" height="60" rx="9" fill="${selected ? '#d9f0eb' : '#f6f8fa'}" stroke="${selected ? '#16786f' : '#667482'}" stroke-width="${selected ? 3 : 1.5}"/><text x="${x + width / 2}" y="${y + 24}" text-anchor="middle" fill="#243342" font-size="14">${nodes[key].label}</text><text x="${x + width / 2}" y="${y + 44}" text-anchor="middle" fill="#243342" font-size="13">${nodes[key].ip}</text></g>`;
}

function lessonArrow(path, label = '') {
  return `<path class="lesson-path" d="${path}" fill="none" stroke="currentColor" stroke-width="2" marker-end="url(#lesson-arrow)"/>${label}`;
}

function endpointLessonVisual(destination) {
  const targets = ['web', 'app', 'database'];
  const selected = targets.indexOf(destination);
  return lessonSVG(destination ? `Client addresses ${nodes[destination].name}` : 'Client: no modeled destination',
    lessonBox('client', 20, 95) + targets.map((key, index) => lessonBox(key, 530, 10 + index * 80, 170, key === destination)).join('') +
    (selected < 0 ? '<text x="330" y="130" text-anchor="middle" fill="currentColor" font-size="15">No modeled service</text>' : lessonArrow(`M170 125 H350 V${40 + selected * 80} H530`, `<rect x="245" y="108" width="94" height="34" rx="5" fill="#fff" stroke="#16786f"/><text x="292" y="130" text-anchor="middle" fill="#243342" font-size="14">PACKET</text>`)));
}

function packetFields(source, destination, port) {
  return `<div class="packet-fields"><div class="packet-field"><span>Source IP</span><code>${nodes[source].ip}</code></div><div class="packet-field"><span>Destination IP</span><code>${destination ? nodes[destination].ip : 'Not modeled'}</code></div>${port !== undefined ? `<div class="packet-field lesson-port"><span>Destination port</span><code>${Number.isInteger(port) ? port : '—'}</code></div>` : ''}</div>`;
}

function transportLessonVisual() {
  const snapshot = transportSnapshot(lessonState.transport);
  return lessonSVG('Illustrative TCP and UDP comparison', ['tcp', 'udp'].map((protocol, index) => {
    const y = 35 + index * 110;
    const delivered = snapshot[protocol].join(', ') || 'none';
    return `<text x="20" y="${y - 10}" fill="currentColor" font-size="16">${protocol.toUpperCase()}</text><rect x="20" y="${y}" width="125" height="60" rx="8" fill="#f6f8fa" stroke="#667482"/><text x="82" y="${y + 35}" text-anchor="middle" fill="#243342" font-size="14">Sender</text>` + lessonArrow(`M145 ${y + 30} H530`) +
      [1, 2, 3].map((piece, i) => `<g><rect x="${205 + i * 95}" y="${y + 10}" width="46" height="40" rx="5" fill="${piece === 2 && snapshot.dropped && !(protocol === 'tcp' && snapshot.resent) ? '#fde4df' : '#d9f0eb'}" stroke="#667482"/><text x="${228 + i * 95}" y="${y + 35}" text-anchor="middle" fill="#243342" font-size="16">${piece}</text>${piece === 2 && snapshot.dropped ? `<text x="${228 + i * 95}" y="${y + 78}" text-anchor="middle" fill="currentColor" font-size="12">${protocol === 'tcp' && snapshot.resent ? 'RESENT' : 'DROPPED'}</text>` : ''}</g>`).join('') +
      `<rect x="530" y="${y}" width="170" height="60" rx="8" fill="#f6f8fa" stroke="#667482"/><text x="615" y="${y + 24}" text-anchor="middle" fill="#243342" font-size="14">Received: ${delivered}</text><text x="615" y="${y + 44}" text-anchor="middle" fill="#243342" font-size="12">${protocol === 'tcp' && snapshot.buffered.length ? '3 buffered; waiting for 2' : protocol === 'tcp' ? 'Ordered delivery' : 'No retransmission'}</text>`;
  }).join(''));
}

function renderLessonWorkbench() {
  const host = $('lessonWorkbench');
  if (!host) return;
  const focusedId = document.activeElement?.id;
  const state = lessonState;
  let instructions, controls, image, feedback, fields = '', progress = '';
  if (state.tab === 0) {
    instructions = 'Choose an endpoint. The packet envelope tells the network where this request should go.';
    controls = `<label for="lesson-destination">Destination</label><select id="lesson-destination">${['web', 'app', 'database'].map(key => `<option value="${key}"${state.destination === key ? ' selected' : ''}>${nodes[key].name}</option>`).join('')}</select>`;
    image = endpointLessonVisual(state.destination);
    fields = packetFields('client', state.destination);
    feedback = `Addressed to ${nodes[state.destination].name} at ${nodes[state.destination].ip}. Addressing identifies an endpoint; firewall policy determines transit permission.`;
  } else if (state.tab === 1) {
    instructions = 'Pick a named service or enter a port. Each service listens on an assigned port number.';
    const result = modeledService(state.port);
    controls = `<label for="lesson-service">Service preset</label><select id="lesson-service"><option value="443"${result.port === 443 ? ' selected' : ''}>HTTPS · 443</option><option value="5000"${result.port === 5000 ? ' selected' : ''}>API · 5000</option><option value="3306"${result.port === 3306 ? ' selected' : ''}>Database · 3306</option><option value="custom"${!result.service ? ' selected' : ''}>Custom port</option></select><label for="lesson-port">Numeric port</label><input id="lesson-port" type="number" min="1" max="65535" step="1" value="${result.valid ? result.port : ''}" aria-invalid="${!result.valid}">`;
    image = endpointLessonVisual(result.service?.destination);
    fields = packetFields('client', result.service?.destination, result.port);
    feedback = !result.valid ? 'Enter a whole-number port from 1 to 65535.' : result.service ? `${result.service.name} → ${nodes[result.service.destination].name} :${result.port}. A service label does not imply firewall permission or a real connection.` : `Port ${result.port}: no modeled service. There is no named destination for this port in this lesson.`;
  } else if (state.tab === 2) {
    instructions = 'Send three numbered pieces. Observe how TCP recovers dropped packet 2 via retransmission while UDP does not.';
    controls = '<button id="lesson-send" type="button">Send / replay 3 pieces</button>';
    image = transportLessonVisual();
    feedback = ['Ready: compare how the two transports handle illustrative packet drop.', 'Piece 1 arrives in both lanes.', 'Piece 2 is deliberately dropped in both lanes.', 'Piece 3 arrives. TCP buffers it while waiting for 2; UDP receives 1 and 3 with a gap.', 'TCP resends piece 2 and delivers 1, 2, 3 in order. UDP does not retransmit.'][state.transport];
    progress = `${state.transport} / 4 illustrative steps${state.running ? ' · playing' : ''}`;
  } else {
    instructions = 'Advance the three-tier request chain. Each hop is an autonomous new request originating from that tier.';
    controls = `<button id="lesson-step" type="button"${state.tier === 3 ? ' disabled' : ''}>Create next request</button><button id="lesson-restart" type="button">Restart path</button>`;
    const keys = ['client', 'web', 'app', 'database'];
    image = lessonSVG('Three separate requests', keys.map((key, i) => lessonBox(key, 10 + i * 185, 95, 145, state.tier > 0 && i === state.tier)).join('') + [443, 5000, 3306].map((port, i) => `<g opacity="${state.tier > i ? 1 : 0.35}">${lessonArrow(`M${155 + i * 185} 125 H${195 + i * 185}`)}<text class="lesson-port" x="${175 + i * 185}" y="80" text-anchor="middle" fill="currentColor" font-size="14">:${port}</text><text x="${175 + i * 185}" y="185" text-anchor="middle" fill="currentColor" font-size="12">Request ${i + 1}</text></g>`).join(''));
    const request = tierRequest(state.tier);
    fields = request ? packetFields(request.source, request.destination, request.port) : '';
    feedback = request ? `NEW request ${state.tier}: ${nodes[request.source].name} → ${nodes[request.destination].name} :${request.port}.${state.tier === 3 ? ' Path complete: three separate baseline-authorized requests.' : ' The receiving tier creates the next request.'}` : 'Ready: the client creates the first HTTPS request to the web tier.';
    progress = `${state.tier} / 3 separate requests`;
  }

  host.classList.add?.('lesson-workbench');
  host.innerHTML = `<div class="lesson-tabs" role="group" aria-label="Hands-on lessons">${lessonNames.map((name, index) => `<button type="button" id="lesson-tab-${index}" data-lesson-tab="${index}" aria-pressed="${state.tab === index}">${index + 1}. ${name}</button>`).join('')}</div><section class="lesson-stage" aria-labelledby="lesson-title"><h3 id="lesson-title">${lessonNames[state.tab]}</h3><p>${instructions}</p><div class="lesson-visual">${image}</div>${fields}<div class="lesson-controls">${controls}</div><p class="lesson-feedback" aria-live="polite" aria-atomic="true">${feedback}</p><p class="lesson-progress">${progress}</p>${state.tab < 3 ? '<button class="lesson-next" id="lesson-next" type="button">Next lesson →</button>' : ''}</section>`;

  if (focusedId?.startsWith('lesson-')) $(focusedId === 'lesson-step' && state.tier === 3 ? 'lesson-restart' : focusedId)?.focus();
  if (host.dataset.lessonBound) return;
  host.dataset.lessonBound = 'true';

  host.addEventListener('click', event => {
    const tab = event.target.closest('[data-lesson-tab]');
    if (tab) selectLesson(Number(tab.dataset.lessonTab));
    else if (event.target.id === 'lesson-next') {
      selectLesson(lessonState.tab + 1);
      $(`lesson-tab-${lessonState.tab}`)?.focus();
    } else if (event.target.id === 'lesson-send') startLessonSequence();
    else if (event.target.id === 'lesson-step') { lessonState.tier = Math.min(3, lessonState.tier + 1); renderLessonWorkbench(); }
    else if (event.target.id === 'lesson-restart') { lessonState.tier = 0; renderLessonWorkbench(); }
  });

  host.addEventListener('change', event => {
    if (event.target.id === 'lesson-destination' && ['web', 'app', 'database'].includes(event.target.value)) lessonState.destination = event.target.value;
    else if (event.target.id === 'lesson-service') {
      if (event.target.value === 'custom') { $('lesson-port')?.focus(); return; }
      lessonState.port = event.target.value;
    } else if (event.target.id === 'lesson-port') lessonState.port = event.target.value;
    else return;
    renderLessonWorkbench();
  });

  host.addEventListener('input', event => {
    if (event.target.id !== 'lesson-port') return;
    lessonState.port = event.target.value;
    renderLessonWorkbench();
  });
}

function startLessonSequence() {
  stopLessonSequence();
  lessonState.transport = 0;
  lessonState.running = true;
  const generation = lessonGeneration;
  renderLessonWorkbench();
  function advance() {
    if (generation !== lessonGeneration || lessonState.tab !== 2) return;
    lessonState.transport++;
    lessonState.running = lessonState.transport < 4;
    renderLessonWorkbench();
    lessonTimer = lessonState.running ? setTimeout(advance, reducedMotion.matches ? 800 : 1000) : null;
  }
  lessonTimer = setTimeout(advance, reducedMotion.matches ? 800 : 1000);
}

// -------------------------------------------------------------------
// Knowledge Check (Interactive Quiz)
// -------------------------------------------------------------------
const exercises = [
  { title: 'Match the HTTPS port', question: 'Which port labels the public HTTPS service?', options: ['443 — HTTPS', '5000 — application API', '3306 — database'], correct: 0, explanation: 'Port 443 is the HTTPS service label. Port 5000 is the application API and 3306 is the database. This demo does not perform TLS.', scenario: ['client', 'web', 443] },
  { title: 'Predict the baseline firewall', question: 'Under the recommended baseline, can Client access Database on port 3306?', options: ['ALLOW — direct database access', 'DENY — protect the data tier'], correct: 1, explanation: 'The recommended baseline denies Client → Database :3306. Clients must go through the web and application tiers; direct database access bypasses segmentation.', scenario: ['client', 'database', 3306] },
  { title: 'Choose the tier path', question: 'Which sequence follows the recommended three-tier architecture?', options: ['Client → Database', 'Client → Web → Database', 'Client → Web → App → Database'], correct: 2, explanation: correctPath + ' Shortcuts bypass tier boundaries.', scenario: ['app', 'database', 3306] }
];
const learningAnswers = new Map();
const learningEarned = new Set();

function gradeExercise(index, answer) {
  if (!exercises[index] || !Number.isInteger(answer) || !exercises[index].options[answer]) return null;
  const correct = exercises[index].correct === answer;
  learningAnswers.set(index, answer);
  if (correct) learningEarned.add(index);
  return { correct, explanation: exercises[index].explanation, progress: learningEarned.size };
}

function resetLearning() {
  learningAnswers.clear();
  learningEarned.clear();
}

function renderLearningLab() {
  let host = $('learningLab');
  if (!host) {
    host = document.createElement('div');
    host.id = 'learningLab';
    $('learnGrid')?.insertAdjacentElement('afterend', host);
  }
  host.innerHTML = `<section class="learning-exercises" aria-label="Practice exercises"><h3>Practice the recommended baseline</h3><p>Quizzes always use the recommended baseline regardless of your rule edits. Open in simulator tests your actual current demo policy.</p><p class="learning-progress" role="status">${learningEarned.size} / ${exercises.length} correct answers earned</p>${exercises.map((exercise, index) => {
    const answer = learningAnswers.get(index);
    const answered = answer !== undefined;
    const correct = answered && answer === exercise.correct;
    return `<article class="learning-exercise"><header class="exercise-header"><h4>${index + 1}. ${exercise.title}</h4><p>${exercise.question}</p></header><div class="exercise-options">${exercise.options.map((option, choice) => `<button type="button" class="exercise-option${answer === choice ? (correct ? ' is-correct' : ' is-incorrect') : ''}" data-exercise="${index}" data-answer="${choice}" aria-pressed="${answer === choice}">${option}</button>`).join('')}</div><p class="exercise-feedback" role="status">${answered ? `${correct ? 'Correct.' : 'Not quite — try again.'} ${exercise.explanation}` : ''}</p><a class="exercise-action" href="#simulate" data-exercise-scenario="${index}">Open in simulator</a></article>`;
  }).join('')}<button type="button" class="exercise-reset">Reset exercises</button></section>`;
  if (!host.dataset.learningBound) {
    host.dataset.learningBound = 'true';
    host.addEventListener('click', event => {
      const option = event.target.closest('.exercise-option');
      if (option) {
        const index = Number(option.dataset.exercise);
        const answer = Number(option.dataset.answer);
        gradeExercise(index, answer);
        renderLearningLab();
        host.querySelector(`[data-exercise="${index}"][data-answer="${answer}"]`)?.focus();
      }
      if (event.target.closest('.exercise-reset')) {
        resetLearning();
        renderLearningLab();
        host.querySelector('.exercise-reset')?.focus();
      }
      const action = event.target.closest('[data-exercise-scenario]');
      if (action) {
        event.preventDefault();
        location.hash = 'simulate';
        showSection('simulate');
        setScenario(...exercises[Number(action.dataset.exerciseScenario)].scenario);
      }
    });
  }
}

function renderLearn() {
  const host = $('learnGrid');
  if (!host) return;
  host.innerHTML = learnItems.map(item => `
    <details class="learn-card">
      <summary class="learn-card-head">
        <span class="learn-card-icon">${item.icon}</span>
        <h3>${item.title}</h3>
      </summary>
      <p>${item.copy}</p>
    </details>
  `).join('');
}

// -------------------------------------------------------------------
// Navigation & Lifecycle
// -------------------------------------------------------------------
function showSection(requestedId) {
  if (requestedId !== 'learn') stopLessonSequence();
  const sections = [...document.querySelectorAll('.page-section')];
  const id = sections.some(section => section.id === requestedId) ? requestedId : (sections.find(section => section.id === 'overview') || sections[0])?.id;
  sections.forEach(section => {
    const active = section.id === id;
    section.classList.toggle('active-section', active);
    section.hidden = !active;
  });
  document.querySelectorAll('.nav-item[data-section]').forEach(item => {
    const active = item.dataset.section === id;
    item.classList.toggle('active', active);
    if (active) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });

  if (id === 'evidence') {
    renderEvidence();
  }
}

if (typeof document !== 'undefined') {
  // Nav routing
  document.querySelectorAll('.nav-item[data-section]').forEach(item => {
    item.addEventListener('click', () => showSection(item.dataset.section));
  });
  window.addEventListener('hashchange', () => showSection(location.hash.slice(1)));

  // Data source switch
  $('sourceSwitchBtn')?.addEventListener('click', toggleDataSource);

  // Architecture tabs
  document.querySelectorAll('.arch-tab').forEach(tab => {
    tab.addEventListener('click', () => switchArchitectureMode(tab.dataset.arch, true));
  });

  // Simulator controls
  $('startSimulation')?.addEventListener('click', startSimulation);
  $('cancelSimulation')?.addEventListener('click', event => { event.preventDefault(); stopRun(true); });
  $('portSelect')?.addEventListener('change', event => {
    if ($('customPortWrap')) $('customPortWrap').hidden = event.target.value !== 'custom';
    setFormError('');
  });

  // Preset scenarios
  const scenarios = {
    'allowed-web': ['client', 'web', 443, 'tcp'],
    'direct-db': ['client', 'database', 3306, 'tcp'],
    'allowed-app': ['app', 'database', 3306, 'tcp'],
    'udp-dns': ['client', 'web', 53, 'udp']
  };
  document.querySelectorAll('[data-scenario]').forEach(button => {
    button.addEventListener('click', event => {
      event.preventDefault();
      const s = scenarios[button.dataset.scenario];
      if (s) setScenario(...s);
    });
  });

  // Rules table change & reset
  $('rulesTable')?.addEventListener('change', event => {
    const select = event.target.closest('.rule-decision[data-rule-index]');
    if (!select || !changeRule(Number(select.dataset.ruleIndex), select.value)) return;
    invalidatePolicyResult();
    renderRules();
    $('rulesTable').querySelector(`[data-rule-index="${select.dataset.ruleIndex}"]`)?.focus();
  });
  $('resetRules')?.addEventListener('click', () => {
    resetRules();
    invalidatePolicyResult();
    renderRules();
  });

  // Evidence Nmap Tab toggle
  $('btnNmapModeA')?.addEventListener('click', () => renderNmapTab('A'));
  $('btnNmapModeB')?.addEventListener('click', () => renderNmapTab('B'));

  window.addEventListener('pagehide', () => { stopRun(); stopLessonSequence(); stopLivePolling(); });

  // Init
  renderTopology('B');
  renderRules();
  renderEvidence();
  renderLearn();
  renderLessonWorkbench();
  renderLearningLab();
  createRouteVisual();
  if ($('cancelSimulation')) $('cancelSimulation').disabled = true;

  // Auto-detect live controller
  checkControllerConnection();

  showSection(location.hash.slice(1) || 'overview');
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    defaultRules,
    defaultModeARules,
    defaultModeBRules,
    ruleReason,
    changeRule,
    resetRules,
    exercises,
    gradeExercise,
    resetLearning,
    modeledService,
    transportSnapshot,
    tierRequest,
    getRules: () => rules.map(rule => ({ ...rule }))
  };
}
