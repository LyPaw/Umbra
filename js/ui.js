/**
 * UMBRA UI Controller v2.0
 * Tabs, sidebar, algo panels, brute-force UI, image analysis UI.
 * Depends on: crypto.js, bruteforce.js
 */
'use strict';

/* ── STATE ────────────────────────────────────────────────── */
const State = {
  theme: localStorage.getItem('umbra-theme') || 'dark',
  tabs: [],
  activeTab: null,
  history: JSON.parse(localStorage.getItem('umbra-history') || '[]'),
  tabCounter: 0,
};

/* ── SIDEBAR GROUPS ───────────────────────────────────────── */
const SIDEBAR_GROUPS = [
  { label: 'Tools', items: [
    { id: 'bruteforce-all', icon: '💥' },
    { id: 'image-scan',     icon: '🖼️' },
    { id: 'auto-detect',    icon: '⚡' },
  ]},
  { label: 'Classic Ciphers', items: [
    { id: 'caesar',       icon: '🔡' },
    { id: 'rot13',        icon: '🔄' },
    { id: 'rot47',        icon: '🔀' },
    { id: 'atbash',       icon: '↔️' },
    { id: 'vigenere',     icon: '🗝️' },
    { id: 'beaufort',     icon: '⚓' },
    { id: 'playfair',     icon: '♟️' },
    { id: 'affine',       icon: '📐' },
    { id: 'railfence',    icon: '🚧' },
    { id: 'columnar',     icon: '📊' },
    { id: 'substitution', icon: '🔤' },
  ]},
  { label: 'Encoding', items: [
    { id: 'base64',    icon: '📦' },
    { id: 'base64url', icon: '🔗' },
    { id: 'base32',    icon: '🧮' },
    { id: 'base58',    icon: '₿'  },
    { id: 'hex',       icon: '🔢' },
    { id: 'binary',    icon: '💾' },
    { id: 'octal',     icon: '8️⃣' },
    { id: 'url',       icon: '🌐' },
    { id: 'html',      icon: '🏷️' },
    { id: 'unicode',   icon: '🔣' },
    { id: 'morse',     icon: '📡' },
    { id: 'nato',      icon: '✈️' },
  ]},
  { label: 'Modern / Symmetric', items: [
    { id: 'xor',     icon: '⊕'  },
    { id: 'aes-gcm', icon: '🔒' },
    { id: 'aes-cbc', icon: '🛡️' },
  ]},
  { label: 'Hash Functions', items: [
    { id: 'md5',    icon: '#️⃣' },
    { id: 'sha1',   icon: '#️⃣' },
    { id: 'sha256', icon: '#️⃣' },
    { id: 'sha384', icon: '#️⃣' },
    { id: 'sha512', icon: '#️⃣' },
    { id: 'crc32',  icon: '🔍' },
  ]},
];

const BADGE_MAP = {
  classic:  { cls: 'badge-classic', label: 'CLASSIC' },
  encoding: { cls: 'badge-encode',  label: 'ENCODE'  },
  modern:   { cls: 'badge-modern',  label: 'MODERN'  },
  hash:     { cls: 'badge-hash',    label: 'HASH'    },
  special:  { cls: 'badge-special', label: 'TOOL'    },
};

const SPECIAL_IDS = new Set(['bruteforce-all','image-scan','auto-detect']);

/* ── THEME ────────────────────────────────────────────────── */
function applyTheme(theme) {
  State.theme = theme;
  document.documentElement.setAttribute('data-theme', theme === 'light' ? 'light' : '');
  const btn = document.getElementById('theme-toggle');
  if (btn) btn.textContent = theme === 'light' ? '🌑' : '☀️';
  localStorage.setItem('umbra-theme', theme);
}
function toggleTheme() { applyTheme(State.theme === 'dark' ? 'light' : 'dark'); }

/* ── SIDEBAR ──────────────────────────────────────────────── */
function buildSidebar() {
  const sidebar = document.getElementById('sidebar');
  sidebar.innerHTML = '';

  const searchDiv = document.createElement('div');
  searchDiv.className = 'sidebar-search';
  searchDiv.innerHTML = `<input type="text" id="algo-search" placeholder="/ search algorithms..." autocomplete="off">`;
  sidebar.appendChild(searchDiv);

  SIDEBAR_GROUPS.forEach(group => {
    const section = document.createElement('div');
    section.className = 'sidebar-section';
    section.dataset.group = group.label;

    const label = document.createElement('div');
    label.className = 'sidebar-label';
    label.textContent = group.label;
    section.appendChild(label);

    group.items.forEach(({ id, icon }) => {
      let info, badge;
      if (SPECIAL_IDS.has(id)) {
        info = { name: specialName(id) };
        badge = BADGE_MAP.special;
      } else {
        const algo = window.ALGOS[id];
        if (!algo) return;
        info = algo.info;
        badge = BADGE_MAP[info.category] || BADGE_MAP.special;
      }
      const item = document.createElement('div');
      item.className = 'algo-item';
      item.dataset.algoId = id;
      item.innerHTML = `<span>${icon}</span><span>${info.name}</span><span class="algo-badge ${badge.cls}">${badge.label}</span>`;
      item.addEventListener('click', () => openTab(id));
      section.appendChild(item);
    });

    sidebar.appendChild(section);
  });

  document.getElementById('algo-search').addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll('.algo-item').forEach(item => {
      item.style.display = item.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
    document.querySelectorAll('.sidebar-section').forEach(sec => {
      const vis = [...sec.querySelectorAll('.algo-item')].some(i => i.style.display !== 'none');
      sec.style.display = vis ? '' : 'none';
    });
  });
}

function specialName(id) {
  return { 'bruteforce-all': 'Brute Force All', 'image-scan': 'Image Scan (OCR)', 'auto-detect': 'Auto-Detect' }[id] || id;
}

/* ── TABS ─────────────────────────────────────────────────── */
function createTab(id) {
  const tabId = `tab-${++State.tabCounter}`;
  const label = SPECIAL_IDS.has(id) ? specialName(id) : (window.ALGOS[id]?.info.name || id);
  const tab = { id: tabId, algoId: id, label, input: '', key: '', output: '', mode: 'decode', status: 'idle' };
  State.tabs.push(tab);
  return tab;
}

function openTab(algoId) {
  const existing = State.tabs.find(t => t.algoId === algoId);
  if (existing) { activateTab(existing.id); return; }
  const tab = createTab(algoId);
  renderTabBar();
  activateTab(tab.id);
  highlightSidebar(algoId);
}

function activateTab(tabId) {
  State.activeTab = tabId;
  renderTabBar();
  renderWorkspace();
  const tab = State.tabs.find(t => t.id === tabId);
  if (tab) highlightSidebar(tab.algoId);
}

function closeTab(tabId) {
  const idx = State.tabs.findIndex(t => t.id === tabId);
  State.tabs.splice(idx, 1);
  if (State.activeTab === tabId) {
    State.activeTab = State.tabs[Math.max(0, idx - 1)]?.id || null;
  }
  renderTabBar();
  renderWorkspace();
}

function renderTabBar() {
  const bar = document.getElementById('tabs-bar');
  bar.innerHTML = '';
  State.tabs.forEach(tab => {
    const el = document.createElement('div');
    el.className = `tab${tab.id === State.activeTab ? ' active' : ''}`;
    el.innerHTML = `<span>${tab.label}</span><button class="tab-close" title="Close">×</button>`;
    el.addEventListener('click', e => { if (!e.target.classList.contains('tab-close')) activateTab(tab.id); });
    el.querySelector('.tab-close').addEventListener('click', e => { e.stopPropagation(); closeTab(tab.id); });
    bar.appendChild(el);
  });
  const newBtn = document.createElement('button');
  newBtn.className = 'tab-new-btn';
  newBtn.title = 'New Auto-Detect tab';
  newBtn.textContent = '+';
  newBtn.addEventListener('click', () => openTab('auto-detect'));
  bar.appendChild(newBtn);
}

function highlightSidebar(algoId) {
  document.querySelectorAll('.algo-item').forEach(el => {
    el.classList.toggle('active', el.dataset.algoId === algoId);
  });
}

/* ── WORKSPACE ────────────────────────────────────────────── */
function renderWorkspace() {
  const panel = document.getElementById('tool-panel');
  panel.innerHTML = '';
  updateBreadcrumb();
  if (!State.activeTab) { renderWelcome(panel); return; }
  const tab = State.tabs.find(t => t.id === State.activeTab);
  if (!tab) { renderWelcome(panel); return; }

  if (tab.algoId === 'auto-detect')    renderAutoDetect(panel, tab);
  else if (tab.algoId === 'bruteforce-all') renderBruteForceAll(panel, tab);
  else if (tab.algoId === 'image-scan')     renderImageScan(panel, tab);
  else renderAlgoPanel(panel, tab);
}

function renderWelcome(panel) {
  panel.innerHTML = `
    <div id="welcome-screen">
      <img src="assets/logo.svg" class="logo-big" alt="Umbra">
      <h2>UMBRA // CRYPTO DECODER</h2>
      <p>Select an algorithm from the sidebar or use the smart tools above. Supports ${Object.keys(window.ALGOS).length}+ algorithms — all processing happens in your browser.</p>
      <div class="quick-actions">
        <button class="btn btn-danger btn-sm" onclick="openTab('bruteforce-all')">💥 Brute Force All</button>
        <button class="btn btn-cyan btn-sm" onclick="openTab('image-scan')">🖼️ Image Scan</button>
        <button class="btn btn-primary btn-sm" onclick="openTab('auto-detect')">⚡ Auto-Detect</button>
        <button class="btn btn-ghost btn-sm" onclick="openTab('base64')">Base64</button>
        <button class="btn btn-ghost btn-sm" onclick="openTab('caesar')">Caesar</button>
        <button class="btn btn-ghost btn-sm" onclick="openTab('sha256')">SHA-256</button>
        <button class="btn btn-ghost btn-sm" onclick="openTab('aes-gcm')">AES-GCM</button>
      </div>
    </div>`;
}

/* ── ALGO PANEL ───────────────────────────────────────────── */
function renderAlgoPanel(panel, tab) {
  const algo = window.ALGOS[tab.algoId];
  if (!algo) return;
  const info = algo.info;
  const badge = BADGE_MAP[info.category] || BADGE_MAP.special;
  const isHash = info.category === 'hash';

  // Mode options — FIXED: caesar bruteforce always available
  const modeOptions = isHash ? [] : [
    `<option value="decode" ${tab.mode==='decode'?'selected':''}>Decrypt / Decode</option>`,
    `<option value="encode" ${tab.mode==='encode'?'selected':''}>Encrypt / Encode</option>`,
    tab.algoId === 'caesar' ? `<option value="bruteforce" ${tab.mode==='bruteforce'?'selected':''}>Brute Force (all 26 shifts)</option>` : '',
  ].join('');

  panel.innerHTML = `
    <div class="tool-header">
      <div class="tool-icon">${getSidebarIcon(tab.algoId)}</div>
      <div>
        <div class="tool-title">${info.name} <span class="algo-badge ${badge.cls}" style="font-size:0.5rem;vertical-align:middle;margin-left:6px">${badge.label}</span></div>
        <div class="tool-desc">${info.description}</div>
      </div>
    </div>
    <div class="tool-body">
      ${!isHash ? `
      <div class="options-row">
        <div class="option-group">
          <div class="option-label">MODE</div>
          <select id="mode-select">${modeOptions}</select>
        </div>
        ${info.keyRequired ? `
        <div class="option-group" style="flex:1;min-width:180px">
          <div class="option-label">${info.keyLabel || 'KEY'}</div>
          <input type="${info.keyType==='password'?'password':'text'}" id="key-input"
                 placeholder="${escHtml(info.keyHint||'')}"
                 value="${escHtml(tab.key)}" autocomplete="off">
        </div>` : ''}
      </div>` : `
      <div style="display:flex;align-items:center;gap:8px">
        <span class="text-danger" style="font-size:0.68rem;letter-spacing:2px;color:var(--accent-danger)">⚠ ONE-WAY HASH — CANNOT DECRYPT</span>
      </div>`}

      <div class="io-row">
        <div class="io-block">
          <div class="io-label">INPUT <span></span></div>
          <textarea id="input-area"
            placeholder="${isHash ? 'Enter text to hash...' : (tab.mode==='decode' ? 'Paste ciphertext here...' : 'Enter plaintext...')}"
            spellcheck="false">${escHtml(tab.input)}</textarea>
          <div class="action-row">
            <button class="btn btn-primary btn-sm" id="run-btn">▶ ${isHash ? 'HASH' : tab.mode==='bruteforce' ? 'BRUTE FORCE' : tab.mode==='decode' ? 'DECRYPT' : 'ENCRYPT'}</button>
            <button class="btn btn-ghost btn-sm" id="clear-btn">⌫ CLEAR</button>
            <button class="btn btn-ghost btn-sm" id="paste-btn">📋 PASTE</button>
            <button class="btn btn-ghost btn-sm" id="sample-btn">💡 SAMPLE</button>
          </div>
        </div>
        <div class="io-block">
          <div class="io-label">OUTPUT <span></span></div>
          <div class="output-wrapper">
            <div class="output-area ${tab.status}" id="output-area">${tab.output || '<span style="opacity:0.25">Output will appear here...</span>'}</div>
            <button class="copy-btn" id="copy-btn">COPY</button>
          </div>
          ${tab.status==='success' ? `
          <div class="action-row" style="margin-top:5px">
            <button class="btn btn-ghost btn-sm" id="use-as-input-btn">↩ USE AS INPUT</button>
            <button class="btn btn-ghost btn-sm" id="send-to-bf-btn">💥 BRUTE FORCE THIS</button>
          </div>` : ''}
        </div>
      </div>

      ${tab.algoId==='morse' && tab.status==='success' && tab.mode==='encode' ? renderMorseVisual(tab.input) : ''}

      <div class="result-meta">
        <div class="meta-item"><span class="meta-key">ALGO</span><span class="meta-val">${info.name}</span></div>
        <div class="meta-item"><span class="meta-key">INPUT</span><span class="meta-val">${tab.input.length} chars</span></div>
        <div class="meta-item"><span class="meta-key">OUTPUT</span><span class="meta-val">${stripHtml(tab.output).length} chars</span></div>
        <div class="meta-item"><span class="meta-key">ENTROPY</span><span class="meta-val">${window.AutoDetect.entropy(tab.input).toFixed(3)}</span></div>
        ${tab.status==='success' ? `<div class="meta-item"><span class="meta-key">READABILITY</span><span class="meta-val">${window.Scorer ? window.Scorer.score(stripHtml(tab.output)) : '—'}/100</span></div>` : ''}
      </div>

      <div class="algo-info">
        <h4>ABOUT ${info.name.toUpperCase()}</h4>
        ${info.description}
        ${info.keyRequired ? `<br><br><code>Key format:</code> ${info.keyHint || info.keyLabel}` : ''}
      </div>
    </div>`;

  // Bind events
  const inputArea  = document.getElementById('input-area');
  const modeSelect = document.getElementById('mode-select');
  const keyInput   = document.getElementById('key-input');

  if (modeSelect) {
    modeSelect.addEventListener('change', () => { tab.mode = modeSelect.value; renderWorkspace(); });
  }
  if (keyInput)   keyInput.addEventListener('input', () => { tab.key = keyInput.value; });
  if (inputArea)  inputArea.addEventListener('input', () => { tab.input = inputArea.value; });

  document.getElementById('run-btn').addEventListener('click', () => runAlgo(tab));
  document.getElementById('clear-btn').addEventListener('click', () => { tab.input='';tab.output='';tab.status='idle'; renderWorkspace(); });
  document.getElementById('paste-btn').addEventListener('click', async () => {
    try { tab.input = await navigator.clipboard.readText(); renderWorkspace(); }
    catch { toast('Clipboard denied', 'error'); }
  });
  document.getElementById('sample-btn').addEventListener('click', () => { tab.input = getSample(tab.algoId); renderWorkspace(); });
  document.getElementById('copy-btn').addEventListener('click', () => {
    navigator.clipboard.writeText(stripHtml(tab.output))
      .then(() => toast('Copied!', 'success'))
      .catch(() => toast('Copy failed', 'error'));
  });

  const useBtn = document.getElementById('use-as-input-btn');
  if (useBtn) useBtn.addEventListener('click', () => { tab.input=stripHtml(tab.output);tab.output='';tab.status='idle'; renderWorkspace(); });

  const bfBtn = document.getElementById('send-to-bf-btn');
  if (bfBtn) bfBtn.addEventListener('click', () => {
    const val = stripHtml(tab.output);
    openTabWithInput('bruteforce-all', val);
  });

  if (inputArea) inputArea.addEventListener('keydown', e => { if ((e.ctrlKey||e.metaKey) && e.key==='Enter') runAlgo(tab); });
}

/* ── RUN ALGO ─────────────────────────────────────────────── */
async function runAlgo(tab) {
  const algo = window.ALGOS[tab.algoId];
  if (!algo) return;

  const inputEl = document.getElementById('input-area');
  const keyEl   = document.getElementById('key-input');
  if (inputEl) tab.input = inputEl.value;
  if (keyEl)   tab.key   = keyEl.value;
  if (!tab.input.trim()) { toast('Input is empty', 'error'); return; }

  tab.status = 'loading';
  const outputArea = document.getElementById('output-area');
  if (outputArea) {
    outputArea.className = 'output-area pending';
    outputArea.innerHTML = `<div class="loading-indicator"><div class="loading-dot"></div><div class="loading-dot"></div><div class="loading-dot"></div></div>`;
  }

  try {
    let result;
    if (tab.mode === 'bruteforce' && tab.algoId === 'caesar') {
      // FIX: properly run Caesar brute force
      const results = window.ALGOS.caesar.bruteforce(tab.input);
      result = results.map(r => `[Shift ${String(r.key).padStart(2,'0')}]  ${r.result}`).join('\n');
    } else if (tab.mode === 'encode') {
      result = algo.info.async ? await algo.encode(tab.input, tab.key) : algo.encode(tab.input, tab.key);
    } else {
      result = algo.info.async ? await algo.decode(tab.input, tab.key) : algo.decode(tab.input, tab.key);
    }
    tab.output = escHtml(result);
    tab.status = 'success';
    addHistory(tab);
  } catch (err) {
    tab.output = `ERROR: ${err.message}`;
    tab.status = 'error';
  }
  renderWorkspace();
}

/* ── MORSE VISUAL ─────────────────────────────────────────── */
function renderMorseVisual(text) {
  const TABLE = window.ALGOS.morse.TABLE;
  const chars = text.toUpperCase().slice(0,32).split('').filter(c => TABLE[c]);
  if (!chars.length) return '';
  return `<div class="morse-visual">${chars.map(c => `
    <div class="morse-char">
      <span class="morse-letter">${c}</span>
      <span class="morse-code">${TABLE[c]}</span>
    </div>`).join('')}</div>`;
}

/* ── AUTO-DETECT ──────────────────────────────────────────── */
function renderAutoDetect(panel, tab) {
  const detected = tab.input ? window.AutoDetect.analyze(tab.input) : [];
  const stats    = tab.input ? window.AutoDetect.stats(tab.input) : null;

  panel.innerHTML = `
    <div class="tool-header">
      <div class="tool-icon">⚡</div>
      <div>
        <div class="tool-title">Auto-Detect</div>
        <div class="tool-desc">Paste encoded or encrypted text — Umbra identifies the format automatically.</div>
      </div>
    </div>
    <div class="tool-body">
      <div class="io-block">
        <div class="io-label">INPUT <span></span></div>
        <textarea id="auto-input" placeholder="Paste ciphertext / encoded text here..." spellcheck="false" style="min-height:130px">${escHtml(tab.input)}</textarea>
        <div class="action-row">
          <button class="btn btn-primary btn-sm" id="auto-run-btn">⚡ ANALYZE</button>
          <button class="btn btn-ghost btn-sm" id="auto-paste-btn">📋 PASTE</button>
          <button class="btn btn-ghost btn-sm" id="auto-clear-btn">⌫ CLEAR</button>
          <button class="btn btn-danger btn-sm" id="auto-bf-btn">💥 BRUTE FORCE</button>
        </div>
      </div>
      ${stats ? `
      <div class="analysis-grid">
        <div class="analysis-card"><span class="val">${stats.chars}</span><span class="lbl">CHARS</span></div>
        <div class="analysis-card"><span class="val">${stats.words}</span><span class="lbl">WORDS</span></div>
        <div class="analysis-card"><span class="val">${stats.unique}</span><span class="lbl">UNIQUE</span></div>
        <div class="analysis-card"><span class="val">${stats.entropy}</span><span class="lbl">ENTROPY</span></div>
      </div>` : ''}
      ${detected.length ? `
      <div class="detect-results">
        <div class="detect-title">DETECTED FORMATS — Click to open decoder</div>
        ${detected.map(d => `
          <div class="detect-item" onclick="openTab('${d.id}')">
            <span>${d.name}</span>
            <div class="detect-confidence">
              <span>${d.confidence}%</span>
              <div class="conf-bar"><div class="conf-fill" style="width:${d.confidence}%"></div></div>
            </div>
          </div>`).join('')}
      </div>` : (tab.input ? `<div class="algo-info">No known format detected automatically. Try <strong>Brute Force All</strong> for an exhaustive search.</div>` : '')}
    </div>`;

  const autoInput = document.getElementById('auto-input');
  autoInput.addEventListener('input', () => { tab.input = autoInput.value; });
  document.getElementById('auto-run-btn').addEventListener('click', () => { tab.input = autoInput.value; renderWorkspace(); });
  document.getElementById('auto-clear-btn').addEventListener('click', () => { tab.input=''; renderWorkspace(); });
  document.getElementById('auto-bf-btn').addEventListener('click', () => openTabWithInput('bruteforce-all', autoInput.value || tab.input));
  document.getElementById('auto-paste-btn').addEventListener('click', async () => {
    try { tab.input = await navigator.clipboard.readText(); renderWorkspace(); }
    catch { toast('Clipboard denied','error'); }
  });
  autoInput.addEventListener('keydown', e => { if ((e.ctrlKey||e.metaKey) && e.key==='Enter') { tab.input=autoInput.value; renderWorkspace(); } });
}

/* ── BRUTE FORCE ALL ──────────────────────────────────────── */
function renderBruteForceAll(panel, tab) {
  panel.innerHTML = `
    <div class="tool-header">
      <div class="tool-icon" style="border-color:var(--accent-danger);color:var(--accent-danger)">💥</div>
      <div>
        <div class="tool-title" style="color:var(--accent-danger)">Brute Force All</div>
        <div class="tool-desc">Tries every supported algorithm + common keys and scores results by English readability. No-key algos + Caesar (26 shifts) + Vigenère (common keys) + Affine + Rail Fence + XOR.</div>
      </div>
    </div>
    <div class="tool-body">
      <div class="io-block">
        <div class="io-label">INPUT <span></span></div>
        <textarea id="bf-input" placeholder="Paste the ciphertext to crack..." spellcheck="false" style="min-height:110px">${escHtml(tab.input)}</textarea>
        <div class="action-row">
          <button class="btn btn-danger btn-sm" id="bf-run-btn">💥 RUN BRUTE FORCE</button>
          <button class="btn btn-ghost btn-sm" id="bf-paste-btn">📋 PASTE</button>
          <button class="btn btn-ghost btn-sm" id="bf-clear-btn">⌫ CLEAR</button>
        </div>
      </div>
      <div id="bf-output-area"></div>
    </div>`;

  const bfInput = document.getElementById('bf-input');
  bfInput.addEventListener('input', () => { tab.input = bfInput.value; });
  document.getElementById('bf-clear-btn').addEventListener('click', () => { tab.input=''; tab.bfResults=null; renderWorkspace(); });
  document.getElementById('bf-paste-btn').addEventListener('click', async () => {
    try { tab.input = await navigator.clipboard.readText(); bfInput.value = tab.input; }
    catch { toast('Clipboard denied','error'); }
  });
  document.getElementById('bf-run-btn').addEventListener('click', () => runBruteForce(tab));

  // If we already have results from a previous run, render them
  if (tab.bfResults) renderBFResults(tab.bfResults, document.getElementById('bf-output-area'));
  bfInput.addEventListener('keydown', e => { if ((e.ctrlKey||e.metaKey) && e.key==='Enter') runBruteForce(tab); });
}

async function runBruteForce(tab) {
  const bfInput = document.getElementById('bf-input');
  if (bfInput) tab.input = bfInput.value;
  if (!tab.input.trim()) { toast('Input is empty','error'); return; }

  const outArea = document.getElementById('bf-output-area');
  if (!outArea) return;

  // Show progress UI
  outArea.innerHTML = `
    <div class="bf-header">
      <div class="bf-header-title">CRACKING...</div>
      <div class="bf-header-sub" id="bf-status">Initializing brute force engine...</div>
      <div class="bf-progress"><div class="bf-progress-bar" id="bf-pbar" style="width:0%"></div></div>
    </div>`;

  try {
    const results = await window.BruteForce.run(tab.input, (pct, label) => {
      const pbar = document.getElementById('bf-pbar');
      const stat = document.getElementById('bf-status');
      if (pbar) pbar.style.width = pct + '%';
      if (stat) stat.textContent = `[${pct}%] Testing: ${label}`;
    });

    tab.bfResults = results;
    renderBFResults(results, outArea);
    addHistory(tab);
  } catch (err) {
    outArea.innerHTML = `<div class="algo-info" style="color:var(--accent-danger)">Error: ${err.message}</div>`;
  }
}

function renderBFResults(results, container) {
  if (!results.length) {
    container.innerHTML = `<div class="algo-info">No decodable results found.</div>`;
    return;
  }

  const top = results[0];
  const highResults  = results.filter(r => r.grade === 'high');
  const medResults   = results.filter(r => r.grade === 'medium');
  const lowResults   = results.filter(r => r.grade === 'low').slice(0, 20);

  container.innerHTML = `
    ${top.grade !== 'low' ? `
    <div class="bf-top-match">
      <div class="bf-top-label">⭐ BEST MATCH (Score: ${top.score}/100)</div>
      <div class="bf-top-result">${escHtml(top.result.slice(0,300))}${top.result.length>300?'...':''}</div>
      <div class="bf-top-algo">${top.algoName}${top.keyLabel ? ` · key: ${top.keyLabel}` : ''}</div>
      <div class="action-row" style="margin-top:8px">
        <button class="btn btn-success btn-xs" onclick="openTabWithInputAndResult('${top.algoId}', ${JSON.stringify(escHtml(top.result))})">↗ OPEN IN DECODER</button>
        <button class="btn btn-ghost btn-xs" onclick="navigator.clipboard.writeText(${JSON.stringify(top.result)}).then(()=>toast('Copied!','success'))">COPY RESULT</button>
      </div>
    </div>` : ''}

    ${highResults.length ? `
    <div class="bf-results">
      <div class="bf-section-title">🟢 HIGH CONFIDENCE (${highResults.length})</div>
      ${highResults.map(r => bfEntryHTML(r)).join('')}
    </div>` : ''}

    ${medResults.length ? `
    <div class="bf-results" style="margin-top:8px">
      <div class="bf-section-title">🟡 MEDIUM CONFIDENCE (${medResults.length})</div>
      ${medResults.slice(0,15).map(r => bfEntryHTML(r)).join('')}
    </div>` : ''}

    ${lowResults.length ? `
    <div class="bf-results" style="margin-top:8px">
      <div class="bf-section-title">⚪ LOW CONFIDENCE — showing ${lowResults.length} of ${results.filter(r=>r.grade==='low').length}</div>
      ${lowResults.map(r => bfEntryHTML(r)).join('')}
    </div>` : ''}

    <div class="result-meta" style="margin-top:8px">
      <div class="meta-item"><span class="meta-key">TOTAL TESTS</span><span class="meta-val">${results.length}</span></div>
      <div class="meta-item"><span class="meta-key">HIGH</span><span class="meta-val">${highResults.length}</span></div>
      <div class="meta-item"><span class="meta-key">MEDIUM</span><span class="meta-val">${medResults.length}</span></div>
    </div>`;

  // Bind click handlers to open in decoder
  container.querySelectorAll('.bf-entry').forEach(el => {
    el.addEventListener('click', () => {
      const algoId = el.dataset.algoId;
      const result = el.dataset.result;
      if (algoId && result) openTabWithInputAndResult(algoId, result);
    });
  });
}

function bfEntryHTML(r) {
  const preview = r.result.slice(0, 120).replace(/\n/g, ' ');
  return `
    <div class="bf-entry" data-algo-id="${r.algoId}" data-result="${escHtml(r.result)}" title="Click to open in decoder">
      <div class="bf-algo">${r.algoName}</div>
      <span class="bf-score ${r.grade}">${r.score}</span>
      <div class="bf-result-text ${r.grade==='high'?'likely':''}">${escHtml(preview)}${r.result.length>120?'…':''}</div>
      <div class="bf-meta">${r.keyLabel ? `key: ${r.keyLabel}` : '—'}</div>
    </div>`;
}

function openTabWithInput(algoId, input) {
  const id = `tab-${++State.tabCounter}`;
  const label = SPECIAL_IDS.has(algoId) ? specialName(algoId) : (window.ALGOS[algoId]?.info.name || algoId);
  State.tabs.push({ id, algoId, label, input: input || '', key: '', output: '', mode: 'decode', status: 'idle' });
  renderTabBar();
  activateTab(id);
}

function openTabWithInputAndResult(algoId, result) {
  const algo = window.ALGOS[algoId];
  if (!algo) return;
  const id = `tab-${++State.tabCounter}`;
  State.tabs.push({ id, algoId, label: algo.info.name, input: '', key: '', output: escHtml(result), mode: 'decode', status: 'success' });
  renderTabBar();
  activateTab(id);
}

/* ── IMAGE SCAN ───────────────────────────────────────────── */
function renderImageScan(panel, tab) {
  panel.innerHTML = `
    <div class="tool-header">
      <div class="tool-icon" style="border-color:var(--accent-cyan);color:var(--accent-cyan)">🖼️</div>
      <div>
        <div class="tool-title" style="color:var(--accent-cyan)">Image Scan (OCR)</div>
        <div class="tool-desc">Upload an image containing ciphertext. Umbra extracts the text via OCR, identifies the encoding, and tells you how to decrypt it.</div>
      </div>
    </div>
    <div class="tool-body">
      <div class="img-scan-panel">
        <div class="img-drop-zone" id="drop-zone">
          <input type="file" id="img-file-input" accept="image/*">
          <span class="drop-icon">📂</span>
          <div class="drop-title">DROP IMAGE HERE</div>
          <div class="drop-sub">PNG · JPG · WEBP · BMP · GIF — or click to browse</div>
        </div>
        <div id="img-analysis-output"></div>
      </div>
    </div>`;

  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('img-file-input');

  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file && file.type.startsWith('image/')) processImage(file, tab);
    else toast('Please drop an image file', 'error');
  });

  fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    if (file) processImage(file, tab);
  });

  // Re-render previous results if available
  if (tab.imgResults) renderImageResults(tab.imgResults, document.getElementById('img-analysis-output'));
}

async function processImage(file, tab) {
  const outArea = document.getElementById('img-analysis-output');
  if (!outArea) return;

  // Preview
  const reader = new FileReader();
  reader.onload = async e => {
    const dataUrl = e.target.result;
    outArea.innerHTML = `
      <div class="img-preview-row">
        <div class="img-preview"><img src="${dataUrl}" alt="uploaded image"></div>
        <div>
          <div class="ocr-progress">
            <div class="loading-indicator"><div class="loading-dot"></div><div class="loading-dot"></div><div class="loading-dot"></div></div>
            <div id="ocr-status">Loading OCR engine...</div>
            <div class="ocr-bar"><div class="ocr-bar-fill"></div></div>
          </div>
        </div>
      </div>`;

    try {
      const { rawText, detections, bruteResults } = await window.ImageAnalysis.analyze(
        dataUrl,
        (pct, status) => {
          const el = document.getElementById('ocr-status');
          if (el) el.textContent = `[${pct}%] ${status}`;
        }
      );

      tab.imgResults = { dataUrl, rawText, detections, bruteResults };
      renderImageResults(tab.imgResults, outArea);
    } catch (err) {
      outArea.innerHTML = `
        <div class="img-preview-row">
          <div class="img-preview"><img src="${dataUrl}" alt="uploaded"></div>
          <div class="algo-info" style="color:var(--accent-danger)">OCR Error: ${err.message}<br><br>Make sure the image contains readable text.</div>
        </div>`;
    }
  };
  reader.readAsDataURL(file);
}

function renderImageResults({ dataUrl, rawText, detections, bruteResults }) {
  const outArea = document.getElementById('img-analysis-output');
  if (!outArea) return;

  outArea.innerHTML = `
    <div class="img-preview-row">
      <div class="img-preview"><img src="${dataUrl}" alt="scanned image"></div>
      <div class="img-scan-results">
        <div class="io-label">EXTRACTED TEXT <span></span></div>
        <div class="img-ocr-result">${escHtml(rawText || '(no text detected)')}</div>
        <div class="action-row" style="margin-top:6px">
          <button class="btn btn-ghost btn-sm" onclick="navigator.clipboard.writeText(${JSON.stringify(rawText)}).then(()=>toast('Copied!','success'))">COPY TEXT</button>
          <button class="btn btn-primary btn-sm" onclick="openTabWithInput('auto-detect', ${JSON.stringify(rawText)})">⚡ AUTO-DETECT</button>
          <button class="btn btn-danger btn-sm" onclick="openTabWithInput('bruteforce-all', ${JSON.stringify(rawText)})">💥 BRUTE FORCE</button>
        </div>
      </div>
    </div>

    ${detections.length ? `
    <div class="detect-results" style="margin-top:10px">
      <div class="detect-title">DETECTED FORMATS IN IMAGE TEXT</div>
      ${detections.map(d => `
        <div class="detect-item" onclick="openTab('${d.id}')">
          <span>${d.name}</span>
          <div class="detect-confidence">
            <span>${d.confidence}%</span>
            <div class="conf-bar"><div class="conf-fill" style="width:${d.confidence}%"></div></div>
          </div>
        </div>`).join('')}
    </div>` : ''}

    ${bruteResults.length ? `
    <div style="margin-top:10px">
      <div class="detect-title" style="font-family:var(--font-display);font-size:0.62rem;letter-spacing:3px;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px;border-bottom:1px solid var(--border-color);padding-bottom:6px">DECRYPTION ATTEMPTS</div>
      <div class="img-scan-results">
        ${bruteResults.map(r => `
          <div class="img-result-card" onclick="openTabWithInputAndResult('${r.algoId}', ${JSON.stringify(r.result)})">
            <div class="img-result-algo">${r.algoName} · Score: ${r.score}/100</div>
            <div class="img-result-text">${escHtml(r.result.slice(0,200))}${r.result.length>200?'…':''}</div>
            <div class="img-result-how">💡 ${r.howTo}</div>
          </div>`).join('')}
      </div>
    </div>` : (rawText ? `<div class="algo-info" style="margin-top:10px">No confident decryption found automatically. Try <strong>Brute Force All</strong> with the extracted text.</div>` : '')}`;
}

/* ── HISTORY ──────────────────────────────────────────────── */
function addHistory(tab) {
  const algoName = SPECIAL_IDS.has(tab.algoId) ? specialName(tab.algoId) : (window.ALGOS[tab.algoId]?.info.name || tab.algoId);
  State.history.unshift({ id: Date.now(), algoId: tab.algoId, algoName, inputPreview: tab.input.slice(0,36), ts: new Date().toLocaleTimeString() });
  if (State.history.length > 20) State.history.pop();
  localStorage.setItem('umbra-history', JSON.stringify(State.history));
  renderHistory();
}
function renderHistory() {
  const panel = document.getElementById('history-panel');
  panel.innerHTML = `<span class="history-label">HISTORY</span>`;
  if (!State.history.length) { panel.innerHTML += `<span style="font-size:0.68rem;color:var(--text-muted)">No recent operations</span>`; return; }
  State.history.slice(0,8).forEach(entry => {
    const el = document.createElement('div');
    el.className = 'history-entry';
    el.innerHTML = `<span class="algo-name">${entry.algoName}</span> <span>${escHtml(entry.inputPreview)}</span> <span style="opacity:0.45;font-size:0.6rem">${entry.ts}</span>`;
    el.addEventListener('click', () => openTab(entry.algoId));
    panel.appendChild(el);
  });
}

/* ── BREADCRUMB ───────────────────────────────────────────── */
function updateBreadcrumb() {
  const bc = document.getElementById('breadcrumb');
  if (!bc) return;
  const tab = State.tabs.find(t => t.id === State.activeTab);
  if (!tab) { bc.innerHTML = 'umbra /'; return; }
  const cat = SPECIAL_IDS.has(tab.algoId) ? 'tools' : (window.ALGOS[tab.algoId]?.info?.category || 'tool');
  bc.innerHTML = `umbra / <span>${cat}</span> / ${tab.label}`;
}

/* ── UTILS ────────────────────────────────────────────────── */
function getSidebarIcon(id) {
  for (const g of SIDEBAR_GROUPS) { const item = g.items.find(i => i.id === id); if (item) return item.icon; }
  return '🔐';
}
function escHtml(str) {
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function stripHtml(str) { return String(str||'').replace(/<[^>]+>/g,'').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"'); }

function getSample(algoId) {
  const samples = {
    caesar:'Khoor Zruog', rot13:'Uryyb Jbeyq', rot47:'96==@ (@C=5',
    atbash:'Svool Dliow', vigenere:'Lxfopv Asvph', beaufort:'Rijvs Uyvnd',
    playfair:'BMODZBXDNABEKUDMUIXMMOUVIF', affine:'Czggj Rjmgy',
    railfence:'Hlo ol!el World', columnar:'HELWROOLLOD', substitution:'ITSSG EGPWT',
    base64:'SGVsbG8sIFdvcmxkIQ==', base64url:'SGVsbG8sIFdvcmxkIQ',
    base32:'JBSWY3DPEBLW64TMMQ======', base58:'2NEpo7TZRRrLZSi2U',
    hex:'48656c6c6f2c20576f726c6421', binary:'01001000 01100101 01101100 01101100 01101111',
    octal:'110 145 154 154 157', url:'Hello%2C%20World%21',
    html:'&lt;b&gt;Hello&lt;/b&gt; &amp; World', unicode:'Hel\u006co\u002c World\u0021',
    morse:'.... . .-.. .-.. --- / .-- --- .-. .-.. -..',
    nato:'Hotel Echo Lima Lima Oscar', xor:'2b1b1d1f1d5c2d1f1b1e1d5c',
    sha256:'Hello, World!', sha512:'Hello, World!', sha1:'Hello, World!',
    sha384:'Hello, World!', md5:'Hello, World!', crc32:'Hello, World!',
  };
  return samples[algoId] || 'Hello, World!';
}

/* ── TOAST ────────────────────────────────────────────────── */
function toast(msg, type='info') {
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.innerHTML = `${type==='success'?'✓':type==='error'?'✗':'ℹ'} ${msg}`;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => { el.style.opacity='0'; el.style.transition='opacity 0.3s'; setTimeout(()=>el.remove(),320); }, 2400);
}

/* ── KEYBOARD SHORTCUTS ───────────────────────────────────── */
document.addEventListener('keydown', e => {
  if ((e.ctrlKey||e.metaKey) && e.key==='k') { e.preventDefault(); document.getElementById('algo-search')?.focus(); }
  if ((e.ctrlKey||e.metaKey) && e.key==='t') { e.preventDefault(); openTab('auto-detect'); }
  if ((e.ctrlKey||e.metaKey) && e.key==='w' && State.activeTab) { e.preventDefault(); closeTab(State.activeTab); }
  if (e.key==='Escape') document.getElementById('sidebar')?.classList.remove('open');
});

/* ── MOBILE SIDEBAR ───────────────────────────────────────── */
function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); }

/* ── INIT ─────────────────────────────────────────────────── */
function init() {
  applyTheme(State.theme);
  buildSidebar();
  renderTabBar();
  renderWorkspace();
  renderHistory();

  document.getElementById('theme-toggle')?.addEventListener('click', toggleTheme);
  document.getElementById('hamburger-btn')?.addEventListener('click', toggleSidebar);

  document.addEventListener('click', e => {
    const sb = document.getElementById('sidebar');
    const hb = document.getElementById('hamburger-btn');
    if (sb?.classList.contains('open') && !sb.contains(e.target) && !hb?.contains(e.target)) sb.classList.remove('open');
  });

  // Expose globally for onclick attrs
  window.openTab = openTab;
  window.openTabWithInput = openTabWithInput;
  window.openTabWithInputAndResult = openTabWithInputAndResult;
  window.toast = toast;

  setInterval(updateBreadcrumb, 600);
}

document.addEventListener('DOMContentLoaded', init);
