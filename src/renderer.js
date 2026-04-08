/**
 * Aegis ReWrite — Renderer v3
 * Wired to match index.html element IDs exactly.
 * Single-page scanner UI: select folder → scan → findings → explain → fix
 */

// ═══════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════

let currentProjectPath = null;
let currentFindings = [];
let selectedFinding = null;
let selectedIndex = -1;
let resolutions = {};
let aiAvailable = false;
let activeSeverityFilters = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
let currentBatchReqId = null;
let aiModel = 'qwen2.5:7b';
let selectedForBatch = new Set();
let currentSort = 'severity';

// ═══════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════

document.addEventListener('DOMContentLoaded', async () => {
    console.log('[ReWrite] Renderer v3 init');

    // ── Window controls ──
    document.getElementById('btn-minimize').addEventListener('click', () => aegis.minimize());
    document.getElementById('btn-maximize').addEventListener('click', () => aegis.maximize());
    document.getElementById('btn-close').addEventListener('click', () => aegis.close());

    // ── Build detail panel HTML inside #detail-scroll ──
    buildDetailPanel();

    // ── AI model from settings ──
    const savedModel = localStorage.getItem('aegis-ai-model');
    if (savedModel) {
        aiModel = savedModel;
        const sel = document.getElementById('model-select');
        if (sel) sel.value = aiModel;
    }

    // ── Check AI status ──
    try {
        const status = await aegis.get('/api/ai/status');
        aiAvailable = status && status.available === true;
        const dot = document.getElementById('ai-status-dot');
        if (dot) {
            dot.classList.toggle('online', aiAvailable);
            dot.classList.toggle('offline', !aiAvailable);
            dot.setAttribute('aria-label', aiAvailable ? 'Ollama status: online' : 'Ollama status: offline');
        }
        console.log('[ReWrite] AI available:', aiAvailable);
    } catch (e) {
        console.warn('AI status check failed:', e);
    }

    // ── Browse button ──
    document.getElementById('browse-btn').addEventListener('click', async () => {
        console.log('[ReWrite] Browse clicked');
        const folderPath = await aegis.selectFolder();
        if (folderPath) {
            setProjectPath(folderPath);
        }
    });

    // ── Scan button ──
    document.getElementById('scan-btn').addEventListener('click', runScan);

    // ── Drag & Drop ──
    const overlay = document.getElementById('drag-overlay');
    let dragCounter = 0;

    document.addEventListener('dragenter', (e) => {
        e.preventDefault();
        dragCounter++;
        overlay.classList.add('active');
    });

    document.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dragCounter--;
        if (dragCounter <= 0) {
            dragCounter = 0;
            overlay.classList.remove('active');
        }
    });

    document.addEventListener('dragover', (e) => {
        e.preventDefault();
    });

    document.addEventListener('drop', async (e) => {
        e.preventDefault();
        dragCounter = 0;
        overlay.classList.remove('active');

        const items = e.dataTransfer.items;
        if (items && items.length > 0) {
            for (let i = 0; i < items.length; i++) {
                const entry = items[i].webkitGetAsEntry ? items[i].webkitGetAsEntry() : null;
                if (entry && entry.isDirectory) {
                    // For Electron, the path is on the file object
                    const file = e.dataTransfer.files[i];
                    if (file && file.path) {
                        setProjectPath(file.path);
                        return;
                    }
                }
            }
            // Fallback: try the first file's path
            const file = e.dataTransfer.files[0];
            if (file && file.path) {
                setProjectPath(file.path);
            }
        }
    });

    // ── Severity filter buttons ──
    document.querySelectorAll('#filter-bar .filter-btn[data-sev]').forEach(btn => {
        btn.addEventListener('click', () => {
            const sev = btn.dataset.sev;
            if (activeSeverityFilters.has(sev)) {
                activeSeverityFilters.delete(sev);
                btn.classList.remove('active');
                btn.setAttribute('aria-pressed', 'false');
            } else {
                activeSeverityFilters.add(sev);
                btn.classList.add('active');
                btn.setAttribute('aria-pressed', 'true');
            }
            renderFindings();
        });
    });

    // ── Sort selector ──
    document.getElementById('sort-select').addEventListener('change', (e) => {
        currentSort = e.target.value;
        renderFindings();
    });

    // ── Batch fix ──
    document.getElementById('batch-preview-btn').addEventListener('click', batchPreviewAll);
    document.getElementById('batch-fix-btn').addEventListener('click', batchFixSelected);
    document.getElementById('batch-clear-btn').addEventListener('click', () => {
        selectedForBatch.clear();
        renderFindings();
        updateBatchBar();
    });

    // ── Export ──
    setupExport();

    // ── Settings ──
    setupSettings();

    // ── Resize handle ──
    setupResizeHandle();

    // ── Load last folder ──
    try {
        const lastFolder = await aegis.getLastFolder();
        if (lastFolder) setProjectPath(lastFolder, false);
    } catch (e) { /* no saved folder */ }
});

// ═══════════════════════════════════════════
// SET PROJECT PATH
// ═══════════════════════════════════════════

function setProjectPath(folderPath, save = true) {
    currentProjectPath = folderPath;
    const input = document.getElementById('folder-path-input');
    input.value = folderPath;
    input.title = folderPath;
    document.getElementById('scan-btn').disabled = false;
    if (save) {
        aegis.saveLastFolder(folderPath).catch(() => {});
    }
    console.log('[ReWrite] Project path set:', folderPath);
}

// ═══════════════════════════════════════════
// BUILD DETAIL PANEL (dynamic HTML inside #detail-scroll)
// ═══════════════════════════════════════════

function buildDetailPanel() {
    const scroll = document.getElementById('detail-scroll');
    scroll.innerHTML = `
        <div class="detail-header">
            <span id="detail-severity" class="detail-severity"></span>
            <h2 id="detail-title" class="detail-title"></h2>
            <div id="detail-meta" class="detail-meta"></div>
        </div>

        <div class="remediation-section">
            <div class="section-label">Remediation</div>
            <div id="remediation-text" class="remediation-text"></div>
            <pre id="remediation-patch" class="remediation-patch"></pre>
            <div id="confidence-badge" class="confidence-badge"></div>
            <a id="docs-link" class="docs-link" href="#" target="_blank" rel="noopener" style="display:none">📚 Documentation</a>
        </div>

        <div class="code-section">
            <div class="code-header section-label">
                Source Code
                <button id="open-in-editor-btn" class="small-btn" title="Open in editor">📝 Open</button>
            </div>
            <pre id="code-block" class="code-block"></pre>
        </div>

        <div id="ai-section" class="ai-section">
            <div class="section-label">
                🤖 AI Explanation
                <button id="ai-refresh-btn" class="small-btn" title="Regenerate" style="display:none">↻</button>
            </div>
            <div id="ai-body" class="ai-body" style="display:none"></div>
            <button id="ai-generate-btn" class="ai-load-btn">🤖 Generate AI Explanation</button>
        </div>

        <div id="diff-block" class="diff-block" style="display:none"></div>
        <div id="fix-status" class="fix-status"></div>

        <div class="fix-actions">
            <button id="preview-diff-btn" class="action-btn">👁 Preview Fix</button>
            <button id="apply-fix-btn" class="action-btn primary">⚡ Apply Fix</button>
            <button id="ignore-btn" class="action-btn muted">Skip</button>
        </div>
    `;

    // Wire detail panel buttons
    document.getElementById('preview-diff-btn').addEventListener('click', previewDiff);
    document.getElementById('apply-fix-btn').addEventListener('click', applyFix);
    document.getElementById('ignore-btn').addEventListener('click', ignoreFinding);
    document.getElementById('ai-refresh-btn').addEventListener('click', () => {
        if (selectedFinding) loadAIExplanation(selectedFinding);
    });
    document.getElementById('ai-generate-btn').addEventListener('click', () => {
        if (selectedFinding) loadAIExplanation(selectedFinding);
    });
    document.getElementById('open-in-editor-btn').addEventListener('click', () => {
        if (selectedFinding) {
            const filepath = resolvePath(selectedFinding.file);
            aegis.openInEditor(filepath, selectedFinding.line);
        }
    });
}

// ═══════════════════════════════════════════
// SCANNER
// ═══════════════════════════════════════════

async function runScan() {
    if (!currentProjectPath) return;

    const scanBtn = document.getElementById('scan-btn');
    scanBtn.disabled = true;

    // Show scan badge
    const scanBadge = document.getElementById('scan-badge');
    scanBadge.classList.add('visible');
    document.getElementById('badge-text').textContent = 'Scanning';

    // Reset state
    selectedFinding = null;
    selectedIndex = -1;
    selectedForBatch.clear();
    document.getElementById('detail-empty').style.display = 'flex';
    document.getElementById('detail-scroll').style.display = 'none';

    // Show progress
    const progressEl = document.getElementById('scan-progress');
    const progressFile = document.getElementById('progress-file');
    const progressPct = document.getElementById('progress-pct');
    const progressFill = document.getElementById('progress-fill');
    progressEl.classList.add('visible');
    progressFile.textContent = 'Counting files...';
    progressPct.textContent = '0%';
    progressFill.style.width = '0%';

    // Clear findings
    const findingsList = document.getElementById('findings-list');
    findingsList.innerHTML = '';

    // Start streaming scan
    const url = new URL('http://127.0.0.1:5055/api/scan/stream');
    url.searchParams.append('path', currentProjectPath);

    const eventSource = new EventSource(url.toString());

    eventSource.onmessage = async (event) => {
        try {
            const data = JSON.parse(event.data);

            if (data.type === 'error') {
                eventSource.close();
                throw new Error(data.message);
            }

            if (data.type === 'counting') {
                progressFile.textContent = `Found ${data.total_files.toLocaleString()} files to scan...`;
            }

            if (data.type === 'progress') {
                const percent = Math.min(100, Math.round((data.files_scanned / data.total_files) * 100));
                progressFill.style.width = `${percent}%`;
                progressPct.textContent = `${percent}%`;
                progressFile.textContent = data.current_file || '';
            }

            if (data.type === 'complete') {
                eventSource.close();

                // Hide progress
                progressEl.classList.remove('visible');
                scanBadge.classList.remove('visible');

                const result = data;
                currentFindings = result.findings || [];
                console.log('[ReWrite] Scan complete:', currentFindings.length, 'findings');

                // Load resolutions
                try {
                    const resData = await aegis.get(`/api/resolutions?project_path=${encodeURIComponent(currentProjectPath)}`);
                    resolutions = {};
                    (resData.resolutions || []).forEach(r => { resolutions[r.finding_hash] = r.status; });
                } catch (e) { /* resolutions unavailable */ }

                // Update summary
                const summaryEl = document.getElementById('scan-summary');
                summaryEl.textContent = `${result.files_scanned} files · ${result.scan_time_ms}ms`;

                // Update severity counts
                const counts = result.severity_counts || {};
                document.getElementById('count-critical').textContent = counts.CRITICAL || 0;
                document.getElementById('count-high').textContent = counts.HIGH || 0;
                document.getElementById('count-medium').textContent = counts.MEDIUM || 0;
                document.getElementById('count-low').textContent = counts.LOW || 0;

                // Enable export
                document.getElementById('export-btn').disabled = currentFindings.length === 0;

                // Render
                renderFindings();
                updateBatchBar();

                // Reset button
                scanBtn.disabled = false;

                toast(`Scan complete: ${currentFindings.length} findings`, currentFindings.length > 0 ? 'info' : 'success');
            }
        } catch (e) {
            console.error('[ReWrite] Scan SSE parsing error:', e);
        }
    };

    eventSource.onerror = () => {
        eventSource.close();
        progressEl.classList.remove('visible');
        scanBadge.classList.remove('visible');
        scanBtn.disabled = false;
        toast('Connection to scanner lost.', 'error');
    };
}

// ═══════════════════════════════════════════
// FINDINGS RENDERER
// ═══════════════════════════════════════════

function sortFindings(findings) {
    const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    const sorted = [...findings];

    if (currentSort === 'severity') {
        sorted.sort((a, b) => (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4));
    } else if (currentSort === 'file') {
        sorted.sort((a, b) => a.file.localeCompare(b.file));
    } else if (currentSort === 'category') {
        sorted.sort((a, b) => (a.category || '').localeCompare(b.category || ''));
    }
    return sorted;
}

function renderFindings() {
    const list = document.getElementById('findings-list');
    list.innerHTML = '';

    const filtered = currentFindings.filter(f => activeSeverityFilters.has(f.severity));
    const sorted = sortFindings(filtered);

    if (sorted.length === 0) {
        list.innerHTML = `<li id="empty-state" role="listitem">
            <div style="display:contents">
                <div class="empty-icon" aria-hidden="true">⛨</div>
                <div class="empty-title">${currentFindings.length === 0 ? 'Nothing to scan yet' : 'No findings match this filter'}</div>
                <div class="empty-body">${currentFindings.length === 0 ? 'Select a project folder and click <strong>Scan</strong>.' : 'Try adjusting the severity filters.'}</div>
            </div>
        </li>`;
        return;
    }

    sorted.forEach((finding, idx) => {
        const fHash = findingHash(finding);
        const status = resolutions[fHash] || 'OPEN';
        const isSelected = selectedFinding === finding;
        const isBatchSelected = selectedForBatch.has(fHash);

        const li = document.createElement('li');
        li.className = `finding-card ${status !== 'OPEN' ? 'resolved' : ''} ${isSelected ? 'selected' : ''} ${isBatchSelected ? 'batch-selected' : ''}`;
        li.role = 'listitem';
        li.tabIndex = 0;

        li.innerHTML = `
            <div class="finding-card-top">
                <input type="checkbox" class="batch-check" ${isBatchSelected ? 'checked' : ''} aria-label="Select for batch fix">
                <div class="sev-dot ${finding.severity}"></div>
                <span class="finding-card-title">${escapeHtml(finding.title)}</span>
                ${status !== 'OPEN' ? `<span class="finding-card-status ${status}">${status}</span>` : ''}
            </div>
            <div class="finding-card-file">${escapeHtml(finding.file)}:${finding.line}</div>
        `;

        // Checkbox for batch
        const checkbox = li.querySelector('.batch-check');
        checkbox.addEventListener('click', (e) => {
            e.stopPropagation();
            if (checkbox.checked) {
                selectedForBatch.add(fHash);
            } else {
                selectedForBatch.delete(fHash);
            }
            li.classList.toggle('batch-selected', checkbox.checked);
            updateBatchBar();
        });

        // Click to select finding
        li.addEventListener('click', (e) => {
            if (e.target === checkbox) return;
            selectFinding(finding, idx);
        });

        list.appendChild(li);
    });
}

// ═══════════════════════════════════════════
// FINDING DETAIL VIEW
// ═══════════════════════════════════════════

async function selectFinding(finding, idx) {
    selectedFinding = finding;
    selectedIndex = idx;

    // Highlight in list
    document.querySelectorAll('.finding-card').forEach(c => c.classList.remove('selected'));
    const cards = document.querySelectorAll('.finding-card');
    if (cards[idx]) cards[idx].classList.add('selected');

    // Show detail panel
    document.getElementById('detail-empty').style.display = 'none';
    document.getElementById('detail-scroll').style.display = 'block';
    document.getElementById('diff-block').style.display = 'none';
    document.getElementById('fix-status').textContent = '';

    // Header
    const sevEl = document.getElementById('detail-severity');
    sevEl.textContent = finding.severity;
    sevEl.className = `detail-severity ${finding.severity}`;
    document.getElementById('detail-title').textContent = finding.title;
    document.getElementById('detail-meta').textContent = `${finding.file}:${finding.line} · ${finding.category}`;

    // Initial content
    document.getElementById('remediation-text').textContent = finding.detail || 'Loading remediation...';
    document.getElementById('remediation-patch').textContent = '';
    document.getElementById('confidence-badge').textContent = '';
    document.getElementById('code-block').textContent = 'Loading code...';

    // Async loads
    loadRemediation(finding);
    loadCodePreview(finding);

    // Reset AI section to show Generate button
    const aiBody = document.getElementById('ai-body');
    const aiGenBtn = document.getElementById('ai-generate-btn');
    const aiRefreshBtn = document.getElementById('ai-refresh-btn');
    aiBody.style.display = 'none';
    aiBody.textContent = '';
    aiGenBtn.style.display = 'block';
    aiRefreshBtn.style.display = 'none';

    if (!aiAvailable) {
        aiGenBtn.textContent = '🤖 AI Unavailable (Ollama offline)';
        aiGenBtn.disabled = true;
    } else {
        aiGenBtn.textContent = '🤖 Generate AI Explanation';
        aiGenBtn.disabled = false;
    }
}

async function loadRemediation(finding) {
    try {
        const suggestion = await aegis.post('/api/suggest', finding);
        if (!suggestion || suggestion.error || !suggestion.suggestion) {
            document.getElementById('remediation-text').innerHTML =
                `<span style="font-weight:bold;color:var(--orange);border-left:2px solid var(--orange);padding-left:8px;margin-bottom:8px;display:inline-block">✋ MANUAL REQUIRED</span><br>${escapeHtml(finding.detail || 'No automated rule available.')}`;
        } else {
            document.getElementById('remediation-text').textContent = suggestion.suggestion;
        }

        document.getElementById('remediation-patch').textContent = suggestion?.example_patch || '';

        const badge = document.getElementById('confidence-badge');
        if (suggestion && suggestion.confidence > 0) {
            const level = suggestion.confidence >= 0.85 ? 'high' : suggestion.confidence >= 0.7 ? 'medium' : 'low';
            badge.className = `confidence-badge ${level}`;
            const actionText = suggestion.confidence >= 0.85
                ? '<span style="color:var(--green)">⚡ Auto-fix safe</span>'
                : '<span style="color:var(--orange)">👁 Review first</span>';
            badge.innerHTML = `${Math.round(suggestion.confidence * 100)}% confidence &nbsp;&bull;&nbsp; ${actionText}`;
        } else {
            badge.className = 'confidence-badge';
            badge.innerHTML = `<span style="color:var(--text-muted)">✋ Manual only</span>`;
        }

        const docsLink = document.getElementById('docs-link');
        docsLink.style.display = suggestion?.docs_url ? 'inline' : 'none';
        if (suggestion?.docs_url) docsLink.href = suggestion.docs_url;
    } catch (e) {
        document.getElementById('remediation-text').textContent = finding.detail || 'Could not load remediation.';
    }
}

async function loadCodePreview(finding) {
    const filepath = resolvePath(finding.file);
    try {
        const data = await aegis.post('/api/read_file', { path: filepath, project_path: currentProjectPath });
        if (!data || data.error) {
            document.getElementById('code-block').textContent = `Error: ${data?.error || 'unknown'}`;
            return;
        }

        const lines = data.lines || [];
        const targetLine = finding.line;
        const start = Math.max(0, targetLine - 5);
        const end = Math.min(lines.length, targetLine + 5);

        let html = '';
        for (let i = start; i < end; i++) {
            const lineNum = i + 1;
            const isTarget = lineNum === targetLine;
            const cls = isTarget ? 'style="background:rgba(240,68,68,0.1);color:var(--red)"' : '';
            html += `<span ${cls}>${String(lineNum).padStart(4)} │ ${escapeHtml(lines[i])}\n</span>`;
        }
        document.getElementById('code-block').innerHTML = html;
    } catch (e) {
        document.getElementById('code-block').textContent = `Could not load: ${e.message}`;
    }
}

async function loadAIExplanation(finding) {
    const aiBody = document.getElementById('ai-body');
    const aiGenBtn = document.getElementById('ai-generate-btn');
    const aiRefreshBtn = document.getElementById('ai-refresh-btn');

    // Hide generate button, show body with loading state
    aiGenBtn.style.display = 'none';
    aiBody.style.display = 'block';
    aiBody.className = 'ai-body loading';
    aiBody.textContent = 'Generating explanation...';
    aiRefreshBtn.style.display = 'none';

    try {
        const result = await aegis.post('/api/ai/explain', { ...finding, model: aiModel });
        if (result && result.explanation) {
            aiBody.className = 'ai-body';
            aiBody.textContent = result.explanation;
            aiRefreshBtn.style.display = 'inline-flex';
        } else {
            aiBody.className = 'ai-body';
            aiBody.textContent = 'AI could not generate an explanation for this finding.';
        }
    } catch (e) {
        aiBody.className = 'ai-body';
        aiBody.textContent = 'AI explanation failed — is Ollama running?';
        // Show generate button again so user can retry
        aiGenBtn.style.display = 'block';
        aiGenBtn.textContent = '🤖 Retry AI Explanation';
    }
}

// ═══════════════════════════════════════════
// FIX ACTIONS
// ═══════════════════════════════════════════

async function previewDiff() {
    if (!selectedFinding) return;
    const filepath = resolvePath(selectedFinding.file);

    const diffEl = document.getElementById('diff-block');
    const statusEl = document.getElementById('fix-status');
    diffEl.style.display = 'block';
    diffEl.innerHTML = '<div class="diff-line-context" style="color:var(--gold)">⏳ Generating fix preview...</div>';
    statusEl.textContent = '';

    try {
        const result = await aegis.post('/api/preview', {
            path: filepath,
            finding: selectedFinding,
            model: aiModel,
            project_path: currentProjectPath,
        });

        if (!result || result.error) {
            diffEl.innerHTML = `<div class="diff-line-context" style="color:var(--red)">Error: ${result?.error || 'unknown'}</div>`;
            return;
        }

        if (!result.method) {
            diffEl.innerHTML = `<div class="diff-line-context" style="color:var(--orange)">⚠ ${escapeHtml(result.message || 'Could not generate a fix.')}</div>`;
            return;
        }

        const methodLabel = result.method === 'ai' ? '🤖 AI Rewrite' : '⚡ Pattern Fix';
        statusEl.innerHTML = `<span style="color:var(--text-muted);font-size:11px">Method: ${methodLabel}</span>`;
        diffEl.innerHTML = formatDiff(result.diff);
    } catch (e) {
        diffEl.innerHTML = `<div class="diff-line-context" style="color:var(--red)">Preview failed: ${e.message}</div>`;
    }
}

async function applyFix() {
    if (!selectedFinding) return;
    const filepath = resolvePath(selectedFinding.file);

    const statusEl = document.getElementById('fix-status');
    statusEl.innerHTML = '<span style="color:var(--gold)">⏳ Applying fix...</span>';

    try {
        const result = await aegis.post('/api/fix', {
            path: filepath,
            finding: selectedFinding,
            model: aiModel,
            project_path: currentProjectPath,
        });

        if (result && result.applied) {
            const trustHtml = result.method === 'ai'
                ? '🤖 AI Contextual Rewrite<br>↳ Backup created → .bak'
                : '⚡ Deterministic rule applied<br>↳ Backup created → .bak';
            statusEl.innerHTML = `<span style="color:var(--green);font-weight:bold;">✅ Fixed</span><br><br><span style="color:var(--text-muted);font-size:12px;border-left:2px solid var(--green);padding-left:8px;display:inline-block;line-height:1.4">${trustHtml}</span>`;
            toast(`Fix applied via ${result.method === 'ai' ? 'AI rewrite' : 'pattern fix'}`, 'success');

            const fHash = findingHash(selectedFinding);
            resolutions[fHash] = 'FIXED';
            renderFindings();
            updateBatchBar();
            loadCodePreview(selectedFinding);
        } else {
            statusEl.textContent = '';
            toast(result?.reason || 'Could not fix — try again', 'error');
        }
    } catch (e) {
        statusEl.textContent = '';
        toast(`Fix failed: ${e.message}`, 'error');
    }
}

async function ignoreFinding() {
    if (!selectedFinding) return;
    try {
        await aegis.post('/api/resolution', {
            finding: selectedFinding,
            status: 'IGNORED',
            project_path: currentProjectPath,
        });
        const fHash = findingHash(selectedFinding);
        resolutions[fHash] = 'IGNORED';
        renderFindings();
        updateBatchBar();
        toast('Finding skipped', 'info');
    } catch (e) {
        toast(`Error: ${e.message}`, 'error');
    }
}

// ═══════════════════════════════════════════
// BATCH FIX
// ═══════════════════════════════════════════

function updateBatchBar() {
    const bar = document.getElementById('batch-bar');
    const count = selectedForBatch.size;
    document.getElementById('batch-count').textContent = `${count} selected`;
    bar.classList.toggle('visible', count > 0);
}

function selectAllSafe() {
    // Select all open findings with confidence >= 0.85
    currentFindings.forEach(f => {
        const fHash = findingHash(f);
        if ((resolutions[fHash] || 'OPEN') === 'OPEN') {
            selectedForBatch.add(fHash);
        }
    });
    renderFindings();
    updateBatchBar();
    toast(`Selected ${selectedForBatch.size} findings for batch fix`, 'info');
}

async function batchPreviewAll() {
    if (selectedForBatch.size === 0) {
        toast('No findings selected', 'info');
        return;
    }

    const batchFindings = currentFindings.filter(f => selectedForBatch.has(findingHash(f)));

    // Show progress
    const progressEl = document.getElementById('batch-progress');
    const progressBar = document.getElementById('batch-progress-bar');
    progressEl.style.display = 'block';
    progressBar.style.width = '0%';
    document.getElementById('batch-preview-btn').disabled = true;

    let previews = [];

    for (let i = 0; i < batchFindings.length; i++) {
        const finding = batchFindings[i];
        const filepath = resolvePath(finding.file);

        try {
            const result = await aegis.post('/api/preview', {
                path: filepath,
                finding: finding,
                model: aiModel,
                project_path: currentProjectPath,
            });

            previews.push({
                finding,
                diff: result?.diff || '',
                method: result?.method || null,
                message: result?.message || '',
                error: result?.error || null,
            });
        } catch (e) {
            previews.push({ finding, diff: '', method: null, error: e.message });
        }

        progressBar.style.width = `${Math.round(((i + 1) / batchFindings.length) * 100)}%`;
    }

    progressEl.style.display = 'none';
    document.getElementById('batch-preview-btn').disabled = false;

    // Build preview modal
    let overlay = document.getElementById('batch-preview-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'batch-preview-overlay';
        overlay.style.cssText = `
            position: fixed; inset: 0; z-index: 9999;
            background: rgba(0,0,0,0.85); display: flex;
            align-items: center; justify-content: center;
        `;
        document.body.appendChild(overlay);
    }

    const fixable = previews.filter(p => p.method);
    const unfixable = previews.filter(p => !p.method);

    let html = `
        <div style="background:var(--surface-1);border:1px solid var(--border);border-radius:12px;
                    max-width:900px;width:90%;max-height:85vh;overflow-y:auto;padding:24px;
                    font-family:var(--font-family);color:var(--text-primary);">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
                <h2 style="margin:0;font-size:18px;color:var(--gold);">👁 Batch Preview — ${previews.length} Findings</h2>
                <button id="close-batch-preview" style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;">✕</button>
            </div>
            <div style="margin-bottom:12px;font-size:13px;color:var(--text-muted);">
                ✅ ${fixable.length} fixable &nbsp;|&nbsp; ⚠ ${unfixable.length} no automatic fix
            </div>
    `;

    for (const p of previews) {
        const sev = p.finding.severity || 'LOW';
        const sevColor = sev === 'CRITICAL' ? 'var(--red)' : sev === 'HIGH' ? 'var(--orange)' : sev === 'MEDIUM' ? 'var(--yellow)' : 'var(--text-muted)';
        const methodLabel = p.method === 'ai' ? '🤖 AI' : p.method === 'pattern' ? '⚡ Pattern' : '—';

        html += `
            <div style="border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:10px;background:var(--surface-0);">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                    <span style="font-weight:600;font-size:13px;">${escapeHtml(p.finding.title)}</span>
                    <span style="font-size:11px;color:${sevColor};font-weight:bold;">${sev}</span>
                </div>
                <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;">
                    ${escapeHtml(p.finding.file)}:${p.finding.line} &nbsp;·&nbsp; Method: ${methodLabel}
                </div>
        `;

        if (p.error) {
            html += `<div style="color:var(--red);font-size:12px;">Error: ${escapeHtml(p.error)}</div>`;
        } else if (p.diff) {
            html += `<pre style="background:var(--surface-2);padding:8px;border-radius:6px;font-size:11px;overflow-x:auto;margin:0;max-height:200px;overflow-y:auto;">${formatDiff(p.diff)}</pre>`;
        } else {
            html += `<div style="color:var(--orange);font-size:12px;">⚠ ${escapeHtml(p.message || 'No automatic fix available')}</div>`;
        }

        html += `</div>`;
    }

    html += `
            <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px;">
                <button id="batch-preview-close-btn" class="action-btn" style="padding:8px 16px;">Close</button>
                <button id="batch-preview-apply-btn" class="action-btn primary" style="padding:8px 16px;" ${fixable.length === 0 ? 'disabled' : ''}>
                    ⚡ Apply ${fixable.length} Fixes
                </button>
            </div>
        </div>
    `;

    overlay.innerHTML = html;
    overlay.style.display = 'flex';

    // Wire close buttons
    document.getElementById('close-batch-preview').addEventListener('click', () => overlay.style.display = 'none');
    document.getElementById('batch-preview-close-btn').addEventListener('click', () => overlay.style.display = 'none');
    document.getElementById('batch-preview-apply-btn').addEventListener('click', () => {
        overlay.style.display = 'none';
        batchFixSelected();
    });

    // Click outside to close
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) overlay.style.display = 'none';
    });
}

async function batchFixSelected() {
    if (selectedForBatch.size === 0) {
        toast('No findings selected', 'info');
        return;
    }

    const batchFindings = currentFindings.filter(f => selectedForBatch.has(findingHash(f)));

    // Show progress
    const progressEl = document.getElementById('batch-progress');
    const progressBar = document.getElementById('batch-progress-bar');
    progressEl.style.display = 'block';
    progressBar.style.width = '0%';

    document.getElementById('batch-fix-btn').disabled = true;

    let applied = 0;
    let skipped = 0;

    for (let i = 0; i < batchFindings.length; i++) {
        const finding = batchFindings[i];
        const filepath = resolvePath(finding.file);

        try {
            const result = await aegis.post('/api/fix', {
                path: filepath,
                finding: finding,
                model: aiModel,
                project_path: currentProjectPath,
            });

            if (result && result.applied) {
                applied++;
                const fHash = findingHash(finding);
                resolutions[fHash] = 'FIXED';
            } else {
                skipped++;
            }
        } catch (e) {
            skipped++;
        }

        progressBar.style.width = `${Math.round(((i + 1) / batchFindings.length) * 100)}%`;
    }

    progressEl.style.display = 'none';
    document.getElementById('batch-fix-btn').disabled = false;

    selectedForBatch.clear();
    renderFindings();
    updateBatchBar();

    toast(`Batch complete: ${applied} applied, ${skipped} skipped`, 'success');
}

// ═══════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════

function setupExport() {
    const exportBtn = document.getElementById('export-btn');
    const exportMenu = document.getElementById('export-menu');

    exportBtn.addEventListener('click', () => {
        exportMenu.classList.toggle('open');
    });

    document.addEventListener('click', (e) => {
        if (!exportBtn.contains(e.target) && !exportMenu.contains(e.target)) {
            exportMenu.classList.remove('open');
        }
    });

    exportMenu.querySelectorAll('.export-item').forEach(item => {
        item.addEventListener('click', () => {
            const fmt = item.dataset.fmt;
            exportFindings(fmt);
            exportMenu.classList.remove('open');
        });
    });
}

function exportFindings(format) {
    if (currentFindings.length === 0) return;

    let content, filename, mime;
    if (format === 'json') {
        content = JSON.stringify(currentFindings, null, 2);
        filename = 'aegis-findings.json';
        mime = 'application/json';
    } else {
        const headers = 'severity,category,title,file,line,detail\n';
        const rows = currentFindings.map(f =>
            `"${f.severity}","${f.category}","${(f.title || '').replace(/"/g, '""')}","${f.file}",${f.line},"${(f.detail || '').replace(/"/g, '""')}"`
        ).join('\n');
        content = headers + rows;
        filename = 'aegis-findings.csv';
        mime = 'text/csv';
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    toast(`Exported ${currentFindings.length} findings as ${format.toUpperCase()}`, 'success');
}

// ═══════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════

function setupSettings() {
    const settingsBtn = document.getElementById('settings-btn');
    const modal = document.getElementById('settings-modal');
    const closeBtn = document.getElementById('settings-close');
    const cancelBtn = document.getElementById('settings-cancel-btn');
    const saveBtn = document.getElementById('settings-save-btn');
    const depthSlider = document.getElementById('backup-depth-slider');
    const depthValue = document.getElementById('backup-depth-value');

    settingsBtn.addEventListener('click', async () => {
        modal.classList.add('open');
        // Load saved prefs
        try {
            const pref = await aegis.getEditorPref();
            if (pref) document.getElementById('editor-pref-select').value = pref;
        } catch (e) {}
        const savedDepth = localStorage.getItem('aegis-backup-depth');
        if (savedDepth) {
            depthSlider.value = savedDepth;
            depthValue.textContent = savedDepth;
        }
    });

    depthSlider.addEventListener('input', () => {
        depthValue.textContent = depthSlider.value;
    });

    const closeModal = () => modal.classList.remove('open');
    closeBtn.addEventListener('click', closeModal);
    cancelBtn.addEventListener('click', closeModal);

    saveBtn.addEventListener('click', async () => {
        const editorPref = document.getElementById('editor-pref-select').value;
        const modelPref = document.getElementById('model-select').value;
        const backupDepth = depthSlider.value;

        aiModel = modelPref;
        localStorage.setItem('aegis-ai-model', modelPref);
        localStorage.setItem('aegis-backup-depth', backupDepth);
        await aegis.saveEditorPref(editorPref);

        closeModal();
        toast('Settings saved', 'success');
    });

    // Close on backdrop click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
    });
}

// ═══════════════════════════════════════════
// RESIZE HANDLE
// ═══════════════════════════════════════════

function setupResizeHandle() {
    const handle = document.getElementById('resize-handle');
    const findingsPanel = document.getElementById('findings-panel');
    let isResizing = false;

    handle.addEventListener('mousedown', (e) => {
        isResizing = true;
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;
        const contentArea = document.getElementById('content-area');
        const rect = contentArea.getBoundingClientRect();
        const newWidth = Math.max(250, Math.min(e.clientX - rect.left, rect.width - 300));
        findingsPanel.style.width = `${newWidth}px`;
        findingsPanel.style.flex = 'none';
    });

    document.addEventListener('mouseup', () => {
        if (isResizing) {
            isResizing = false;
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        }
    });
}

// ═══════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════

function resolvePath(relPath) {
    const sep = navigator.platform.startsWith('Win') ? '\\' : '/';
    const normalized = relPath.replace(/[/\\]/g, sep);
    const base = currentProjectPath.replace(/[/\\]$/, '');
    return base + sep + normalized;
}

function findingHash(finding) {
    const raw = `${currentProjectPath}|${finding.file}|${finding.line}|${finding.category}|${finding.title}`;
    let hash = 0;
    for (let i = 0; i < raw.length; i++) {
        const c = raw.charCodeAt(i);
        hash = ((hash << 5) - hash) + c;
        hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(8, '0').slice(0, 16);
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
}

function formatDiff(diffText) {
    if (!diffText) return '<span class="diff-line-context">No changes</span>';
    return diffText.split('\n').map(line => {
        if (line.startsWith('+++') || line.startsWith('---'))
            return `<div class="diff-line-header">${escapeHtml(line)}</div>`;
        if (line.startsWith('+'))
            return `<div class="diff-line-add">${escapeHtml(line)}</div>`;
        if (line.startsWith('-'))
            return `<div class="diff-line-remove">${escapeHtml(line)}</div>`;
        if (line.startsWith('@@'))
            return `<div class="diff-line-header">${escapeHtml(line)}</div>`;
        return `<div class="diff-line-context">${escapeHtml(line)}</div>`;
    }).join('');
}

function toast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => el.remove(), 4000);
}
