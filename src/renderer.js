/**
 * Aegis ReWrite — Renderer
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
let activeSeverityFilter = null;

// ═══════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════

document.addEventListener('DOMContentLoaded', async () => {
    console.log('[ReWrite] Renderer init');

    // Check AI status
    try {
        const status = await aegis.get('/api/ai/status');
        aiAvailable = status && status.available === true;
        const badge = document.getElementById('ai-badge');
        if (aiAvailable) badge.classList.add('active');
        badge.title = aiAvailable ? 'Ollama AI: Connected' : 'Ollama AI: Not available';
        console.log('[ReWrite] AI available:', aiAvailable);
    } catch (e) {
        console.warn('AI status check failed:', e);
    }

    // Wire folder button
    document.getElementById('select-folder-btn').addEventListener('click', async () => {
        const path = await aegis.selectFolder();
        if (path) {
            currentProjectPath = path;
            const btn = document.getElementById('select-folder-btn');
            const pathEl = document.getElementById('folder-path');
            pathEl.textContent = path;
            btn.classList.add('has-path');
            document.getElementById('scan-btn').disabled = false;
            console.log('[ReWrite] Selected folder:', path);
        }
    });

    // Wire scan button
    document.getElementById('scan-btn').addEventListener('click', runScan);

    // Wire fix actions
    document.getElementById('preview-diff-btn').addEventListener('click', previewDiff);
    document.getElementById('apply-fix-btn').addEventListener('click', applyFix);
    document.getElementById('ignore-btn').addEventListener('click', ignoreFinding);
    document.getElementById('ai-refresh-btn').addEventListener('click', () => {
        if (selectedFinding) loadAIExplanation(selectedFinding);
    });

    // Wire batch actions
    document.getElementById('batch-preview-btn').addEventListener('click', batchPreview);
    document.getElementById('batch-apply-btn').addEventListener('click', batchApply);
    document.getElementById('batch-cancel-btn').addEventListener('click', batchCancel);
});

// ═══════════════════════════════════════════
// SCANNER
// ═══════════════════════════════════════════

async function runScan() {
    if (!currentProjectPath) return;

    const scanBtn = document.getElementById('scan-btn');
    scanBtn.disabled = true;
    scanBtn.classList.add('scanning');
    scanBtn.textContent = '⏳ Scanning...';

    // Reset state
    selectedFinding = null;
    selectedIndex = -1;
    document.getElementById('detail-content').style.display = 'none';
    document.getElementById('detail-placeholder').style.display = 'flex';
    document.getElementById('diff-block').style.display = 'none';
    document.getElementById('fix-status').textContent = '';

    try {
        const result = await aegis.post('/api/scan', { path: currentProjectPath });

        if (result.error) {
            toast(result.error, 'error');
            return;
        }

        currentFindings = result.findings || [];
        console.log('[ReWrite] Scan results:', currentFindings.length, 'findings');

        // Load resolutions
        try {
            const resData = await aegis.get(`/api/resolutions?project_path=${encodeURIComponent(currentProjectPath)}`);
            resolutions = {};
            (resData.resolutions || []).forEach(r => { resolutions[r.finding_hash] = r.status; });
        } catch (e) { /* resolutions unavailable */ }

        // Summary
        const summaryEl = document.getElementById('scan-summary');
        summaryEl.style.display = 'flex';
        summaryEl.innerHTML = `
            <span>${result.files_scanned} files</span>
            <span>${result.scan_time_ms}ms</span>
            ${result.severity_counts.CRITICAL ? `<span style="color:var(--red)">${result.severity_counts.CRITICAL} critical</span>` : ''}
            ${result.severity_counts.HIGH ? `<span style="color:var(--orange)">${result.severity_counts.HIGH} high</span>` : ''}
            ${result.severity_counts.MEDIUM ? `<span style="color:var(--gold)">${result.severity_counts.MEDIUM} medium</span>` : ''}
        `;

        // Update badge
        document.getElementById('findings-count').textContent = currentFindings.length;

        // Render severity filters
        renderSeverityFilters(result.severity_counts);

        // Render findings
        renderFindings();

        // Show batch bar if there are fixable findings
        updateBatchBar();

        toast(`Scan complete: ${currentFindings.length} findings`, currentFindings.length > 0 ? 'info' : 'success');
    } catch (e) {
        toast(`Scan failed: ${e.message}`, 'error');
        console.error('[ReWrite] Scan error:', e);
    } finally {
        scanBtn.disabled = false;
        scanBtn.classList.remove('scanning');
        scanBtn.textContent = '⛨ Scan';
    }
}

// ═══════════════════════════════════════════
// SEVERITY FILTERS
// ═══════════════════════════════════════════

function renderSeverityFilters(counts) {
    const container = document.getElementById('severity-filters');
    container.innerHTML = '';
    const sevs = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    sevs.forEach(sev => {
        if (!counts[sev]) return;
        const btn = document.createElement('button');
        btn.className = 'sev-filter';
        btn.textContent = `${sev} (${counts[sev]})`;
        btn.addEventListener('click', () => {
            if (activeSeverityFilter === sev) {
                activeSeverityFilter = null;
                btn.classList.remove('active');
            } else {
                activeSeverityFilter = sev;
                container.querySelectorAll('.sev-filter').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
            }
            renderFindings();
        });
        container.appendChild(btn);
    });
}

// ═══════════════════════════════════════════
// FINDINGS RENDERER
// ═══════════════════════════════════════════

function renderFindings() {
    const list = document.getElementById('findings-list');
    list.innerHTML = '';

    const filtered = activeSeverityFilter
        ? currentFindings.filter(f => f.severity === activeSeverityFilter)
        : currentFindings;

    if (filtered.length === 0) {
        list.innerHTML = `<div class="empty-state">
            <div class="empty-icon">${currentFindings.length === 0 ? '✅' : '🔍'}</div>
            <p>${currentFindings.length === 0 ? 'No vulnerabilities found!' : 'No findings match this filter'}</p>
        </div>`;
        return;
    }

    filtered.forEach((finding, idx) => {
        const fHash = findingHash(finding);
        const status = resolutions[fHash] || 'OPEN';

        const card = document.createElement('div');
        card.className = `finding-card ${status !== 'OPEN' ? 'resolved' : ''} ${selectedIndex === idx ? 'selected' : ''}`;
        card.dataset.index = idx;

        card.innerHTML = `
            <div class="finding-card-top">
                <div class="sev-dot ${finding.severity}"></div>
                <span class="finding-card-title">${escapeHtml(finding.title)}</span>
                ${status !== 'OPEN' ? `<span class="finding-card-status ${status}">${status}</span>` : ''}
            </div>
            <div class="finding-card-file">${escapeHtml(finding.file)}:${finding.line}</div>
        `;

        card.addEventListener('click', () => {
            console.log('[ReWrite] Clicked finding:', finding.title, finding.file);
            selectFinding(finding, idx);
        });
        list.appendChild(card);
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

    // *** SHOW DETAIL PANEL IMMEDIATELY (before any API calls) ***
    document.getElementById('detail-placeholder').style.display = 'none';
    document.getElementById('detail-content').style.display = 'block';
    document.getElementById('diff-block').style.display = 'none';
    document.getElementById('fix-status').textContent = '';

    // Header — populate immediately from finding data
    const sevEl = document.getElementById('detail-severity');
    sevEl.textContent = finding.severity;
    sevEl.className = `detail-severity ${finding.severity}`;
    document.getElementById('detail-title').textContent = finding.title;
    document.getElementById('detail-meta').textContent = `${finding.file}:${finding.line} • ${finding.category}`;

    // Set initial content while API calls are in flight
    document.getElementById('remediation-text').textContent = finding.detail || 'Loading remediation...';
    document.getElementById('remediation-patch').textContent = '';
    document.getElementById('confidence-badge').textContent = '';
    document.getElementById('code-block').textContent = 'Loading code...';

    // Load remediation (async, non-blocking for UI)
    loadRemediation(finding);

    // Load code preview (async, non-blocking)
    loadCodePreview(finding);

    // Load AI explanation (async, non-blocking)
    if (aiAvailable) {
        loadAIExplanation(finding);
    } else {
        document.getElementById('ai-section').style.display = 'none';
    }
}

async function loadRemediation(finding) {
    try {
        const suggestion = await aegis.post('/api/suggest', finding);
        console.log('[ReWrite] Remediation result:', suggestion);

        if (!suggestion || suggestion.error) {
            document.getElementById('remediation-text').textContent = finding.detail || 'No remediation available.';
            return;
        }

        document.getElementById('remediation-text').textContent = suggestion.suggestion || 'No specific fix available.';
        document.getElementById('remediation-patch').textContent = suggestion.example_patch || '';

        const badge = document.getElementById('confidence-badge');
        if (suggestion.confidence > 0) {
            const level = suggestion.confidence >= 0.85 ? 'high' : suggestion.confidence >= 0.7 ? 'medium' : 'low';
            badge.className = `confidence-badge ${level}`;
            badge.textContent = `${Math.round(suggestion.confidence * 100)}% confidence`;
        } else {
            badge.className = 'confidence-badge';
            badge.textContent = '';
        }

        const docsLink = document.getElementById('docs-link');
        if (suggestion.docs_url) {
            docsLink.href = suggestion.docs_url;
            docsLink.style.display = 'inline';
        } else {
            docsLink.style.display = 'none';
        }
    } catch (e) {
        console.error('[ReWrite] Remediation error:', e);
        document.getElementById('remediation-text').textContent = finding.detail || 'Could not load remediation.';
    }
}

async function loadCodePreview(finding) {
    const filepath = resolvePath(finding.file);
    console.log('[ReWrite] Loading code preview:', filepath);

    try {
        const data = await aegis.post('/api/read_file', { path: filepath });
        console.log('[ReWrite] Code preview result:', data ? 'OK' : 'null', data?.error || '');

        if (!data || data.error) {
            document.getElementById('code-block').textContent = `Error loading file: ${data?.error || 'unknown'}`;
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
            const lineClass = isTarget ? 'style="background:rgba(240,68,68,0.1);color:var(--red)"' : '';
            html += `<span ${lineClass}>${String(lineNum).padStart(4)} │ ${escapeHtml(lines[i])}\n</span>`;
        }

        document.getElementById('code-block').innerHTML = html;
    } catch (e) {
        console.error('[ReWrite] Code preview error:', e);
        document.getElementById('code-block').textContent = `Could not load file: ${e.message}`;
    }
}

async function loadAIExplanation(finding) {
    const aiSection = document.getElementById('ai-section');
    const aiBody = document.getElementById('ai-body');
    aiSection.style.display = 'block';
    aiBody.className = 'ai-body loading';
    aiBody.textContent = 'Generating explanation...';

    try {
        const result = await aegis.post('/api/ai/explain', finding);
        if (result && result.explanation) {
            aiBody.className = 'ai-body';
            aiBody.textContent = result.explanation;
        } else {
            aiSection.style.display = 'none';
        }
    } catch (e) {
        console.error('[ReWrite] AI explain error:', e);
        aiSection.style.display = 'none';
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
        });

        if (!result || result.error) {
            diffEl.innerHTML = `<div class="diff-line-context" style="color:var(--red)">Error: ${result?.error || 'unknown'}</div>`;
            return;
        }

        if (!result.method) {
            diffEl.innerHTML = '<div class="diff-line-context" style="color:var(--orange)">⚠ Could not generate a fix for this finding.</div>';
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
            project_path: currentProjectPath,
        });

        if (result && result.applied) {
            const methodLabel = result.method === 'ai' ? 'AI rewrite' : 'pattern fix';
            statusEl.textContent = `✅ Fixed (${methodLabel}) — backup saved`;
            toast(`Fix applied via ${methodLabel}`, 'success');

            const fHash = findingHash(selectedFinding);
            resolutions[fHash] = 'FIXED';
            renderFindings();
            updateBatchBar();

            // Reload the code preview to show the fixed state
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
    const openFindings = currentFindings.filter(f => {
        const fHash = findingHash(f);
        return (resolutions[fHash] || 'OPEN') === 'OPEN';
    });

    const bar = document.getElementById('batch-bar');
    if (openFindings.length > 1) {
        bar.style.display = 'flex';
        document.getElementById('batch-label').textContent = `${openFindings.length} open findings available for batch fix`;
    } else {
        bar.style.display = 'none';
    }
}

async function batchPreview() {
    const openFindings = currentFindings.filter(f => {
        const fHash = findingHash(f);
        return (resolutions[fHash] || 'OPEN') === 'OPEN';
    });

    toast(`${openFindings.length} findings will be fixed`, 'info');
    document.getElementById('batch-apply-btn').style.display = 'inline-flex';
    document.getElementById('batch-cancel-btn').style.display = 'inline-flex';
}

async function batchApply() {
    const openFindings = currentFindings.filter(f => {
        const fHash = findingHash(f);
        return (resolutions[fHash] || 'OPEN') === 'OPEN';
    });

    try {
        const result = await aegis.post('/api/batch_fix', {
            findings: openFindings,
            project_path: currentProjectPath,
        });

        toast(`Batch complete: ${result.applied} applied, ${result.skipped} skipped`, 'success');

        // Reload resolutions
        const resData = await aegis.get(`/api/resolutions?project_path=${encodeURIComponent(currentProjectPath)}`);
        resolutions = {};
        (resData.resolutions || []).forEach(r => { resolutions[r.finding_hash] = r.status; });

        renderFindings();
        updateBatchBar();
        batchCancel();
    } catch (e) {
        toast(`Batch fix failed: ${e.message}`, 'error');
    }
}

function batchCancel() {
    document.getElementById('batch-apply-btn').style.display = 'none';
    document.getElementById('batch-cancel-btn').style.display = 'none';
}

// ═══════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════

function resolvePath(relPath) {
    // Use OS-appropriate separator
    const sep = navigator.platform.startsWith('Win') ? '\\' : '/';
    const normalized = relPath.replace(/[/\\]/g, sep);
    const base = currentProjectPath.replace(/[/\\]$/, '');
    return base + sep + normalized;
}

function findingHash(finding) {
    const raw = `${currentProjectPath}|${finding.file}|${finding.line}|${finding.category}|${finding.title}`;
    // Simple hash for frontend matching
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
