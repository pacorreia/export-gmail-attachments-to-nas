/* Gmail Attachment Exporter - SPA */

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (res.status === 204) return null;
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  if (!res.ok) {
    throw new Error((json && json.error) || text || `HTTP ${res.status}`);
  }
  return json;
}

function showToast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

function showModal(html) {
  document.getElementById('modal-box').innerHTML = html;
  document.getElementById('modal-overlay').classList.remove('hidden');
}

function closeModal(e) {
  if (!e || e.target === document.getElementById('modal-overlay')) {
    document.getElementById('modal-overlay').classList.add('hidden');
    document.getElementById('modal-box').innerHTML = '';
  }
}

function navigate(page, ...args) {
  document.querySelectorAll('.sidebar-nav a').forEach(a => a.classList.remove('active'));
  const link = document.querySelector(`.sidebar-nav a[onclick*="'${page}'"]`);
  if (link) link.classList.add('active');

  const content = document.getElementById('main-content');
  content.innerHTML = '<div class="loading">Loading...</div>';

  const pages = {
    accounts: renderAccounts,
    fileshares: renderFileShares,
    rules: renderRules,
    plugins: renderPlugins,
    logs: renderLogs,
    settings: renderSettings,
  };
  if (pages[page]) pages[page](...args);
}

// ─────────────────────────── ACCOUNTS ───────────────────────────

async function renderAccounts() {
  const content = document.getElementById('main-content');
  try {
    const accounts = await api('/api/accounts');
    const rows = (accounts || []).map(a => `
      <tr>
        <td>${esc(a.id)}</td>
        <td>${esc(a.label)}</td>
        <td>${esc(a.email)}</td>
        <td>${a.last_sync_at ? esc(a.last_sync_at) : '<span class="badge badge-gray">Never</span>'}</td>
        <td class="actions">
          <button class="btn btn-danger btn-sm" onclick="deleteAccount(${a.id})">Delete</button>
        </td>
      </tr>`).join('');

    content.innerHTML = `
      <div class="page-header">
        <h2>Accounts</h2>
        <button class="btn btn-primary" onclick="startOAuth()">+ Add Account</button>
      </div>
      <div class="card">
        ${(accounts || []).length === 0
          ? '<div class="empty-state"><div class="empty-state-icon">📭</div><p>No accounts yet. Add a Gmail account to get started.</p></div>'
          : `<table><thead><tr><th>ID</th><th>Label</th><th>Email</th><th>Last Sync</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`}
      </div>`;
  } catch (e) {
    content.innerHTML = `<div class="card"><p style="color:red">Error: ${esc(e.message)}</p></div>`;
  }
}

async function startOAuth() {
  try {
    const { url } = await api('/api/accounts/oauth/start', { method: 'POST', body: '{}' });
    const popup = window.open(url, 'gmail-oauth', 'width=600,height=700');
    showToast('Complete the OAuth flow in the popup window.', 'info');
    const timer = setInterval(() => {
      if (popup.closed) {
        clearInterval(timer);
        showToast('OAuth complete. Refreshing accounts...', 'success');
        renderAccounts();
      }
    }, 800);
  } catch (e) {
    showToast('Failed to start OAuth: ' + e.message, 'error');
  }
}

async function deleteAccount(id) {
  if (!confirm('Delete this account?')) return;
  try {
    await api(`/api/accounts/${id}`, { method: 'DELETE' });
    showToast('Account deleted.', 'success');
    renderAccounts();
  } catch (e) {
    showToast('Error: ' + e.message, 'error');
  }
}

// ─────────────────────────── FILE SHARES ───────────────────────────

async function renderFileShares() {
  const content = document.getElementById('main-content');
  try {
    const fss = await api('/api/fileshares');
    const rows = (fss || []).map(f => {
      const testBadge = f.last_test_at
        ? (f.last_test_ok ? '<span class="badge badge-green">OK</span>' : '<span class="badge badge-red">Failed</span>')
        : '<span class="badge badge-gray">Untested</span>';
      return `<tr>
        <td>${esc(f.id)}</td>
        <td>${esc(f.label)}</td>
        <td>${esc(f.type)}</td>
        <td>${esc(f.host || f.base_path)}</td>
        <td>${testBadge}</td>
        <td class="actions">
          <button class="btn btn-secondary btn-sm" onclick="testFileShare(${f.id})">Test</button>
          <button class="btn btn-danger btn-sm" onclick="deleteFileShare(${f.id})">Delete</button>
        </td>
      </tr>`;
    }).join('');

    content.innerHTML = `
      <div class="page-header">
        <h2>File Shares</h2>
        <button class="btn btn-primary" onclick="showFileShareForm()">+ Add File Share</button>
      </div>
      <div class="card">
        ${(fss || []).length === 0
          ? '<div class="empty-state"><div class="empty-state-icon">📁</div><p>No file shares configured.</p></div>'
          : `<table><thead><tr><th>ID</th><th>Label</th><th>Type</th><th>Host/Path</th><th>Status</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`}
      </div>`;
  } catch (e) {
    content.innerHTML = `<div class="card"><p style="color:red">Error: ${esc(e.message)}</p></div>`;
  }
}

function showFileShareForm() {
  showModal(`
    <div class="modal-title">Add File Share</div>
    <form id="fs-form" onsubmit="submitFileShare(event)">
      <div class="form-group"><label>Label</label><input name="label" required /></div>
      <div class="form-group">
        <label>Type</label>
        <select name="type" onchange="fsTypeChange(this.value)">
          <option value="smb">SMB</option>
          <option value="local">Local</option>
        </select>
      </div>
      <div id="smb-fields">
        <div class="form-group"><label>Host</label><input name="host" /></div>
        <div class="form-group"><label>Share</label><input name="share" /></div>
        <div class="form-group"><label>Username</label><input name="username" /></div>
        <div class="form-group"><label>Password</label><input name="password" type="password" /></div>
      </div>
      <div id="local-fields" style="display:none">
        <div class="form-group"><label>Base Path</label><input name="base_path" /></div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
        <button type="submit" class="btn btn-primary">Save</button>
      </div>
    </form>`);
}

function fsTypeChange(type) {
  document.getElementById('smb-fields').style.display = type === 'smb' ? '' : 'none';
  document.getElementById('local-fields').style.display = type === 'local' ? '' : 'none';
}

async function submitFileShare(e) {
  e.preventDefault();
  const f = e.target;
  const type = f.type.value;
  const body = {
    label: f.label.value,
    type,
    host: type === 'smb' ? f.host.value : '',
    share: type === 'smb' ? f.share.value : '',
    username: type === 'smb' ? f.username.value : '',
    password: type === 'smb' ? f.password.value : '',
    base_path: type === 'local' ? f.base_path.value : '',
  };
  try {
    await api('/api/fileshares', { method: 'POST', body: JSON.stringify(body) });
    closeModal();
    showToast('File share created.', 'success');
    renderFileShares();
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

async function testFileShare(id) {
  try {
    const res = await api(`/api/fileshares/${id}/test`, { method: 'POST', body: '{}' });
    if (res.ok) showToast('Connection test passed!', 'success');
    else showToast('Test failed: ' + res.error, 'error');
    renderFileShares();
  } catch (e) {
    showToast('Error: ' + e.message, 'error');
  }
}

async function deleteFileShare(id) {
  if (!confirm('Delete this file share?')) return;
  try {
    await api(`/api/fileshares/${id}`, { method: 'DELETE' });
    showToast('File share deleted.', 'success');
    renderFileShares();
  } catch (e) {
    showToast('Error: ' + e.message, 'error');
  }
}

// ─────────────────────────── RULES ───────────────────────────

async function renderRules() {
  const content = document.getElementById('main-content');
  try {
    const rules = await api('/api/rules');
    const rows = (rules || []).map(r => `
      <tr>
        <td>${esc(r.id)}</td>
        <td>${esc(r.label)}</td>
        <td><code>${esc(r.gmail_query)}</code></td>
        <td>${r.enabled ? '<span class="badge badge-green">Enabled</span>' : '<span class="badge badge-gray">Disabled</span>'}</td>
        <td>${r.convert_pdf_to_image ? '<span class="badge badge-blue">Yes</span>' : '<span class="badge badge-gray">No</span>'}</td>
        <td class="actions">
          <button class="btn btn-secondary btn-sm" onclick="showRuleForm(${r.id})">Edit</button>
          <button class="btn btn-danger btn-sm" onclick="deleteRule(${r.id})">Delete</button>
        </td>
      </tr>`).join('');

    content.innerHTML = `
      <div class="page-header">
        <h2>Rules</h2>
        <button class="btn btn-primary" onclick="showRuleForm()">+ Add Rule</button>
      </div>
      <div class="card">
        ${(rules || []).length === 0
          ? '<div class="empty-state"><div class="empty-state-icon">📋</div><p>No rules configured.</p></div>'
          : `<table><thead><tr><th>ID</th><th>Label</th><th>Gmail Query</th><th>Status</th><th>PDF→Img</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`}
      </div>`;
  } catch (e) {
    content.innerHTML = `<div class="card"><p style="color:red">Error: ${esc(e.message)}</p></div>`;
  }
}

async function showRuleForm(id) {
  let rule = null;
  let selectedAccountIDs = [];
  let selectedFileShareIDs = [];

  const [accounts, fileshares] = await Promise.all([
    api('/api/accounts'),
    api('/api/fileshares'),
  ]);

  if (id) {
    const [rules, assignments] = await Promise.all([
      api('/api/rules'),
      api(`/api/rules/${id}/assignments`),
    ]);
    rule = (rules || []).find(r => r.id === id);
    selectedAccountIDs = (assignments || []).map(a => a.account_id);
    selectedFileShareIDs = (assignments || []).map(a => a.file_share_id);
  }

  const accountOptions = (accounts || []).map(a =>
    `<option value="${a.id}" ${selectedAccountIDs.includes(a.id) ? 'selected' : ''}>${esc(a.label)}</option>`
  ).join('');

  const fsOptions = (fileshares || []).map(f =>
    `<option value="${f.id}" ${selectedFileShareIDs.includes(f.id) ? 'selected' : ''}>${esc(f.label)}</option>`
  ).join('');

  showModal(`
    <div class="modal-title">${id ? 'Edit' : 'Add'} Rule</div>
    <form id="rule-form" onsubmit="submitRule(event, ${id || 'null'})">
      <div class="form-group"><label>Label</label><input name="label" value="${esc(rule?.label || '')}" required /></div>
      <div class="form-group"><label>Gmail Query</label><input name="gmail_query" value="${esc(rule?.gmail_query || '')}" placeholder="has:attachment newer_than:30d" required /></div>
      <div class="form-group"><label>Subfolder Template</label><input name="subfolder_template" value="${esc(rule?.subfolder_template || '')}" placeholder="{year}/{month}/{sender}" /></div>
      <div class="form-group">
        <div class="form-check">
          <input type="checkbox" name="convert_pdf_to_image" id="cvt" ${rule?.convert_pdf_to_image ? 'checked' : ''} />
          <label for="cvt">Convert PDF to Images</label>
        </div>
      </div>
      <div class="form-group">
        <div class="form-check">
          <input type="checkbox" name="enabled" id="enb" ${(!rule || rule.enabled) ? 'checked' : ''} />
          <label for="enb">Enabled</label>
        </div>
      </div>
      <div class="form-group">
        <label>Accounts (hold Ctrl/Cmd to select multiple)</label>
        <select name="account_ids" multiple style="height:90px">${accountOptions}</select>
      </div>
      <div class="form-group">
        <label>File Shares (hold Ctrl/Cmd to select multiple)</label>
        <select name="file_share_ids" multiple style="height:90px">${fsOptions}</select>
      </div>
      <div class="form-group">
        <button type="button" class="btn btn-secondary btn-sm" onclick="previewQuery()">Preview Query</button>
        <div id="preview-results"></div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
        <button type="submit" class="btn btn-primary">${id ? 'Update' : 'Create'}</button>
      </div>
    </form>`);
}

async function previewQuery() {
  const f = document.getElementById('rule-form');
  const accountSel = f.querySelector('[name="account_ids"]');
  const selected = Array.from(accountSel.selectedOptions);
  if (selected.length === 0) {
    showToast('Select at least one account to preview.', 'error');
    return;
  }
  const accountID = parseInt(selected[0].value);
  const query = f.querySelector('[name="gmail_query"]').value;
  const el = document.getElementById('preview-results');
  el.innerHTML = '<p>Searching...</p>';
  try {
    const results = await api('/api/accounts/preview', {
      method: 'POST',
      body: JSON.stringify({ account_id: accountID, query }),
    });
    if (!results || results.length === 0) {
      el.innerHTML = '<p style="color:#888;margin-top:8px">No messages found.</p>';
      return;
    }
    const rows = results.map(m => `<tr><td>${esc(m.date)}</td><td>${esc(m.sender)}</td><td>${esc(m.subject)}</td></tr>`).join('');
    el.innerHTML = `<div class="preview-table-wrap"><table>
      <thead><tr><th>Date</th><th>Sender</th><th>Subject</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  } catch (e) {
    el.innerHTML = `<p style="color:red;margin-top:8px">Error: ${esc(e.message)}</p>`;
  }
}

async function submitRule(e, id) {
  e.preventDefault();
  const f = e.target;
  const accountIDs = Array.from(f.querySelector('[name="account_ids"]').selectedOptions).map(o => parseInt(o.value));
  const fileShareIDs = Array.from(f.querySelector('[name="file_share_ids"]').selectedOptions).map(o => parseInt(o.value));
  const body = {
    label: f.label.value,
    gmail_query: f.gmail_query.value,
    subfolder_template: f.subfolder_template.value,
    convert_pdf_to_image: f.convert_pdf_to_image.checked,
    enabled: f.enabled.checked,
    account_ids: accountIDs,
    file_share_ids: fileShareIDs,
  };
  try {
    if (id) {
      await api(`/api/rules/${id}`, { method: 'PUT', body: JSON.stringify(body) });
      showToast('Rule updated.', 'success');
    } else {
      await api('/api/rules', { method: 'POST', body: JSON.stringify(body) });
      showToast('Rule created.', 'success');
    }
    closeModal();
    renderRules();
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

async function deleteRule(id) {
  if (!confirm('Delete this rule?')) return;
  try {
    await api(`/api/rules/${id}`, { method: 'DELETE' });
    showToast('Rule deleted.', 'success');
    renderRules();
  } catch (e) {
    showToast('Error: ' + e.message, 'error');
  }
}

// ─────────────────────────── PLUGINS ───────────────────────────

async function renderPlugins() {
  const content = document.getElementById('main-content');
  try {
    const plugins = await api('/api/plugins');
    const rows = (plugins || []).map(p => `
      <tr>
        <td>${esc(p.id)}</td>
        <td>${esc(p.label)}</td>
        <td>${esc(p.type)}</td>
        <td>${p.enabled ? '<span class="badge badge-green">Enabled</span>' : '<span class="badge badge-gray">Disabled</span>'}</td>
        <td class="actions">
          <button class="btn btn-secondary btn-sm" onclick="testPlugin(${p.id})">Test</button>
          <button class="btn btn-secondary btn-sm" onclick="showPluginForm(${p.id})">Edit</button>
          <button class="btn btn-danger btn-sm" onclick="deletePlugin(${p.id})">Delete</button>
        </td>
      </tr>`).join('');

    content.innerHTML = `
      <div class="page-header">
        <h2>Plugins</h2>
        <button class="btn btn-primary" onclick="showPluginForm()">+ Add Plugin</button>
      </div>
      <div class="card">
        ${(plugins || []).length === 0
          ? '<div class="empty-state"><div class="empty-state-icon">🔌</div><p>No plugins configured.</p></div>'
          : `<table><thead><tr><th>ID</th><th>Label</th><th>Type</th><th>Status</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`}
      </div>`;
  } catch (e) {
    content.innerHTML = `<div class="card"><p style="color:red">Error: ${esc(e.message)}</p></div>`;
  }
}

async function showPluginForm(id) {
  let plugin = null;
  let cfg = {};
  if (id) {
    const plugins = await api('/api/plugins');
    plugin = (plugins || []).find(p => p.id === id);
    try { cfg = JSON.parse(plugin?.config_json || '{}'); } catch {}
  }

  const type = plugin?.type || 'webhook';

  showModal(`
    <div class="modal-title">${id ? 'Edit' : 'Add'} Plugin</div>
    <form id="plugin-form" onsubmit="submitPlugin(event, ${id || 'null'})">
      <div class="form-group"><label>Label</label><input name="label" value="${esc(plugin?.label || '')}" required /></div>
      <div class="form-group">
        <label>Type</label>
        <select name="type" onchange="pluginTypeChange(this.value)">
          <option value="webhook" ${type === 'webhook' ? 'selected' : ''}>Webhook</option>
          <option value="subprocess" ${type === 'subprocess' ? 'selected' : ''}>Subprocess</option>
        </select>
      </div>
      <div class="form-group">
        <div class="form-check">
          <input type="checkbox" name="enabled" id="p-enb" ${(!plugin || plugin.enabled) ? 'checked' : ''} />
          <label for="p-enb">Enabled</label>
        </div>
      </div>
      <div id="webhook-fields" style="display:${type === 'webhook' ? '' : 'none'}">
        <div class="form-group"><label>URL</label><input name="wh_url" value="${esc(cfg.url || '')}" /></div>
        <div class="form-group"><label>Secret (HMAC)</label><input name="wh_secret" value="${esc(cfg.secret || '')}" /></div>
        <div class="form-group"><label>Retries</label><input name="wh_retries" type="number" value="${cfg.retries ?? 3}" /></div>
      </div>
      <div id="subprocess-fields" style="display:${type === 'subprocess' ? '' : 'none'}">
        <div class="form-group"><label>Executable</label><input name="sp_exe" value="${esc(cfg.executable || '')}" /></div>
        <div class="form-group"><label>Args (comma-separated)</label><input name="sp_args" value="${esc((cfg.args || []).join(','))}" /></div>
        <div class="form-group"><label>Timeout (sec)</label><input name="sp_timeout" type="number" value="${cfg.timeout_sec ?? 30}" /></div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
        <button type="submit" class="btn btn-primary">${id ? 'Update' : 'Create'}</button>
      </div>
    </form>`);
}

function pluginTypeChange(type) {
  document.getElementById('webhook-fields').style.display = type === 'webhook' ? '' : 'none';
  document.getElementById('subprocess-fields').style.display = type === 'subprocess' ? '' : 'none';
}

async function submitPlugin(e, id) {
  e.preventDefault();
  const f = e.target;
  const type = f.type.value;
  let cfg = {};
  if (type === 'webhook') {
    cfg = { url: f.wh_url.value, secret: f.wh_secret.value, retries: parseInt(f.wh_retries.value) || 3 };
  } else {
    const args = f.sp_args.value ? f.sp_args.value.split(',').map(s => s.trim()).filter(Boolean) : [];
    cfg = { executable: f.sp_exe.value, args, timeout_sec: parseInt(f.sp_timeout.value) || 30 };
  }
  const body = { label: f.label.value, type, enabled: f.enabled.checked, config_json: JSON.stringify(cfg) };
  try {
    if (id) {
      await api(`/api/plugins/${id}`, { method: 'PUT', body: JSON.stringify(body) });
      showToast('Plugin updated.', 'success');
    } else {
      await api('/api/plugins', { method: 'POST', body: JSON.stringify(body) });
      showToast('Plugin created.', 'success');
    }
    closeModal();
    renderPlugins();
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

async function testPlugin(id) {
  try {
    const res = await api(`/api/plugins/${id}/test`, { method: 'POST', body: '{}' });
    if (res.ok) showToast('Plugin test passed!', 'success');
    else showToast('Test failed: ' + res.error, 'error');
  } catch (e) {
    showToast('Error: ' + e.message, 'error');
  }
}

async function deletePlugin(id) {
  if (!confirm('Delete this plugin?')) return;
  try {
    await api(`/api/plugins/${id}`, { method: 'DELETE' });
    showToast('Plugin deleted.', 'success');
    renderPlugins();
  } catch (e) {
    showToast('Error: ' + e.message, 'error');
  }
}

// ─────────────────────────── LOGS ───────────────────────────

async function renderLogs(page = 1) {
  const content = document.getElementById('main-content');

  const [accounts, rules] = await Promise.all([
    api('/api/accounts').catch(() => []),
    api('/api/rules').catch(() => []),
  ]);

  const accountMap = Object.fromEntries((accounts || []).map(a => [a.id, a.label]));
  const ruleMap = Object.fromEntries((rules || []).map(r => [r.id, r.label]));

  const accountOpts = (accounts || []).map(a => `<option value="${a.id}">${esc(a.label)}</option>`).join('');
  const ruleOpts = (rules || []).map(r => `<option value="${r.id}">${esc(r.label)}</option>`).join('');

  content.innerHTML = `
    <div class="page-header"><h2>Run Logs</h2></div>
    <div class="card">
      <div class="filters-bar">
        <select id="f-account" onchange="applyLogFilters()">
          <option value="">All Accounts</option>${accountOpts}
        </select>
        <select id="f-rule" onchange="applyLogFilters()">
          <option value="">All Rules</option>${ruleOpts}
        </select>
        <select id="f-status" onchange="applyLogFilters()">
          <option value="">All Statuses</option>
          <option value="running">Running</option>
          <option value="success">Success</option>
          <option value="error">Error</option>
        </select>
      </div>
      <div id="logs-table-wrap"><div class="loading">Loading...</div></div>
    </div>`;

  await loadLogsTable(page, accountMap, ruleMap);
}

async function applyLogFilters() {
  const accountMap = {};
  const ruleMap = {};
  await loadLogsTable(1, accountMap, ruleMap);
}

async function loadLogsTable(page, accountMap, ruleMap) {
  const accountID = document.getElementById('f-account')?.value || '';
  const ruleID = document.getElementById('f-rule')?.value || '';
  const status = document.getElementById('f-status')?.value || '';

  let url = `/api/logs?page=${page}`;
  if (accountID) url += `&account_id=${accountID}`;
  if (ruleID) url += `&rule_id=${ruleID}`;
  if (status) url += `&status=${status}`;

  const wrap = document.getElementById('logs-table-wrap');
  if (wrap) wrap.innerHTML = '<div class="loading">Loading...</div>';

  try {
    const data = await api(url);
    const items = data.items || [];
    const total = data.total || 0;
    const totalPages = Math.ceil(total / 50) || 1;

    const statusBadge = s => {
      if (s === 'success') return '<span class="badge badge-green">Success</span>';
      if (s === 'error') return '<span class="badge badge-red">Error</span>';
      return '<span class="badge badge-blue">Running</span>';
    };

    const rows = items.map(l => `
      <tr>
        <td>${esc(l.id)}</td>
        <td>${esc(ruleMap[l.rule_id] || l.rule_id)}</td>
        <td>${esc(accountMap[l.account_id] || l.account_id)}</td>
        <td>${esc(l.started_at ? l.started_at.replace('T', ' ').slice(0, 19) : '')}</td>
        <td>${esc(l.finished_at ? l.finished_at.replace('T', ' ').slice(0, 19) : '-')}</td>
        <td>${statusBadge(l.status)}</td>
        <td>${esc(l.message_count)}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(l.error)}">${esc(l.error || '')}</td>
      </tr>`).join('');

    const pagination = `
      <div class="pagination">
        <span>Page ${page} of ${totalPages} (${total} total)</span>
        ${page > 1 ? `<button class="btn btn-secondary btn-sm" onclick="loadLogsTable(${page - 1}, {}, {})">‹ Prev</button>` : ''}
        ${page < totalPages ? `<button class="btn btn-secondary btn-sm" onclick="loadLogsTable(${page + 1}, {}, {})">Next ›</button>` : ''}
      </div>`;

    if (wrap) wrap.innerHTML = items.length === 0
      ? '<div class="empty-state"><div class="empty-state-icon">📝</div><p>No log entries.</p></div>'
      : `<table><thead><tr><th>ID</th><th>Rule</th><th>Account</th><th>Started</th><th>Finished</th><th>Status</th><th>Messages</th><th>Error</th></tr></thead><tbody>${rows}</tbody></table>${pagination}`;
  } catch (e) {
    if (wrap) wrap.innerHTML = `<p style="color:red">Error: ${esc(e.message)}</p>`;
  }
}

// ─────────────────────────── SETTINGS ───────────────────────────

async function renderSettings() {
  const content = document.getElementById('main-content');
  try {
    const settings = await api('/api/settings');
    content.innerHTML = `
      <div class="page-header"><h2>Settings</h2></div>
      <div class="card">
        <form id="settings-form" onsubmit="submitSettings(event)">
          <div class="form-group">
            <label>Database URL <span style="color:#888;font-size:11px">(read-only)</span></label>
            <input value="${esc(settings.database_url || '')}" readonly style="background:#f4f6f9" />
          </div>
          <div class="form-group">
            <label>Scheduler Interval (minutes)</label>
            <input name="scheduler_interval_minutes" type="number" min="1" value="${esc(settings.scheduler_interval_minutes || '60')}" />
          </div>
          <div class="form-group">
            <label>Log Retention (days)</label>
            <input name="log_retention_days" type="number" min="1" value="${esc(settings.log_retention_days || '90')}" />
          </div>
          <div class="modal-footer" style="border:none;padding:0;margin-top:10px">
            <button type="submit" class="btn btn-primary">Save Settings</button>
          </div>
        </form>
      </div>`;
  } catch (e) {
    content.innerHTML = `<div class="card"><p style="color:red">Error: ${esc(e.message)}</p></div>`;
  }
}

async function submitSettings(e) {
  e.preventDefault();
  const f = e.target;
  const body = {
    scheduler_interval_minutes: f.scheduler_interval_minutes.value,
    log_retention_days: f.log_retention_days.value,
  };
  try {
    await api('/api/settings', { method: 'PUT', body: JSON.stringify(body) });
    showToast('Settings saved.', 'success');
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

// ─────────────────────────── INIT ───────────────────────────

document.addEventListener('DOMContentLoaded', () => navigate('accounts'));
