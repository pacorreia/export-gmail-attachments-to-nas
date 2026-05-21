import { createResource, createSignal, createEffect, createMemo, Switch, Match, For, Show } from 'solid-js';
import { api } from '../api';
import { useToast } from '../components/Toast';
import { useModal } from '../components/Modal';
import QueryBuilder, { buildQuery, parseQuery, validateQuery } from '../components/QueryBuilder';
import RecurrencePicker from '../components/RecurrencePicker';

const DAY_NAMES = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
function pad(n) { return String(n).padStart(2,'0'); }

function scheduleHumanLabel(s) {
  if (!s) return 'Global default';
  if (!s.startsWith('{')) {
    const m = s.match(/^(\d+)([smhd])$/);
    if (!m) return s;
    const num = m[1], u = { s:'s', m:'min', h:'h', d:'d' }[m[2]];
    return `Every ${num}${u}`;
  }
  try {
    const r = JSON.parse(s);
    switch (r.type) {
      case 'interval': {
        const m2 = (r.interval || '').match(/^(\d+)([smhd])$/);
        if (!m2) return r.interval || '?';
        const u = { s:'s', m:'min', h:'h', d:'d' }[m2[2]];
        return `Every ${m2[1]}${u}`;
      }
      case 'daily':    return `Daily at ${pad(r.hour)}:${pad(r.minute)}`;
      case 'weekly':   return `Weekly on ${(r.days||[]).map(d=>DAY_NAMES[d]).join('/')} at ${pad(r.hour)}:${pad(r.minute)}`;
      case 'monthly':  return `Monthly day ${r.day_of_month} at ${pad(r.hour)}:${pad(r.minute)}`;
      case 'once':     return `Once on ${(r.once_at||'').replace('T',' ')}`;
      default: return s;
    }
  } catch { return s; }
}

function RuleForm(props) {
  const toast = useToast();
  const modal = useModal();
  const [query, setQuery] = createSignal(props.rule?.gmail_query || '');
  const queryWarnings = createMemo(() => validateQuery(query()));
  const [preview, setPreview] = createSignal(null);
  const [previewing, setPreviewing] = createSignal(false);
  let accountRef, fsRef;

  // Schedule and delete-after-export state
  const [schedule, setSchedule] = createSignal(props.rule?.schedule || '');
  const [deleteAfterExport, setDeleteAfterExport] = createSignal(props.rule?.delete_after_export || false);

  async function handleSubmit(e) {
    e.preventDefault();
    const f = e.target;
    const accountIDs = Array.from(accountRef.selectedOptions).map(o => parseInt(o.value));
    const fsIDs = Array.from(fsRef.selectedOptions).map(o => parseInt(o.value));
    const body = {
      label: f.label.value,
      gmail_query: query(),
      subfolder_template: f.subfolder_template.value,
      convert_pdf_to_image: f.convert_pdf_to_image.checked,
      enabled: f.enabled.checked,
      schedule: schedule(),
      delete_after_export: deleteAfterExport(),
      account_ids: accountIDs,
      file_share_ids: fsIDs,
    };
    try {
      if (props.rule) {
        await api(`/api/rules/${props.rule.id}`, { method: 'PUT', body: JSON.stringify(body) });
        toast.show('Rule updated.', 'success');
      } else {
        await api('/api/rules', { method: 'POST', body: JSON.stringify(body) });
        toast.show('Rule created.', 'success');
      }
      modal.close();
      props.onSave?.();
    } catch (err) {
      toast.show('Error: ' + err.message, 'error');
    }
  }

  async function previewQuery() {
    const selected = Array.from(accountRef.selectedOptions);
    if (selected.length === 0) {
      toast.show('Select at least one account to preview.', 'error');
      return;
    }
    setPreviewing(true);
    setPreview(null);
    try {
      const results = await api('/api/accounts/preview', {
        method: 'POST',
        body: JSON.stringify({ account_id: parseInt(selected[0].value), query: query() }),
      });
      setPreview(results || []);
    } catch (e) {
      toast.show('Preview error: ' + e.message, 'error');
    } finally {
      setPreviewing(false);
    }
  }

  const isEdit = !!props.rule;

  return (
    <div>
      <div class="modal-title">{isEdit ? 'Edit' : 'Add'} Rule</div>
      <form onSubmit={handleSubmit}>
        <div class="modal-body">
        <div class="form-group">
          <label>Label</label>
          <input name="label" value={props.rule?.label || ''} required />
        </div>

        <div class="form-group">
          <label>Gmail Query</label>
          <QueryBuilder value={query()} onChange={setQuery} />
          <div class="qb-raw-wrap" style="margin-top:6px">
            <span class="qb-raw-label">Generated query</span>
            <input
              value={query()}
              onInput={e => setQuery(e.target.value)}
              placeholder="has:attachment newer_than:30d"
              required
            />
          </div>
          <Show when={queryWarnings().length > 0}>
            <ul class="qb-warnings">
              <For each={queryWarnings()}>{w => <li>{w.message}</li>}</For>
            </ul>
          </Show>
        </div>

        <div class="form-group">
          <label>Subfolder Template</label>
          <input name="subfolder_template" value={props.rule?.subfolder_template || ''} placeholder="{year}/{month}/{sender}" />
        </div>

        <div class="form-group">
          <div class="form-check">
            <input type="checkbox" name="convert_pdf_to_image" id="cvt" checked={props.rule?.convert_pdf_to_image} />
            <label for="cvt">Convert PDF to Images</label>
          </div>
        </div>

        <div class="form-group">
          <div class="form-check">
            <input type="checkbox" name="enabled" id="enb" checked={!props.rule || props.rule.enabled} />
            <label for="enb">Enabled</label>
          </div>
        </div>

        <div class="form-group">
          <label>Schedule</label>
          <RecurrencePicker value={schedule()} onChange={setSchedule} />
        </div>

        <div class="form-group">
          <div class="form-check">
            <input type="checkbox" name="delete_after_export" id="dae"
              checked={deleteAfterExport()}
              onChange={e => setDeleteAfterExport(e.target.checked)} />
            <label for="dae">Delete email after successful export</label>
          </div>
        </div>

        <div class="form-group">
          <label>Accounts (hold Ctrl/Cmd to select multiple)</label>
          <select name="account_ids" multiple style="height:90px" ref={accountRef}>
            <For each={props.accounts}>
              {a => (
                <option
                  value={a.id}
                  selected={props.selectedAccountIDs?.includes(a.id)}
                >{a.label}</option>
              )}
            </For>
          </select>
        </div>

        <div class="form-group">
          <label>File Shares (hold Ctrl/Cmd to select multiple)</label>
          <select name="file_share_ids" multiple style="height:90px" ref={fsRef}>
            <For each={props.fileshares}>
              {f => (
                <option
                  value={f.id}
                  selected={props.selectedFileShareIDs?.includes(f.id)}
                >{f.label}</option>
              )}
            </For>
          </select>
        </div>

        <div class="form-group">
          <button type="button" class="btn btn-secondary btn-sm" onClick={previewQuery}>Preview Query</button>
          <Show when={previewing()}>
            <p style="margin-top:8px;color:#888">Searching…</p>
          </Show>
          <Show when={preview() !== null && !previewing()}>
            <Show
              when={preview().length > 0}
              fallback={<p style="color:#888;margin-top:8px">No messages found.</p>}
            >
              <div class="preview-table-wrap">
                <table>
                  <thead><tr><th>Date</th><th>Sender</th><th>Subject</th></tr></thead>
                  <tbody>
                    <For each={preview()}>
                      {m => <tr><td>{m.date}</td><td>{m.sender}</td><td>{m.subject}</td></tr>}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </Show>
        </div>

        </div>{/* end modal-body */}
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" onClick={modal.close}>Cancel</button>
          <button type="submit" class="btn btn-primary">{isEdit ? 'Update' : 'Create'}</button>
        </div>
      </form>
    </div>
  );
}

export default function Rules() {
  const toast = useToast();
  const modal = useModal();
  const [rules, { refetch }] = createResource(() => api('/api/rules'));

  const [selected, setSelected] = createSignal(new Set());
  let selectAllRef;
  createEffect(() => {
    const n = selected().size;
    const total = (rules() || []).length;
    if (selectAllRef) selectAllRef.indeterminate = n > 0 && n < total;
  });

  function toggleSelect(id) {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    const all = rules() || [];
    setSelected(selected().size === all.length && all.length > 0 ? new Set() : new Set(all.map(r => r.id)));
  }

  async function runSelected() {
    const ids = [...selected()];
    await Promise.all(ids.map(id => api(`/api/rules/${id}/execute`, { method: 'POST' }).catch(() => {})));
    toast.show(`Started ${ids.length} rule(s).`, 'success');
  }

  async function enableSelected() {
    const toEnable = (rules() || []).filter(r => selected().has(r.id) && !r.enabled);
    await Promise.all(toEnable.map(r => api(`/api/rules/${r.id}/toggle`, { method: 'PATCH' }).catch(() => {})));
    setSelected(new Set());
    refetch();
    if (toEnable.length) toast.show(`Enabled ${toEnable.length} rule(s).`, 'success');
  }

  async function disableSelected() {
    const toDisable = (rules() || []).filter(r => selected().has(r.id) && r.enabled);
    await Promise.all(toDisable.map(r => api(`/api/rules/${r.id}/toggle`, { method: 'PATCH' }).catch(() => {})));
    setSelected(new Set());
    refetch();
    if (toDisable.length) toast.show(`Disabled ${toDisable.length} rule(s).`, 'success');
  }

  async function showForm(rule) {
    try {
      const [accounts, fileshares, assignments] = await Promise.all([
        api('/api/accounts'),
        api('/api/fileshares'),
        rule ? api(`/api/rules/${rule.id}/assignments`) : Promise.resolve([]),
      ]);
      const selectedAccountIDs = (assignments || []).map(a => a.account_id);
      const selectedFileShareIDs = (assignments || []).map(a => a.file_share_id);
      modal.show(() => (
        <RuleForm
          rule={rule || null}
          accounts={accounts || []}
          fileshares={fileshares || []}
          selectedAccountIDs={selectedAccountIDs}
          selectedFileShareIDs={selectedFileShareIDs}
          onSave={refetch}
        />
      ));
    } catch (err) {
      toast.show('Failed to open rule form: ' + err.message, 'error');
    }
  }

  async function executeRule(id) {
    try {
      await api(`/api/rules/${id}/execute`, { method: 'POST' });
      toast.show('Rule execution started.', 'success');
    } catch (e) {
      toast.show('Error: ' + e.message, 'error');
    }
  }

  async function toggleRule(id) {
    try {
      await api(`/api/rules/${id}/toggle`, { method: 'PATCH' });
      refetch();
    } catch (e) {
      toast.show('Error: ' + e.message, 'error');
    }
  }

  async function resetCheckpoint(id) {
    if (!confirm('Reset checkpoint? The next run will re-process all matching emails.')) return;
    try {
      await api(`/api/rules/${id}/checkpoint`, { method: 'DELETE' });
      toast.show('Checkpoint reset. Next run will re-process all matching emails.', 'success');
    } catch (e) {
      toast.show('Error: ' + e.message, 'error');
    }
  }

  async function deleteRule(id) {
    if (!confirm('Delete this rule?')) return;
    try {
      await api(`/api/rules/${id}`, { method: 'DELETE' });
      toast.show('Rule deleted.', 'success');
      refetch();
    } catch (e) {
      toast.show('Error: ' + e.message, 'error');
    }
  }

  return (
    <div>
      <div class="page-header">
        <h2>Rules</h2>
        <button class="btn btn-primary" onClick={() => showForm(null)}>+ Add Rule</button>
      </div>
      <div class="card">
        <div class="bulk-actions-bar">
          <span class="text-muted">{selected().size > 0 ? `${selected().size} selected` : 'No selection'}</span>
          <button class="btn btn-secondary btn-sm" onClick={runSelected} disabled={selected().size === 0}>Run now</button>
          <button class="btn btn-secondary btn-sm" onClick={enableSelected} disabled={selected().size === 0}>Enable</button>
          <button class="btn btn-secondary btn-sm" onClick={disableSelected} disabled={selected().size === 0}>Disable</button>
        </div>
        <Switch>
          <Match when={rules.loading}><div class="loading">Loading…</div></Match>
          <Match when={rules.error}><p class="text-error" style="padding:16px">Error: {rules.error?.message}</p></Match>
          <Match when={(rules() || []).length === 0}>
            <div class="empty-state">
              <div class="empty-state-icon">📋</div>
              <p>No rules configured.</p>
            </div>
          </Match>
          <Match when={rules()}>
            <table>
              <thead>
                <tr>
                  <th style="width:36px">
                    <input type="checkbox" ref={selectAllRef}
                      checked={selected().size > 0 && selected().size === (rules() || []).length}
                      onChange={toggleSelectAll} />
                  </th>
                  <th>ID</th><th>Label</th><th>Gmail Query</th><th>Schedule</th><th>Status</th><th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <For each={rules()}>
                  {r => (
                    <tr class={selected().has(r.id) ? 'row-selected' : ''}>
                      <td><input type="checkbox" checked={selected().has(r.id)} onChange={() => toggleSelect(r.id)} /></td>
                      <td>{r.id}</td>
                      <td>{r.label}</td>
                      <td class="cell-overflow"><code title={r.gmail_query}>{r.gmail_query}</code></td>
              <td class="text-muted" style="font-size:13px">{scheduleHumanLabel(r.schedule)}</td>
                      <td>
                        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
                          <span
                            class={`badge ${r.enabled ? 'badge-green' : 'badge-gray'}`}
                            style="cursor:pointer;user-select:none"
                            onClick={() => toggleRule(r.id)}
                            title={r.enabled ? 'Click to disable' : 'Click to enable'}
                          >
                            {r.enabled ? 'Enabled' : 'Disabled'}
                          </span>
                          {r.convert_pdf_to_image && <span class="badge badge-orange">PDF→Img</span>}
                          {r.delete_after_export && <span class="badge badge-red">Deletes email</span>}
                        </div>
                      </td>
                      <td class="actions">
                        <button class="btn btn-secondary btn-sm" onClick={() => executeRule(r.id)}>Run now</button>
                        <button class="btn btn-secondary btn-sm" onClick={() => resetCheckpoint(r.id)} title="Reset sync checkpoint">Reset checkpoint</button>
                        <button class="btn btn-secondary btn-sm" onClick={() => showForm(r)}>Edit</button>
                        <button class="btn btn-danger btn-sm" onClick={() => deleteRule(r.id)}>Delete</button>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </Match>
        </Switch>
      </div>
    </div>
  );
}
