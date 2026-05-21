import { createResource, createSignal, Switch, Match, For, Show } from 'solid-js';
import { api } from '../api';
import { useToast } from '../components/Toast';
import { useModal } from '../components/Modal';

function PluginForm(props) {
  const toast = useToast();
  const modal = useModal();
  const [type, setType] = createSignal(props.plugin?.type || 'webhook');

  let cfg = {};
  if (props.plugin?.config_json) {
    try { cfg = JSON.parse(props.plugin.config_json); } catch {}
  }

  async function handleSubmit(e) {
    e.preventDefault();
    const f = e.target;
    const t = type();
    let config = {};
    if (t === 'webhook') {
      config = { url: f.wh_url.value, secret: f.wh_secret.value, retries: parseInt(f.wh_retries.value) || 3 };
    } else {
      const args = f.sp_args.value ? f.sp_args.value.split(',').map(s => s.trim()).filter(Boolean) : [];
      config = { executable: f.sp_exe.value, args, timeout_sec: parseInt(f.sp_timeout.value) || 30 };
    }
    const body = { label: f.label.value, type: t, enabled: f.enabled.checked, config_json: JSON.stringify(config) };
    try {
      if (props.plugin) {
        await api(`/api/plugins/${props.plugin.id}`, { method: 'PUT', body: JSON.stringify(body) });
        toast.show('Plugin updated.', 'success');
      } else {
        await api('/api/plugins', { method: 'POST', body: JSON.stringify(body) });
        toast.show('Plugin created.', 'success');
      }
      modal.close();
      props.onSave?.();
    } catch (err) {
      toast.show('Error: ' + err.message, 'error');
    }
  }

  const isEdit = !!props.plugin;

  return (
    <div>
      <div class="modal-title">{isEdit ? 'Edit' : 'Add'} Plugin</div>
      <form onSubmit={handleSubmit}>
        <div class="modal-body">
        <div class="form-group">
          <label>Label</label>
          <input name="label" value={props.plugin?.label || ''} required />
        </div>
        <div class="form-group">
          <label>Type</label>
          <select name="type" value={type()} onChange={e => setType(e.target.value)}>
            <option value="webhook">Webhook</option>
            <option value="subprocess">Subprocess</option>
          </select>
        </div>
        <div class="form-group">
          <div class="form-check">
            <input type="checkbox" name="enabled" id="p-enb" checked={!props.plugin || props.plugin.enabled} />
            <label for="p-enb">Enabled</label>
          </div>
        </div>

        <Show when={type() === 'webhook'}>
          <div class="form-group"><label>URL</label><input name="wh_url" value={cfg.url || ''} /></div>
          <div class="form-group"><label>Secret (HMAC)</label><input name="wh_secret" value={cfg.secret || ''} /></div>
          <div class="form-group">
            <label>Retries</label>
            <input name="wh_retries" type="number" min="0" max="10" value={cfg.retries ?? 3} style="width:90px" />
          </div>
        </Show>
        <Show when={type() === 'subprocess'}>
          <div class="form-group"><label>Executable</label><input name="sp_exe" value={cfg.executable || ''} /></div>
          <div class="form-group"><label>Args (comma-separated)</label><input name="sp_args" value={(cfg.args || []).join(',')} /></div>
          <div class="form-group">
            <label>Timeout (sec)</label>
            <input name="sp_timeout" type="number" min="1" value={cfg.timeout_sec ?? 30} style="width:90px" />
          </div>
        </Show>

        </div>{/* end modal-body */}
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" onClick={modal.close}>Cancel</button>
          <button type="submit" class="btn btn-primary">{isEdit ? 'Update' : 'Create'}</button>
        </div>
      </form>
    </div>
  );
}

export default function Plugins() {
  const toast = useToast();
  const modal = useModal();
  const [plugins, { refetch }] = createResource(() => api('/api/plugins'));

  function showForm(plugin) {
    modal.show(() => <PluginForm plugin={plugin || null} onSave={refetch} />);
  }

  async function testPlugin(id) {
    try {
      const res = await api(`/api/plugins/${id}/test`, { method: 'POST', body: '{}' });
      if (res?.ok) toast.show('Plugin test passed!', 'success');
      else toast.show('Test failed: ' + (res?.error || 'unknown error'), 'error');
    } catch (e) {
      toast.show('Error: ' + e.message, 'error');
    }
  }

  async function deletePlugin(id) {
    if (!confirm('Delete this plugin?')) return;
    try {
      await api(`/api/plugins/${id}`, { method: 'DELETE' });
      toast.show('Plugin deleted.', 'success');
      refetch();
    } catch (e) {
      toast.show('Error: ' + e.message, 'error');
    }
  }

  return (
    <div>
      <div class="page-header">
        <h2>Plugins</h2>
        <button class="btn btn-primary" onClick={() => showForm(null)}>+ Add Plugin</button>
      </div>
      <div class="card">
        <Switch>
          <Match when={plugins.loading}><div class="loading">Loading…</div></Match>
          <Match when={plugins.error}><p class="text-error" style="padding:16px">Error: {plugins.error?.message}</p></Match>
          <Match when={(plugins() || []).length === 0}>
            <div class="empty-state">
              <div class="empty-state-icon">🔌</div>
              <p>No plugins configured.</p>
            </div>
          </Match>
          <Match when={plugins()}>
            <table>
              <thead>
                <tr><th>ID</th><th>Label</th><th>Type</th><th>Status</th><th>Actions</th></tr>
              </thead>
              <tbody>
                <For each={plugins()}>
                  {p => (
                    <tr>
                      <td>{p.id}</td>
                      <td>{p.label}</td>
                      <td>
                        {p.type === 'webhook'
                          ? <span class="badge badge-blue">Webhook</span>
                          : <span class="badge badge-orange">Subprocess</span>}
                      </td>
                      <td>{p.enabled
                        ? <span class="badge badge-green">Enabled</span>
                        : <span class="badge badge-gray">Disabled</span>}
                      </td>
                      <td class="actions">
                        <button class="btn btn-secondary btn-sm" onClick={() => testPlugin(p.id)}>Test</button>
                        <button class="btn btn-secondary btn-sm" onClick={() => showForm(p)}>Edit</button>
                        <button class="btn btn-danger btn-sm" onClick={() => deletePlugin(p.id)}>Delete</button>
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
