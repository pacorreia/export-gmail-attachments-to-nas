import { createResource, createSignal, Switch, Match, For, Show } from 'solid-js';
import { api } from '../api';
import { useToast } from '../components/Toast';
import { useModal } from '../components/Modal';

function FileShareForm(props) {
  const toast = useToast();
  const modal = useModal();
  const [type, setType] = createSignal(props.share?.type || 'smb');
  const [testing, setTesting] = createSignal(false);
  let formRef;

  function buildConnBody() {
    const t = type();
    return {
      type: t,
      host:      t === 'smb' ? formRef.host?.value     : '',
      share:     t === 'smb' ? formRef.share?.value    : '',
      username:  t === 'smb' ? formRef.username?.value : '',
      password:  t === 'smb' ? formRef.password?.value : '',
      base_path: t === 'local' ? formRef.base_path?.value : '',
    };
  }

  async function testConnection() {
    setTesting(true);
    try {
      const res = await api('/api/fileshares/test', {
        method: 'POST',
        body: JSON.stringify(buildConnBody()),
      });
      if (res?.ok) toast.show('Connection test passed!', 'success');
      else toast.show('Test failed: ' + (res?.error || 'unknown error'), 'error');
    } catch (e) {
      toast.show('Error: ' + e.message, 'error');
    } finally {
      setTesting(false);
    }
  }

  const isEdit = !!props.share;

  async function handleSubmit(e) {
    e.preventDefault();
    const body = { label: formRef.label.value, ...buildConnBody() };
    try {
      if (isEdit) {
        await api(`/api/fileshares/${props.share.id}`, { method: 'PUT', body: JSON.stringify(body) });
        toast.show('File share updated.', 'success');
      } else {
        await api('/api/fileshares', { method: 'POST', body: JSON.stringify(body) });
        toast.show('File share created.', 'success');
      }
      modal.close();
      props.onSave?.();
    } catch (err) {
      toast.show('Error: ' + err.message, 'error');
    }
  }

  return (
    <div>
      <div class="modal-title">{isEdit ? 'Edit' : 'Add'} File Share</div>
      <form onSubmit={handleSubmit} ref={formRef}>
        <div class="modal-body">
        <div class="form-group">
          <label>Label</label>
          <input name="label" value={props.share?.label || ''} required />
        </div>
        <div class="form-group">
          <label>Type</label>
          <select name="type" value={type()} onChange={e => setType(e.target.value)}>
            <option value="smb">SMB</option>
            <option value="local">Local</option>
          </select>
        </div>
        <Show when={type() === 'smb'}>
          <div class="form-group"><label>Host</label><input name="host" value={props.share?.host || ''} /></div>
          <div class="form-group"><label>Share</label><input name="share" value={props.share?.share || ''} /></div>
          <div class="form-group"><label>Username</label><input name="username" value={props.share?.username || ''} /></div>
          <div class="form-group"><label>Password</label><input name="password" type="password" placeholder={isEdit ? 'leave blank to keep existing' : ''} /></div>
        </Show>
        <Show when={type() === 'local'}>
          <div class="form-group"><label>Base Path</label><input name="base_path" value={props.share?.base_path || ''} /></div>
        </Show>
        </div>{/* end modal-body */}
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" onClick={modal.close}>Cancel</button>
          <button type="button" class="btn btn-secondary" onClick={testConnection} disabled={testing()}>
            {testing() ? 'Testing…' : 'Test Connection'}
          </button>
          <button type="submit" class="btn btn-primary">{isEdit ? 'Update' : 'Save'}</button>
        </div>
      </form>
    </div>
  );
}

export default function FileShares() {
  const toast = useToast();
  const modal = useModal();
  const [fileshares, { refetch }] = createResource(() => api('/api/fileshares'));

  function showForm(share) {
    modal.show(() => <FileShareForm share={share || null} onSave={refetch} />);
  }

  async function testFileShare(id) {
    try {
      const res = await api(`/api/fileshares/${id}/test`, { method: 'POST', body: '{}' });
      if (res?.ok) toast.show('Connection test passed!', 'success');
      else toast.show('Test failed: ' + (res?.error || 'unknown error'), 'error');
      refetch();
    } catch (e) {
      toast.show('Error: ' + e.message, 'error');
    }
  }

  async function deleteFileShare(id) {
    if (!confirm('Delete this file share?')) return;
    try {
      await api(`/api/fileshares/${id}`, { method: 'DELETE' });
      toast.show('File share deleted.', 'success');
      refetch();
    } catch (e) {
      toast.show('Error: ' + e.message, 'error');
    }
  }

  return (
    <div>
      <div class="page-header">
        <h2>File Shares</h2>
        <button class="btn btn-primary" onClick={() => showForm(null)}>+ Add File Share</button>
      </div>
      <div class="card">
        <Switch>
          <Match when={fileshares.loading}><div class="loading">Loading…</div></Match>
          <Match when={fileshares.error}><p class="text-error" style="padding:16px">Error: {fileshares.error?.message}</p></Match>
          <Match when={(fileshares() || []).length === 0}>
            <div class="empty-state">
              <div class="empty-state-icon">📁</div>
              <p>No file shares configured.</p>
            </div>
          </Match>
          <Match when={fileshares()}>
            <table>
              <thead>
                <tr><th>ID</th><th>Label</th><th>Type</th><th>Host / Path</th><th>Status</th><th>Actions</th></tr>
              </thead>
              <tbody>
                <For each={fileshares()}>
                  {f => {
                    const badge = f.last_test_at
                      ? (f.last_test_ok
                        ? <span class="badge badge-green">OK</span>
                        : <span class="badge badge-red">Failed</span>)
                      : <span class="badge badge-gray">Untested</span>;
                    return (
                      <tr>
                        <td>{f.id}</td>
                        <td>{f.label}</td>
                        <td>
                          {f.type === 'smb'
                            ? <span class="badge badge-blue">SMB</span>
                            : <span class="badge badge-purple">Local</span>}
                        </td>
                        <td class="text-mono">{f.host || f.base_path || <span class="text-muted">—</span>}</td>
                        <td>{badge}</td>
                        <td class="actions">
                          <button class="btn btn-secondary btn-sm" onClick={() => testFileShare(f.id)}>Test</button>
                          <button class="btn btn-secondary btn-sm" onClick={() => showForm(f)}>Edit</button>
                          <button class="btn btn-danger btn-sm" onClick={() => deleteFileShare(f.id)}>Delete</button>
                        </td>
                      </tr>
                    );
                  }}
                </For>
              </tbody>
            </table>
          </Match>
        </Switch>
      </div>
    </div>
  );
}
