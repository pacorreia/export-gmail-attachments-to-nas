import { createResource, Switch, Match, For } from 'solid-js';
import { api } from '../api';
import { useToast } from '../components/Toast';

function fmtDate(iso) {
  if (!iso) return null;
  return iso.replace('T', ' ').slice(0, 16);
}

export default function Accounts() {
  const toast = useToast();
  const [accounts, { refetch }] = createResource(() => api('/api/accounts'));

  async function startOAuth() {
    try {
      const { url } = await api('/api/accounts/oauth/start', { method: 'POST', body: '{}' });
      const popup = window.open(url, 'gmail-oauth', 'width=600,height=700');
      toast.show('Complete the OAuth flow in the popup window.', 'info');
      const timer = setInterval(() => {
        if (popup.closed) {
          clearInterval(timer);
          toast.show('OAuth complete. Refreshing accounts...', 'success');
          refetch();
        }
      }, 800);
    } catch (e) {
      toast.show('Failed to start OAuth: ' + e.message, 'error');
    }
  }

  async function deleteAccount(id) {
    if (!confirm('Delete this account?')) return;
    try {
      await api(`/api/accounts/${id}`, { method: 'DELETE' });
      toast.show('Account deleted.', 'success');
      refetch();
    } catch (e) {
      toast.show('Error: ' + e.message, 'error');
    }
  }

  return (
    <div>
      <div class="page-header">
        <h2>Accounts</h2>
        <button class="btn btn-primary" onClick={startOAuth}>+ Add Account</button>
      </div>
      <div class="card">
        <Switch>
          <Match when={accounts.loading}><div class="loading">Loading…</div></Match>
          <Match when={accounts.error}><p class="text-error" style="padding:16px">Error: {accounts.error?.message}</p></Match>
          <Match when={(accounts() || []).length === 0}>
            <div class="empty-state">
              <div class="empty-state-icon">📭</div>
              <p>No accounts yet. Add a Gmail account to get started.</p>
            </div>
          </Match>
          <Match when={accounts()}>
            <table>
              <thead>
                <tr><th>ID</th><th>Label / Email</th><th>Last Sync</th><th>Actions</th></tr>
              </thead>
              <tbody>
                <For each={accounts()}>
                  {a => (
                    <tr>
                      <td>{a.id}</td>
                      <td>
                        <div style="font-weight:500">{a.label}</div>
                        <div class="text-muted" style="font-size:12px">{a.email}</div>
                      </td>
                      <td>{fmtDate(a.last_sync_at) || <span class="badge badge-gray">Never</span>}</td>
                      <td class="actions">
                        <button class="btn btn-danger btn-sm" onClick={() => deleteAccount(a.id)}>Delete</button>
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
