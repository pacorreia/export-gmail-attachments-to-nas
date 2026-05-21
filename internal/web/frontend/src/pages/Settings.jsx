import { createResource, Switch, Match, Show } from 'solid-js';
import { api } from '../api';
import { useToast } from '../components/Toast';

export default function Settings() {
  const toast = useToast();
  const [settings, { refetch }] = createResource(() => api('/api/settings'));

  async function submitOAuth(e) {
    e.preventDefault();
    const f = e.target;
    const body = {
      google_client_id: f.google_client_id.value,
      google_redirect_url: f.google_redirect_url.value,
    };
    if (f.google_client_secret.value) body.google_client_secret = f.google_client_secret.value;
    try {
      await api('/api/settings', { method: 'PUT', body: JSON.stringify(body) });
      toast.show('OAuth settings saved.', 'success');
      refetch();
    } catch (err) {
      toast.show('Error: ' + err.message, 'error');
    }
  }

  async function submitGeneral(e) {
    e.preventDefault();
    const f = e.target;
    const body = {
      scheduler_interval_minutes: f.scheduler_interval_minutes.value,
      log_retention_days: f.log_retention_days.value,
    };
    try {
      await api('/api/settings', { method: 'PUT', body: JSON.stringify(body) });
      toast.show('Settings saved.', 'success');
    } catch (err) {
      toast.show('Error: ' + err.message, 'error');
    }
  }

  return (
    <div>
      <div class="page-header"><h2>Settings</h2></div>
      <div style="max-width:640px">
      <Switch>
        <Match when={settings.loading}><div class="loading">Loading…</div></Match>
        <Match when={settings.error}><p style="color:red">Error: {settings.error?.message}</p></Match>
        <Match when={settings()}>
          {() => {
            const s = settings();
            const secretSet = s.google_client_secret === '****';
            return (
              <>
                <div class="card">
                  <div style="padding:20px 24px 24px">
                  <h3 style="margin:0 0 16px">Google OAuth</h3>
                  <form onSubmit={submitOAuth}>
                    <div class="form-group">
                      <label>Client ID</label>
                      <input name="google_client_id" value={s.google_client_id || ''} placeholder="paste your Google OAuth Client ID" />
                    </div>
                    <div class="form-group">
                      <label>
                        Client Secret
                        <Show when={secretSet}>
                          {' '}<span class="badge badge-green">configured</span>
                        </Show>
                      </label>
                      <input
                        name="google_client_secret"
                        type="password"
                        placeholder={secretSet ? 'leave blank to keep existing secret' : 'paste your Google OAuth Client Secret'}
                      />
                    </div>
                    <div class="form-group">
                      <label>OAuth Redirect URL</label>
                      <input name="google_redirect_url" value={s.google_redirect_url || ''} placeholder="http://localhost:8080/oauth/callback" />
                    </div>
                    <div style="display:flex;justify-content:flex-end;margin-top:8px">
                      <button type="submit" class="btn btn-primary">Save OAuth Settings</button>
                    </div>
                  </form>
                  </div>
                </div>

                <div class="card">
                  <div style="padding:20px 24px 24px">
                  <h3 style="margin:0 0 16px">General</h3>
                  <form onSubmit={submitGeneral}>
                    <div class="form-group">
                      <label>Database URL <span style="color:var(--md-on-surface-low);font-size:11px">(read-only)</span></label>
                      <input value={s.database_url || ''} readonly style="background:#F4F6FA;color:var(--md-on-surface-med);font-family:monospace;font-size:13px" />
                    </div>
                    <div style="display:flex;gap:24px;flex-wrap:wrap">
                      <div class="form-group" style="flex:0 0 auto">
                        <label>Scheduler interval (minutes)</label>
                        <input name="scheduler_interval_minutes" type="number" min="1" value={s.scheduler_interval_minutes || '60'} style="width:110px" />
                      </div>
                      <div class="form-group" style="flex:0 0 auto">
                        <label>Log retention (days)</label>
                        <input name="log_retention_days" type="number" min="1" value={s.log_retention_days || '90'} style="width:110px" />
                      </div>
                    </div>
                    <div style="display:flex;justify-content:flex-end;margin-top:8px">
                      <button type="submit" class="btn btn-primary">Save Settings</button>
                    </div>
                  </form>
                  </div>
                </div>
              </>
            );
          }}
        </Match>
      </Switch>
      </div>
    </div>
  );
}
