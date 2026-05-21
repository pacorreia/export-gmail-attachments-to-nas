import { createResource, createSignal, createEffect, onCleanup, Switch, Match, For, Show } from 'solid-js';
import { api } from '../api';
import { useToast } from '../components/Toast';

function fmtDate(iso) {
  if (!iso) return '';
  return iso.replace('T', ' ').slice(0, 16);
}

function statusBadge(s) {
  if (s === 'success') return <span class="badge badge-green">Success</span>;
  if (s === 'error')   return <span class="badge badge-red">Error</span>;
  return <span class="badge badge-blue">Running</span>;
}

export default function Logs() {
  const toast = useToast();
  const [page, setPage] = createSignal(1);
  const [accountFilter, setAccountFilter] = createSignal('');
  const [ruleFilter, setRuleFilter] = createSignal('');
  const [statusFilter, setStatusFilter] = createSignal('');
  const [autoRefresh, setAutoRefresh] = createSignal(false);
  const [refreshInterval, setRefreshInterval] = createSignal(15);
  const [perPage, setPerPage] = createSignal(25);
  const [tick, setTick] = createSignal(0);

  createEffect(() => {
    if (!autoRefresh()) return;
    const ms = refreshInterval() * 1000;
    const id = setInterval(() => setTick(t => t + 1), ms);
    onCleanup(() => clearInterval(id));
  });

  const [meta] = createResource(() => Promise.all([
    api('/api/accounts').catch(() => []),
    api('/api/rules').catch(() => []),
  ]));

  const [logs] = createResource(
    () => ({ page: page(), account: accountFilter(), rule: ruleFilter(), status: statusFilter(), tick: tick(), limit: perPage() }),
    async ({ page: p, account, rule, status, limit }) => {
      let url = `/api/logs?page=${p}&limit=${limit}`;
      if (account) url += `&account_id=${account}`;
      if (rule) url += `&rule_id=${rule}`;
      if (status) url += `&status=${status}`;
      return api(url);
    }
  );

  const accounts = () => (meta() ? meta()[0] : []) || [];
  const rules = () => (meta() ? meta()[1] : []) || [];
  const accountMap = () => Object.fromEntries(accounts().map(a => [a.id, a.label]));
  const ruleMap = () => Object.fromEntries(rules().map(r => [r.id, r.label]));

  const items = () => logs()?.items || [];
  const total = () => logs()?.total || 0;
  const totalPages = () => Math.max(1, Math.ceil(total() / perPage()));

  // Build list of page buttons: { t:'page', n } | { t:'gap', target }
  function pageList() {
    const tot = totalPages();
    const cur = page();
    if (tot <= 1) return [];
    // 4-page window; keep current in position 2
    let ws = Math.max(1, cur - 1);
    let we = Math.min(tot, ws + 3);
    ws = Math.max(1, we - 3);
    const out = [];
    if (ws > 1) {
      out.push({ t: 'page', n: 1 });
      if (ws > 2) out.push({ t: 'gap', target: Math.max(2, ws - 3) });
    }
    for (let i = ws; i <= we; i++) out.push({ t: 'page', n: i });
    if (we < tot) {
      if (we < tot - 1) out.push({ t: 'gap', target: Math.min(tot - 1, we + 3) });
      out.push({ t: 'page', n: tot });
    }
    return out;
  }

  return (
    <div>
      <div class="page-header">
        <h2>Run Logs</h2>
        <div style="display:flex;gap:8px;align-items:center">
          <button class="btn btn-secondary btn-sm" onClick={() => setTick(t => t + 1)}>Refresh</button>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer;font-size:14px">
            <input type="checkbox" checked={autoRefresh()} onChange={e => setAutoRefresh(e.target.checked)} />
            Auto-refresh
          </label>
          <select
            style="font-size:13px"
            disabled={!autoRefresh()}
            value={refreshInterval()}
            onChange={e => setRefreshInterval(Number(e.target.value))}
          >
            <option value={5}>5s</option>
            <option value={10}>10s</option>
            <option value={15}>15s</option>
            <option value={30}>30s</option>
            <option value={60}>1m</option>
          </select>
        </div>
      </div>
      <div class="card">
        <div class="filters-bar">
          <select value={accountFilter()} onChange={e => { setAccountFilter(e.target.value); setPage(1); }}>
            <option value="">All Accounts</option>
            <For each={accounts()}>{a => <option value={a.id}>{a.label}</option>}</For>
          </select>
          <select value={ruleFilter()} onChange={e => { setRuleFilter(e.target.value); setPage(1); }}>
            <option value="">All Rules</option>
            <For each={rules()}>{r => <option value={r.id}>{r.label}</option>}</For>
          </select>
          <select value={statusFilter()} onChange={e => { setStatusFilter(e.target.value); setPage(1); }}>
            <option value="">All Statuses</option>
            <option value="running">Running</option>
            <option value="success">Success</option>
            <option value="error">Error</option>
          </select>
          <select value={perPage()} onChange={e => { setPerPage(Number(e.target.value)); setPage(1); }}>
            <option value={10}>10 / page</option>
            <option value={25}>25 / page</option>
            <option value={50}>50 / page</option>
            <option value={100}>100 / page</option>
          </select>
        </div>

        <Switch>
          <Match when={logs.loading}><div class="loading">Loading…</div></Match>
          <Match when={logs.error}><p class="text-error" style="padding:16px">Error: {logs.error?.message}</p></Match>
          <Match when={items().length === 0}>
            <div class="empty-state">
              <div class="empty-state-icon">📝</div>
              <p>No log entries.</p>
            </div>
          </Match>
          <Match when={logs()}>
            <table>
              <thead>
                <tr>
                  <th>ID</th><th>Rule</th><th>Account</th><th>Started</th>
                  <th>Finished</th><th>Status</th><th>Messages</th><th>Error</th>
                </tr>
              </thead>
              <tbody>
                <For each={items()}>
                  {l => (
                    <tr>
                      <td>{l.id}</td>
                      <td>{ruleMap()[l.rule_id] || l.rule_id}</td>
                      <td>{accountMap()[l.account_id] || l.account_id}</td>
                      <td class="text-muted" style="font-size:13px">{fmtDate(l.started_at)}</td>
                      <td class="text-muted" style="font-size:13px">{fmtDate(l.finished_at) || <span class="text-muted">—</span>}</td>
                      <td>{statusBadge(l.status)}</td>
                      <td>{l.message_count}</td>
                      <td class="cell-overflow" title={l.error}>
                        {l.error ? <span class="text-error">{l.error}</span> : <span class="text-muted">—</span>}
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
            <div class="pagination">
              <button class="btn btn-secondary btn-sm" onClick={() => setPage(p => p - 1)} disabled={page() <= 1}>‹ Prev</button>
              <For each={pageList()}>
                {item => item.t === 'page'
                  ? <button
                      class={`btn btn-sm ${page() === item.n ? 'btn-primary' : 'btn-secondary'}`}
                      style="min-width:32px"
                      onClick={() => setPage(item.n)}
                    >{item.n}</button>
                  : <button class="btn btn-secondary btn-sm" style="min-width:32px" onClick={() => setPage(item.target)}>…</button>
                }
              </For>
              <span class="text-muted" style="font-size:12px">{total()} total</span>
              <button class="btn btn-secondary btn-sm" onClick={() => setPage(p => p + 1)} disabled={page() >= totalPages()}>Next ›</button>
            </div>
          </Match>
        </Switch>
      </div>
    </div>
  );
}
