import { createSignal, For, Show } from 'solid-js';
import { createStore } from 'solid-js/store';

export const QB_TYPES = [
  { id: 'has_attachment', label: 'Has Attachment',   op: 'has:attachment', noValue: true },
  { id: 'from',           label: 'From',              op: 'from:',          placeholder: 'sender@example.com' },
  { id: 'to',             label: 'To',                op: 'to:',            placeholder: 'recipient@example.com' },
  { id: 'subject',        label: 'Subject contains',  op: 'subject:',       placeholder: 'Invoice' },
  { id: 'filename',       label: 'Attachment name',   op: 'filename:',      placeholder: '*.pdf' },
  { id: 'newer_than',     label: 'Newer than',        op: 'newer_than:',    placeholder: '30d · 6m · 1y' },
  { id: 'older_than',     label: 'Older than',        op: 'older_than:',    placeholder: '30d · 6m · 1y' },
  { id: 'label',          label: 'Has label',         op: 'label:',         placeholder: 'label-name' },
  { id: 'is_unread',      label: 'Is unread',         op: 'is:unread',      noValue: true },
  { id: 'larger',         label: 'Larger than',       op: 'larger:',        placeholder: '5M · 1024K' },
  { id: 'smaller',        label: 'Smaller than',      op: 'smaller:',       placeholder: '5M · 1024K' },
  { id: 'custom',         label: 'Custom …',          op: '',               placeholder: 'any:query token' },
];

export function buildQuery(conditions) {
  const parts = [];
  for (let i = 0; i < conditions.length; i++) {
    const c = conditions[i];
    const def = QB_TYPES.find(t => t.id === c.type);
    if (!def) continue;
    let token;
    if (def.id === 'custom') {
      token = c.value.trim();
      if (!token) continue;
    } else if (def.noValue) {
      token = def.op;
    } else {
      if (!c.value.trim()) continue;
      const v = c.value.trim();
      token = def.op + (v.includes(' ') ? `"${v}"` : v);
    }
    if (c.negate) token = '-' + token;
    if (parts.length > 0) parts.push(c.join === 'OR' ? 'OR' : '');
    parts.push(token);
  }
  return parts.filter(p => p !== '').join(' ');
}

// Known Gmail operators used for query validation
const KNOWN_OPS = [
  { prefix: 'has:',         values: /^(attachment|drive|document|spreadsheet|presentation|youtube|image|video)$/i, hint: 'attachment · drive · document · image · etc.' },
  { prefix: 'is:',          values: /^(read|unread|starred|snoozed|important|chat)$/i,                           hint: 'read · unread · starred · important · etc.' },
  { prefix: 'newer_than:',  values: /^\d+[dmy]$/i,                                                               hint: 'number + d/m/y  (e.g. 30d, 6m, 1y)' },
  { prefix: 'older_than:',  values: /^\d+[dmy]$/i,                                                               hint: 'number + d/m/y  (e.g. 30d, 6m, 1y)' },
  { prefix: 'after:',       values: /^\d{4}\/\d{1,2}\/\d{1,2}$|^\d+$/,                                          hint: 'YYYY/MM/DD or Unix timestamp' },
  { prefix: 'before:',      values: /^\d{4}\/\d{1,2}\/\d{1,2}$|^\d+$/,                                          hint: 'YYYY/MM/DD or Unix timestamp' },
  { prefix: 'larger:',      values: /^\d+[KMGkmg]?$/,                                                            hint: 'bytes or with K/M suffix  (e.g. 1024, 5M)' },
  { prefix: 'smaller:',     values: /^\d+[KMGkmg]?$/,                                                            hint: 'bytes or with K/M suffix  (e.g. 1024, 5M)' },
  { prefix: 'size:',        values: /^\d+[KMGkmg]?$/,                                                            hint: 'bytes or with K/M suffix  (e.g. 1024, 5M)' },
  { prefix: 'from:',        values: null },
  { prefix: 'to:',          values: null },
  { prefix: 'cc:',          values: null },
  { prefix: 'bcc:',         values: null },
  { prefix: 'subject:',     values: null },
  { prefix: 'label:',       values: null },
  { prefix: 'filename:',    values: null },
  { prefix: 'in:',          values: null },
  { prefix: 'deliveredto:', values: null },
  { prefix: 'category:',    values: null },
  { prefix: 'rfc822msgid:', values: null },
];

/**
 * Validate a raw Gmail query string.
 * Returns an array of { token, message } warning objects.
 */
export function validateQuery(raw) {
  if (!raw || !raw.trim()) return [];
  const tokens = raw.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
  const warnings = [];
  for (const t of tokens) {
    const upper = t.toUpperCase();
    if (upper === 'OR' || upper === 'AND' || upper === 'NOT') continue;
    const bare = t.startsWith('-') ? t.slice(1) : t;
    if (!bare.includes(':')) continue; // bare text search — always valid
    const low = bare.toLowerCase();
    const matched = KNOWN_OPS.find(o => low.startsWith(o.prefix));
    if (!matched) {
      const opPart = bare.slice(0, bare.indexOf(':') + 1);
      warnings.push({ token: bare, message: `Unknown Gmail operator "${opPart}"` });
      continue;
    }
    if (matched.values) {
      const val = bare.slice(matched.prefix.length).replace(/^"(.*)"$/, '$1');
      if (!matched.values.test(val)) {
        warnings.push({ token: bare, message: `"${bare}" — expected format: ${matched.hint}` });
      }
    }
  }
  return warnings;
}

export function parseQuery(query) {
  if (!query) return [];
  const tokens = query.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
  const conditions = [];
  let nextJoin = 'AND';
  for (const t of tokens) {
    if (t.toUpperCase() === 'OR') { nextJoin = 'OR'; continue; }
    const negate = t.startsWith('-');
    const token = negate ? t.slice(1) : t;
    let matched = false;
    for (const def of QB_TYPES) {
      if (def.id === 'custom') continue;
      if (def.noValue && token === def.op) {
        conditions.push({ type: def.id, value: '', negate, join: nextJoin });
        matched = true; break;
      }
      if (!def.noValue && token.startsWith(def.op)) {
        let val = token.slice(def.op.length);
        if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
        conditions.push({ type: def.id, value: val, negate, join: nextJoin });
        matched = true; break;
      }
    }
    if (!matched) conditions.push({ type: 'custom', value: token, negate, join: nextJoin });
    nextJoin = 'AND';
  }
  return conditions;
}

/**
 * QueryBuilder — visual Gmail query builder.
 * Props:
 *   value: string       — initial raw query string
 *   onChange: (q) => void — called whenever the built query changes
 */
export default function QueryBuilder(props) {
  const initial = parseQuery(props.value || '');
  const [conditions, setConditions] = createStore(
    initial.length > 0 ? initial : [{ type: 'has_attachment', value: '', negate: false, join: 'AND' }]
  );

  function notify(updated) {
    props.onChange?.(buildQuery(updated ?? conditions));
  }

  function addCondition() {
    setConditions(cs => [...cs, { type: 'has_attachment', value: '', negate: false, join: 'AND' }]);
    notify();
  }

  function removeCondition(idx) {
    setConditions(cs => cs.filter((_, i) => i !== idx));
    notify();
  }

  function changeType(idx, type) {
    setConditions(idx, { type, value: '', negate: conditions[idx].negate, join: conditions[idx].join });
    notify();
  }

  function changeValue(idx, value) {
    setConditions(idx, 'value', value);
    notify();
  }

  function toggleNegate(idx, checked) {
    setConditions(idx, 'negate', checked);
    notify();
  }

  function changeJoin(idx, join) {
    setConditions(idx, 'join', join);
    notify();
  }

  return (
    <div class="qb-builder">
      <For each={conditions}>
        {(c, i) => {
          const def = () => QB_TYPES.find(t => t.id === c.type);
          return (
            <>
              <Show when={i() > 0}>
                <div class="qb-join">
                  <button
                    type="button"
                    classList={{ 'qb-join-btn': true, active: c.join !== 'OR' }}
                    onClick={() => changeJoin(i(), 'AND')}
                  >AND</button>
                  <button
                    type="button"
                    classList={{ 'qb-join-btn': true, active: c.join === 'OR' }}
                    onClick={() => changeJoin(i(), 'OR')}
                  >OR</button>
                </div>
              </Show>
              <div class="qb-row">
                <select
                  class="qb-type"
                  value={c.type}
                  onChange={e => changeType(i(), e.target.value)}
                >
                  <For each={QB_TYPES}>
                    {t => <option value={t.id}>{t.label}</option>}
                  </For>
                </select>

                <Show
                  when={!def()?.noValue}
                  fallback={<span class="qb-no-value" />}
                >
                  <input
                    class="qb-value"
                    type="text"
                    value={c.value}
                    placeholder={def()?.placeholder || ''}
                    onInput={e => changeValue(i(), e.target.value)}
                  />
                </Show>

                <label class="qb-negate-label" title="Exclude / NOT this condition">
                  <input
                    type="checkbox"
                    checked={c.negate}
                    onChange={e => toggleNegate(i(), e.target.checked)}
                  />
                  NOT
                </label>

                <button
                  type="button"
                  class="btn btn-danger btn-sm qb-remove"
                  onClick={() => removeCondition(i())}
                >✕</button>
              </div>
            </>
          );
        }}
      </For>
      <button type="button" class="btn btn-secondary btn-sm qb-add" onClick={addCondition}>
        + Add condition
      </button>
    </div>
  );
}
