import { createSignal, createEffect, Show } from 'solid-js';

const DAY_LABELS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

function pad(n) {
  return String(n).padStart(2, '0');
}

function buildScheduleJSON(type, state) {
  const base = { type };
  switch (type) {
    case 'interval':
      return JSON.stringify({ type: 'interval', interval: state.intervalNum + state.intervalUnit });
    case 'daily':
      return JSON.stringify({
        type: 'daily',
        hour: Number(state.hour),
        minute: Number(state.minute),
        ...(state.until ? { until: state.until } : {}),
      });
    case 'weekly':
      return JSON.stringify({
        type: 'weekly',
        days: [...state.days].sort((a, b) => a - b),
        hour: Number(state.hour),
        minute: Number(state.minute),
        ...(state.until ? { until: state.until } : {}),
      });
    case 'monthly':
      return JSON.stringify({
        type: 'monthly',
        day_of_month: Number(state.dayOfMonth),
        hour: Number(state.hour),
        minute: Number(state.minute),
        ...(state.until ? { until: state.until } : {}),
      });
    case 'once':
      return JSON.stringify({
        type: 'once',
        once_at: state.onceDate + 'T' + pad(state.onceHour) + ':' + pad(state.onceMinute),
      });
    default:
      return '';
  }
}

function parseInitial(value) {
  if (!value) return null;
  if (!value.startsWith('{')) {
    // Legacy: "1h", "30m", "7d"
    const m = value.match(/^(\d+)([smhd])$/);
    if (m) return { type: 'interval', intervalNum: m[1], intervalUnit: m[2] };
    return null;
  }
  try { return JSON.parse(value); } catch { return null; }
}

export default function RecurrencePicker(props) {
  const initial = parseInitial(props.value);

  // Compute initial values from the parsed schedule.
  const initIntervalNum = (() => {
    if (initial?.type === 'interval' && initial.interval) {
      const m = initial.interval.match(/^(\d+)/);
      return m ? m[1] : '1';
    }
    return '1';
  })();
  const initIntervalUnit = (() => {
    if (initial?.type === 'interval' && initial.interval) {
      const m = initial.interval.match(/([smhd])$/);
      return m ? m[1] : 'h';
    }
    return 'h';
  })();
  const initOnceDate = (() => (initial?.once_at ? initial.once_at.slice(0, 10) : ''))();
  const initOnceHour = (() => (initial?.once_at ? Number(initial.once_at.slice(11, 13)) : 8))();
  const initOnceMinute = (() => (initial?.once_at ? Number(initial.once_at.slice(14, 16)) : 0))();

  const [type, setType] = createSignal(initial?.type || 'interval');
  const [intervalNum, setIntervalNum] = createSignal(initIntervalNum);
  const [intervalUnit, setIntervalUnit] = createSignal(initIntervalUnit);
  const [hour, setHour] = createSignal(initial?.hour ?? 8);
  const [minute, setMinute] = createSignal(initial?.minute ?? 0);
  const [days, setDays] = createSignal(new Set(initial?.days || []));
  const [dayOfMonth, setDayOfMonth] = createSignal(initial?.day_of_month ?? 1);
  const [until, setUntil] = createSignal(initial?.until || '');
  const [onceDate, setOnceDate] = createSignal(initOnceDate);
  const [onceHour, setOnceHour] = createSignal(initOnceHour);
  const [onceMinute, setOnceMinute] = createSignal(initOnceMinute);

  function emit() {
    const json = buildScheduleJSON(type(), {
      intervalNum: intervalNum(),
      intervalUnit: intervalUnit(),
      hour: hour(),
      minute: minute(),
      days: days(),
      dayOfMonth: dayOfMonth(),
      until: until(),
      onceDate: onceDate(),
      onceHour: onceHour(),
      onceMinute: onceMinute(),
    });
    props.onChange?.(json);
  }

  // Emit whenever any value changes.
  createEffect(() => {
    type(); intervalNum(); intervalUnit(); hour(); minute();
    // read days as array to track reactivity
    [...days()]; dayOfMonth(); until(); onceDate(); onceHour(); onceMinute();
    emit();
  });

  function toggleDay(d) {
    setDays(prev => {
      const next = new Set(prev);
      if (next.has(d)) next.delete(d);
      else next.add(d);
      return next;
    });
  }

  const timeInputs = () => (
    <div class="recurrence-row">
      <label class="form-label" style="margin:0;min-width:32px">At</label>
      <input class="input" type="number" min="0" max="23" value={hour()}
        style="width:64px;text-align:center"
        onInput={e => setHour(Number(e.target.value))} />
      <span style="align-self:center;font-weight:600;color:var(--on-surface-variant)">:</span>
      <input class="input" type="number" min="0" max="59" value={minute()}
        style="width:64px;text-align:center"
        onInput={e => setMinute(Number(e.target.value))} />
    </div>
  );

  const untilInput = () => (
    <div class="recurrence-row">
      <label class="form-label" style="margin:0;min-width:32px">Until</label>
      <input class="input" type="date" value={until()}
        style="width:180px"
        onInput={e => setUntil(e.target.value)} />
      <span class="text-muted" style="font-size:12px">(optional)</span>
    </div>
  );

  return (
    <div class="recurrence-picker">
      {/* Type selector */}
      <div class="recurrence-row">
        <label class="form-label" style="margin:0;min-width:80px">Recurrence</label>
        <div class="recurrence-type-tabs">
          {['interval', 'daily', 'weekly', 'monthly', 'once'].map(t => (
            <button type="button"
              class={'recurrence-tab' + (type() === t ? ' active' : '')}
              onClick={() => setType(t)}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Interval */}
      <Show when={type() === 'interval'}>
        <div class="recurrence-row">
          <label class="form-label" style="margin:0;min-width:80px">Every</label>
          <input class="input" type="number" min="1" value={intervalNum()}
            style="width:72px;text-align:center"
            onInput={e => setIntervalNum(e.target.value)} />
          <select class="select" value={intervalUnit()}
            onChange={e => setIntervalUnit(e.target.value)}>
            <option value="s">Seconds</option>
            <option value="m">Minutes</option>
            <option value="h">Hours</option>
            <option value="d">Days</option>
          </select>
        </div>
      </Show>

      {/* Daily */}
      <Show when={type() === 'daily'}>
        {timeInputs()}
        {untilInput()}
      </Show>

      {/* Weekly */}
      <Show when={type() === 'weekly'}>
        <div class="recurrence-row">
          <label class="form-label" style="margin:0;min-width:80px">On</label>
          <div class="day-pills">
            {DAY_LABELS.map((label, i) => (
              <button type="button"
                class={'day-pill' + (days().has(i) ? ' active' : '')}
                onClick={() => toggleDay(i)}>
                {label.slice(0, 2)}
              </button>
            ))}
          </div>
        </div>
        {timeInputs()}
        {untilInput()}
      </Show>

      {/* Monthly */}
      <Show when={type() === 'monthly'}>
        <div class="recurrence-row">
          <label class="form-label" style="margin:0;min-width:80px">Day</label>
          <input class="input" type="number" min="1" max="31" value={dayOfMonth()}
            style="width:72px;text-align:center"
            onInput={e => setDayOfMonth(Number(e.target.value))} />
          <span class="text-muted" style="font-size:13px">of each month</span>
        </div>
        {timeInputs()}
        {untilInput()}
      </Show>

      {/* Once */}
      <Show when={type() === 'once'}>
        <div class="recurrence-row">
          <label class="form-label" style="margin:0;min-width:80px">Date</label>
          <input class="input" type="date" value={onceDate()}
            style="width:180px"
            onInput={e => setOnceDate(e.target.value)} />
        </div>
        <div class="recurrence-row">
          <label class="form-label" style="margin:0;min-width:80px">At</label>
          <input class="input" type="number" min="0" max="23" value={onceHour()}
            style="width:64px;text-align:center"
            onInput={e => setOnceHour(Number(e.target.value))} />
          <span style="align-self:center;font-weight:600;color:var(--on-surface-variant)">:</span>
          <input class="input" type="number" min="0" max="59" value={onceMinute()}
            style="width:64px;text-align:center"
            onInput={e => setOnceMinute(Number(e.target.value))} />
        </div>
      </Show>
    </div>
  );
}
