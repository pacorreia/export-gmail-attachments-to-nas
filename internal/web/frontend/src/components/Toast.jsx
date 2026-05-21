import { createContext, useContext, createSignal } from 'solid-js';
import { For } from 'solid-js';

const ToastContext = createContext();

export function ToastProvider(props) {
  const [toasts, setToasts] = createSignal([]);
  let nextId = 0;

  function show(msg, type = 'info') {
    const id = nextId++;
    setToasts(t => [...t, { id, msg, type }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4000);
  }

  return (
    <ToastContext.Provider value={{ show }}>
      {props.children}
      <div id="toast-container">
        <For each={toasts()}>
          {t => <div class={`toast toast-${t.type}`}>{t.msg}</div>}
        </For>
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);
