import { createContext, useContext, createSignal, Show } from 'solid-js';

const ModalContext = createContext();

export function ModalProvider(props) {
  const [factory, setFactory] = createSignal(null);

  // Pass a zero-argument factory: () => <YourComponent />
  function show(fn) { setFactory(() => fn); }
  function close() { setFactory(null); }

  function onOverlayClick(e) {
    if (e.target === e.currentTarget) close();
  }

  return (
    <ModalContext.Provider value={{ show, close }}>
      {props.children}
      <Show when={factory()}>
        <div class="modal-overlay" onClick={onOverlayClick}>
          {/* Call the factory inside the reactive tree so components get proper owner + context */}
          <div class="modal-box">{factory()?.()}</div>
        </div>
      </Show>
    </ModalContext.Provider>
  );
}

export const useModal = () => useContext(ModalContext);
