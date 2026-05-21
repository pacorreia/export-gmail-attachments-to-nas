import { createSignal, Switch, Match } from 'solid-js';
import { ToastProvider } from './components/Toast';
import { ModalProvider } from './components/Modal';
import Accounts from './pages/Accounts';
import FileShares from './pages/FileShares';
import Rules from './pages/Rules';
import Plugins from './pages/Plugins';
import Logs from './pages/Logs';
import Settings from './pages/Settings';

const NAV_ITEMS = [
  { id: 'accounts',   label: 'Accounts',    icon: '👤' },
  { id: 'fileshares', label: 'File Shares', icon: '📁' },
  { id: 'rules',      label: 'Rules',       icon: '⚡' },
  { id: 'plugins',    label: 'Plugins',     icon: '🔌' },
  { id: 'logs',       label: 'Run Logs',    icon: '📋' },
  { id: 'settings',   label: 'Settings',    icon: '⚙️' },
];

export default function App() {
  const [page, setPage] = createSignal('accounts');

  return (
    <ToastProvider>
      <ModalProvider>
        <div class="layout">
          <nav class="sidebar">
            <div class="sidebar-brand">📧 NAS Exporter</div>
            <ul class="sidebar-nav">
              {NAV_ITEMS.map(item => (
                <li>
                  <a
                    href="#"
                    classList={{ active: page() === item.id }}
                    onClick={e => { e.preventDefault(); setPage(item.id); }}
                  >
                    <span style="margin-right:8px;font-size:15px">{item.icon}</span>{item.label}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
          <main class="main-content">
            <Switch>
              <Match when={page() === 'accounts'}><Accounts /></Match>
              <Match when={page() === 'fileshares'}><FileShares /></Match>
              <Match when={page() === 'rules'}><Rules /></Match>
              <Match when={page() === 'plugins'}><Plugins /></Match>
              <Match when={page() === 'logs'}><Logs /></Match>
              <Match when={page() === 'settings'}><Settings /></Match>
            </Switch>
          </main>
        </div>
      </ModalProvider>
    </ToastProvider>
  );
}
