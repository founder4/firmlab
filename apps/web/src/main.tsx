import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { initLocale } from './i18n';
import { initAppearance } from './theme';
import './theme.css';

// Apply the saved theme/density before first paint so there's no flash of the wrong theme, and the saved locale
// for the same reason — <html lang> has to be right from the first paint, not after React mounts.
initAppearance();
initLocale();

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
