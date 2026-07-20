import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { initAppearance } from './theme';
import './theme.css';

// Apply the saved theme/density before first paint so there's no flash of the wrong theme.
initAppearance();

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
