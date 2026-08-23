import '@testing-library/jest-dom/vitest';

// Node 22 exposes an experimental global `localStorage` whose getter warns unless the process received a backing
// file. Tests run in jsdom and already have the browser-compatible store they need; pin the global name to that
// store before application modules evaluate so neither the warning nor two competing storage implementations leak
// into the suite.
const testStorageData = new Map<string, string>();
const testStorage: Storage = {
  get length() {
    return testStorageData.size;
  },
  clear: () => testStorageData.clear(),
  getItem: (key) => testStorageData.get(key) ?? null,
  key: (index) => [...testStorageData.keys()][index] ?? null,
  removeItem: (key) => testStorageData.delete(key),
  setItem: (key, value) => testStorageData.set(key, String(value)),
};
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: testStorage });
if (document.defaultView) {
  Object.defineProperty(document.defaultView, 'localStorage', { configurable: true, value: testStorage });
}
