import { useEffect, useReducer } from 'react';

/**
 * Minimal global toast surface — a module-level store + a <Toaster/> mounted once in the shell, so any code can
 * `toast.error(...)` without threading a context through every panel. Toasts auto-dismiss and are click-to-close.
 */
type ToastKind = 'error' | 'success' | 'info';
interface Toast {
  id: number;
  kind: ToastKind;
  msg: string;
}

let items: Toast[] = [];
let seq = 0;
const listeners = new Set<() => void>();

function emit(): void {
  for (const l of listeners) l();
}

function push(kind: ToastKind, msg: string): void {
  const id = ++seq;
  items = [...items, { id, kind, msg }];
  emit();
  window.setTimeout(() => dismiss(id), 5000);
}

function dismiss(id: number): void {
  items = items.filter((t) => t.id !== id);
  emit();
}

/** Turn any caught value into a readable message. */
function toMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export const toast = {
  error: (e: unknown) => push('error', toMessage(e)),
  success: (msg: string) => push('success', msg),
  info: (msg: string) => push('info', msg),
};

export function Toaster(): JSX.Element {
  const [, force] = useReducer((x: number) => x + 1, 0);
  useEffect(() => {
    const l = () => force();
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  }, []);
  return (
    <div className="toaster" aria-live="polite">
      {items.map((t) => (
        <button type="button" key={t.id} className={`toast toast-${t.kind}`} onClick={() => dismiss(t.id)}>
          {t.msg}
        </button>
      ))}
    </div>
  );
}
