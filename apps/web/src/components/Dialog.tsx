/**
 * The one modal this shell uses — for a confirmation, and for the few actions that need a short typed answer.
 *
 * It replaces `window.prompt`, which blocked the page, could not be styled, could not say WHICH field was missing,
 * and asked two questions as two separate native popups (withdrawing an assertion). A field here is required
 * unless marked otherwise, and submitting with one empty names it instead of silently doing nothing.
 *
 * Focus: a destructive dialog opens on Cancel (a stray Enter must not delete anything); otherwise on the first
 * field, or on the confirm button. Tab is kept inside the dialog and Escape cancels.
 */
import { type KeyboardEvent, useId, useRef, useState } from 'react';
import { useMessages } from '../i18n';

export interface DialogField {
  name: string;
  label: string;
  initial?: string;
  /** Required unless false. */
  required?: boolean;
  multiline?: boolean;
}

export function Dialog({
  title,
  body,
  confirmLabel,
  danger,
  fields = [],
  onCancel,
  onConfirm,
}: {
  title: string;
  body?: string;
  confirmLabel: string;
  danger?: boolean;
  fields?: readonly DialogField[];
  onCancel: () => void;
  onConfirm: (values: Record<string, string>) => void;
}): JSX.Element {
  const t = useMessages();
  const id = useId();
  const box = useRef<HTMLDivElement>(null);
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(fields.map((f) => [f.name, f.initial ?? ''])),
  );
  const [missing, setMissing] = useState<string[]>([]);

  const submit = (): void => {
    const empty = fields.filter((f) => f.required !== false && !(values[f.name] ?? '').trim()).map((f) => f.name);
    setMissing(empty);
    if (empty.length > 0) return;
    onConfirm(Object.fromEntries(Object.entries(values).map(([k, v]) => [k, v.trim()])));
  };

  const onKeyDown = (e: KeyboardEvent): void => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      onCancel();
      return;
    }
    if (e.key !== 'Tab' || !box.current) return;
    const focusable = box.current.querySelectorAll<HTMLElement>('input, textarea, button');
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last?.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first?.focus();
    }
  };

  const autoFocusField = !danger && fields.length > 0;
  return (
    <div className="modal-scrim" onClick={onCancel} onKeyDown={onKeyDown} role="presentation">
      <div
        ref={box}
        className="dialog"
        // biome-ignore lint/a11y/useSemanticElements: a portal-free modal; focus is placed and trapped explicitly.
        role="dialog"
        onClick={(e) => e.stopPropagation()}
        aria-modal="true"
        aria-labelledby={`${id}-title`}
      >
        <div className="dialog-title" id={`${id}-title`}>
          {title}
        </div>
        {body ? (
          <p className="hint" style={{ margin: '0 0 16px' }}>
            {body}
          </p>
        ) : null}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          {fields.map((f, i) => {
            const fieldId = `${id}-${f.name}`;
            const isMissing = missing.includes(f.name);
            const common = {
              id: fieldId,
              className: 'input',
              value: values[f.name] ?? '',
              'aria-invalid': isMissing || undefined,
              'aria-describedby': isMissing ? `${fieldId}-err` : undefined,
              ref: (el: HTMLInputElement | HTMLTextAreaElement | null) => {
                if (
                  autoFocusField &&
                  i === 0 &&
                  el &&
                  document.activeElement !== el &&
                  !box.current?.contains(document.activeElement)
                )
                  el.focus();
              },
              onChange: (e: { target: { value: string } }) => setValues((v) => ({ ...v, [f.name]: e.target.value })),
            };
            return (
              <div key={f.name} style={{ marginBottom: 12 }}>
                <label htmlFor={fieldId} className="field-label">
                  {f.label}
                </label>
                {f.multiline ? <textarea rows={3} {...common} /> : <input type="text" {...common} />}
                {isMissing ? (
                  <div id={`${fieldId}-err`} className="field-error" role="alert">
                    {t.common.required(f.label)}
                  </div>
                ) : null}
              </div>
            );
          })}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            {/* A destructive dialog opens on Cancel, so a stray Enter cannot delete anything. */}
            <button
              type="button"
              className="btn btn-sm"
              onClick={onCancel}
              ref={(el) => (danger && el && !box.current?.contains(document.activeElement) ? el.focus() : undefined)}
            >
              {t.common.cancel}
            </button>
            <button
              type="submit"
              className={`btn btn-sm ${danger ? 'btn-danger' : 'btn-primary'}`}
              ref={(el) =>
                !danger && fields.length === 0 && el && !box.current?.contains(document.activeElement)
                  ? el.focus()
                  : undefined
              }
            >
              {confirmLabel}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
