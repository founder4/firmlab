import { render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { StaticAnalysis } from '../api';
import { setLocale } from '../i18n';
import {
  DIGEST_COUNT_FIELDS,
  SignatureDigestCoverage,
  presentSignatureDigestCoverage,
} from './SignatureDigestCoverage';

const coverage: NonNullable<StaticAnalysis['signatureDigests']> = {
  scope: 'listed_mediatek_brom_hits',
  capability: 'provided',
  listed: 7,
  planned: 6,
  attempted: 3,
  completed: 2,
  matched: 1,
  mismatched: 1,
  unavailable: 1,
  invalidCandidates: 1,
  skipped: 3,
  skippedExecutionBudget: 2,
  skippedByteBudget: 1,
  bytesPlanned: 9000,
  bytesSubmitted: 5000,
  bytesCompleted: 3000,
  maxExecutions: 3,
  maxBytes: 6000,
  note: 'Provider text stays verbatim.\nNot translated or rewritten.',
};
const zero = Object.fromEntries(DIGEST_COUNT_FIELDS.map((key) => [key, 0]));

beforeEach(() => setLocale('en'));

function count(label: string): HTMLElement {
  const dt = screen.getByText(label, { selector: 'dt' });
  const row = dt.parentElement;
  if (!row) throw new Error(`Missing metric: ${label}`);
  return within(row).getByRole('definition');
}

describe('persisted signature digest presentation decisions', () => {
  it('preserves every recorded raw count and lower applied limits without deriving from listed rows', () => {
    const view = presentSignatureDigestCoverage(coverage);
    expect(view.state).toBe('recorded');
    for (const key of DIGEST_COUNT_FIELDS) expect(view.counts[key]).toBe(coverage[key]);
    expect(view.capability).toBe('provided');
    expect(view.note).toBe(coverage.note);
  });

  it('treats an absent legacy field as not recorded, never a fabricated zero', () => {
    const view = presentSignatureDigestCoverage(undefined);
    expect(view.state).toBe('not-recorded');
    expect(Object.values(view.counts).every((n) => n === null)).toBe(true);
    expect(view.capability).toBeNull();
  });

  it.each([null, [], 'unexpected', 0, true, {}, { scope: 'whole_image', ...zero }])(
    'does not assign known scope or zero counts to malformed or future records: %j',
    (value) => {
      const view = presentSignatureDigestCoverage(value);
      expect(view.state).toBe('unknown');
      expect(Object.values(view.counts).every((n) => n === null)).toBe(true);
    },
  );

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1, '2', null, {}])(
    'retains valid fields but makes a malformed count unknown: %j',
    (completed) => {
      const view = presentSignatureDigestCoverage({ ...coverage, completed });
      expect(view.state).toBe('partial');
      expect(view.counts.completed).toBeNull();
      expect(view.counts.attempted).toBe(3);
      expect(view.counts.mismatched).toBe(1);
    },
  );

  it('does not derive completed from attempts, matches, capability or missing fields', () => {
    const { completed: _completed, ...partial } = coverage;
    const view = presentSignatureDigestCoverage(partial);
    expect(view.state).toBe('partial');
    expect(view.counts.completed).toBeNull();
    expect(view.counts.matched).toBe(1);
    expect(presentSignatureDigestCoverage({ ...coverage, capability: 'future' }).capability).toBeNull();
  });

  it.each([
    { listed: 8 },
    { completed: 6 },
    { matched: 2 },
    { skippedExecutionBudget: 3 },
    { attempted: 1 },
    { maxExecutions: 2 },
    { bytesCompleted: 5001 },
    { bytesSubmitted: 9001 },
    { maxBytes: 4999 },
    { capability: 'unavailable' },
  ])('marks inconsistent counts uncertain while preserving recorded valid values: %j', (patch) => {
    const view = presentSignatureDigestCoverage({ ...coverage, ...patch });
    expect(view.state).toBe('partial');
    expect(view.counts.listed).toBe(patch.listed ?? 7);
  });

  it.each([{ bytesPlanned: 1 }, { bytesSubmitted: 1 }, { bytesCompleted: 1 }])(
    'does not treat bytes with zero corresponding work as a consistent record: %j',
    (patch) => {
      const view = presentSignatureDigestCoverage({ ...coverage, ...zero, ...patch });
      expect(view.state).toBe('partial');
    },
  );

  it('rejects impossible applied limits rather than clamping them to the ceilings', () => {
    const view = presentSignatureDigestCoverage({ ...coverage, maxExecutions: 9, maxBytes: 67_108_865 });
    expect(view.state).toBe('partial');
    expect(view.counts.maxExecutions).toBeNull();
    expect(view.counts.maxBytes).toBeNull();
  });

  it('accepts recorded zero work and unavailable capability as separate valid states', () => {
    const empty = { ...coverage, ...zero, maxExecutions: 8, maxBytes: 67_108_864 };
    expect(presentSignatureDigestCoverage(empty).state).toBe('recorded');
    const unavailable = {
      ...empty,
      capability: 'unavailable',
      listed: 2,
      planned: 2,
      unavailable: 2,
      bytesPlanned: 500,
    };
    expect(presentSignatureDigestCoverage(unavailable).state).toBe('recorded');
    expect(presentSignatureDigestCoverage(unavailable).counts.mismatched).toBe(0);
  });
});

const contradictoryRecords = [
  {
    name: 'provided capability with unavailable result but no attempt',
    patch: { attempted: 0, completed: 0, matched: 0, unavailable: 1, bytesSubmitted: 0, bytesCompleted: 0 },
  },
  {
    name: 'completed digest without submitted or completed bytes',
    patch: { attempted: 1, completed: 1, matched: 1, unavailable: 0, bytesSubmitted: 0, bytesCompleted: 0 },
  },
  {
    name: 'planned candidate and byte skip without planned bytes',
    patch: {
      attempted: 0,
      completed: 0,
      matched: 0,
      unavailable: 0,
      skipped: 1,
      skippedByteBudget: 1,
      bytesPlanned: 0,
      bytesSubmitted: 0,
      bytesCompleted: 0,
      maxBytes: 0,
    },
  },
].map(({ name, patch }) => ({
  name,
  record: {
    ...coverage,
    listed: 1,
    planned: 1,
    invalidCandidates: 0,
    mismatched: 0,
    skipped: 0,
    skippedExecutionBudget: 0,
    skippedByteBudget: 0,
    bytesPlanned: 1025,
    maxExecutions: 8,
    maxBytes: 67_108_864,
    ...patch,
  },
}));

describe('contradictory saved digest counters', () => {
  it.each(contradictoryRecords)('warns without rewriting raw counts: $name', ({ record }) => {
    const view = presentSignatureDigestCoverage(record);
    expect(view.state).toBe('partial');
    for (const key of DIGEST_COUNT_FIELDS) expect(view.counts[key]).toBe(record[key]);
    render(<SignatureDigestCoverage coverage={record} />);
    expect(screen.getByText(/This record is incomplete or inconsistent/)).toBeVisible();
    expect(count('Attempts')).toHaveTextContent(new RegExp(`^${record.attempted}$`));
    expect(count('Unavailable results')).toHaveTextContent(new RegExp(`^${record.unavailable}$`));
  });
});

describe('recorded digest coverage interface', () => {
  it('labels attempts, completions, unavailable results and each budget independently', () => {
    render(<SignatureDigestCoverage coverage={coverage} />);
    expect(count('Listed supported hits')).toHaveTextContent(/^7$/);
    expect(count('Planned valid candidates')).toHaveTextContent(/^6$/);
    expect(count('Attempts')).toHaveTextContent(/^3$/);
    expect(count('Completed digests')).toHaveTextContent(/^2$/);
    expect(count('Matches')).toHaveTextContent(/^1$/);
    expect(count('Mismatches')).toHaveTextContent(/^1$/);
    expect(count('Unavailable results')).toHaveTextContent(/^1$/);
    expect(count('Invalid candidates')).toHaveTextContent(/^1$/);
    expect(count('Budget skips')).toHaveTextContent(/^3$/);
    const summary = screen.getByText('Budgets and recorded details');
    expect(summary.tagName).toBe('SUMMARY');
    const details = summary.parentElement;
    expect(details?.tagName).toBe('DETAILS');
    expect(details).not.toHaveAttribute('open');
    // Native disclosure behavior is verified in Chromium, not fabricated by a jsdom click assertion.
    expect(count('Execution-budget skips')).toHaveTextContent(/^2$/);
    expect(count('Byte-budget skips')).toHaveTextContent(/^1$/);
    expect(count('Bytes planned')).toHaveTextContent(/^9000$/);
    expect(count('Bytes submitted')).toHaveTextContent(/^5000$/);
    expect(count('Bytes completed')).toHaveTextContent(/^3000$/);
    expect(count('Applied execution limit')).toHaveTextContent(/^3$/);
    expect(count('Applied byte limit')).toHaveTextContent(/^6000$/);
    expect(screen.getByText(/even when a call throws/)).toBeInTheDocument();
    expect(screen.getByText(/8 executions and 64 MiB/)).toBeInTheDocument();
    expect(screen.getByText(/capability was provided/)).toBeInTheDocument();
  });

  it('keeps hit scope and the unkeyed GFH/payload-only caveat visible with budgets closed', () => {
    render(<SignatureDigestCoverage coverage={coverage} />);
    expect(screen.getByText(/listed, supported MediaTek BootROM hits only/)).toBeVisible();
    expect(screen.getByText(/Unavailable results are not mismatches/)).toBeVisible();
    expect(screen.getByText(/first 0x600 device\/BRLYT header bytes/)).toBeVisible();
    expect(screen.getByText(/unkeyed digest.*GFH\/payload/)).toBeVisible();
    expect(screen.getByText(/no authenticity, boot, runtime or device behavior/)).toBeVisible();
    expect(screen.queryByRole('progressbar')).toBeNull();
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('does not turn a zero listing or zero mismatches into a clean verdict', () => {
    render(<SignatureDigestCoverage coverage={{ ...coverage, ...zero }} />);
    expect(count('Completed digests')).toHaveTextContent(/^0$/);
    expect(screen.getByText(/Zero counts never mean clean/)).toBeVisible();
    expect(screen.getByText(/do not cover all signatures or the firmware/)).toBeVisible();
  });

  it('keeps a missing capability distinct from a mismatch and a completed digest', () => {
    render(
      <SignatureDigestCoverage
        coverage={{ ...coverage, ...zero, capability: 'unavailable', listed: 2, planned: 2, unavailable: 2 }}
      />,
    );
    expect(count('Unavailable results')).toHaveTextContent(/^2$/);
    expect(count('Mismatches')).toHaveTextContent(/^0$/);
    expect(count('Completed digests')).toHaveTextContent(/^0$/);
    expect(screen.getByText(/capability was recorded as unavailable; this is not a mismatch/)).toBeInTheDocument();
  });

  it('does not render counters or actions for old saved analyses', () => {
    render(<SignatureDigestCoverage />);
    expect(screen.getByText(/coverage was not recorded/)).toBeVisible();
    expect(screen.queryByRole('definition')).toBeNull();
    expect(screen.queryByText('Budgets and recorded details')).toBeNull();
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('renders partial records as unknown per missing value and preserves large exact raw counts', () => {
    render(<SignatureDigestCoverage coverage={{ scope: coverage.scope, listed: Number.MAX_SAFE_INTEGER, note: 2 }} />);
    expect(count('Listed supported hits')).toHaveTextContent(/^9007199254740991$/);
    expect(count('Completed digests')).toHaveTextContent(/^Unknown$/);
    expect(count('Applied byte limit')).toHaveTextContent(/^Unknown$/);
    expect(screen.getByText(/incomplete or inconsistent/)).toBeVisible();
    expect(screen.getByText(/capability is unknown/)).toBeInTheDocument();
    expect(screen.queryByText('Provider note (verbatim)')).toBeNull();
  });

  it('does not expose wrong-scope counts as MediaTek work', () => {
    render(<SignatureDigestCoverage coverage={{ ...coverage, scope: 'future_scope' }} />);
    expect(screen.getByText(/record is not understood/)).toBeVisible();
    expect(screen.queryByRole('definition')).toBeNull();
  });

  it('localises the interface while retaining provider prose verbatim', () => {
    setLocale('es');
    render(<SignatureDigestCoverage coverage={coverage} />);
    expect(screen.getByRole('region', { name: 'Cobertura SHA-256 registrada' })).toBeVisible();
    expect(count('Intentos')).toHaveTextContent(/^3$/);
    expect(count('Resúmenes completados')).toHaveTextContent(/^2$/);
    expect(count('Omitidos por tope de bytes')).toHaveTextContent(/^1$/);
    expect(screen.getByText(/0x600 bytes de cabecera de dispositivo\/BRLYT/)).toBeVisible();
    expect(screen.getByText(/No prueba autenticidad/)).toBeVisible();
    expect(screen.getByText('Nota del proveedor (literal)')).toBeInTheDocument();
    const note = screen.getByText(/Provider text stays verbatim/);
    expect(note.textContent).toBe(coverage.note);
  });
});
