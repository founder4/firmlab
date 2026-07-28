import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { type UpdatePathResult, type UpdaterCandidate, api } from '../api';
import { mockedApi } from '../test-api-mock';
import { UpdatePathPanel, sourceChainOf, updatePathState } from './UpdatePathPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

/** The OpenWrt case the source pass exists for: the entry point verifies nothing; the file it sources does. */
const sysupgrade = (o: Partial<UpdaterCandidate> = {}): UpdaterCandidate => ({
  path: 'sbin/sysupgrade',
  kind: 'script',
  why: 'file name "sysupgrade" is a firmware-update entry point',
  verifyCommands: [],
  missingVerifiers: [],
  flashWrites: ['mtd write'],
  ...o,
});

const withChain = (): UpdaterCandidate =>
  sysupgrade({
    sourced: [
      {
        file: 'lib/upgrade/fwtool.sh',
        via: ['sbin/sysupgrade', 'lib/functions.sh', 'lib/upgrade/fwtool.sh'],
        verifyCommands: ['ucert -V'],
        signatureCommands: ['ucert -V'],
        missingVerifiers: [],
        flashWrites: [],
        rollbackMarkers: [],
      },
    ],
    unresolvedSources: [
      {
        from: 'sbin/sysupgrade',
        directive: '.',
        spec: '$LIB_DIR/helper.sh',
        reason: 'the operand is built from a variable, so it is not knowable from the bytes',
      },
    ],
    sourceBounds: [
      'the 2-hop source-depth bound was reached, so the 3 further source directive(s) in lib/functions.sh were not followed',
    ],
  });

const result = (o: Partial<UpdatePathResult> = {}): UpdatePathResult => ({
  available: true,
  updaters: [withChain()],
  reason: 'Update-path integrity: container openwrt-fwtool; 1 updater(s) located across 4102 rootfs entries.',
  ...o,
});

function mount(r: UpdatePathResult | null) {
  mockApi.updatePath.mockResolvedValue(r);
  return render(<UpdatePathPanel imageId="img1" />);
}

describe('UpdatePathPanel — the chain that credited the candidate', () => {
  it('names the file the evidence is physically in, and how it was reached', async () => {
    const { container } = mount(result());
    await screen.findByText('Source chain');
    const text = container.textContent ?? '';
    expect(text).toContain('lib/upgrade/fwtool.sh');
    expect(text).toContain('the file these lines are physically in');
    expect(text).toContain('sbin/sysupgrade → lib/functions.sh → lib/upgrade/fwtool.sh');
    expect(text).toContain('ucert -V');
    // …and never as a line the entry point contains.
    expect(text).toContain('not under sbin/sysupgrade, which contains none of these lines');
  });

  it('keeps the honesty point: a credited verification is not a runtime proof', async () => {
    const { container } = mount(result());
    await screen.findByText('Source chain');
    const text = container.textContent ?? '';
    expect(text).toContain('does not prove the check runs');
    expect(text).toContain('sourcing a file defines its functions, it does not call them');
    expect(text).toContain('No source edge raises a proof state');
  });

  it('states what could not be resolved, and why', async () => {
    const { container } = mount(result());
    await screen.findByText('Source chain');
    const text = container.textContent ?? '';
    expect(text).toContain('$LIB_DIR/helper.sh');
    expect(text).toContain('the operand is built from a variable');
    expect(text).toContain('Guessing one would fabricate');
  });

  it('states where the bounds stopped following, as a bound and not as an answer', async () => {
    const { container } = mount(result());
    await screen.findByText('Source chain');
    const text = container.textContent ?? '';
    expect(text).toContain('A bound is not an answer');
    expect(text).toContain('the 2-hop source-depth bound was reached');
    expect(text).toContain('absent from what this candidate is credited with rather than cleared by it');
  });
});

describe('UpdatePathPanel — a result stored before the source pass reads exactly as it did', () => {
  it('prints the candidate with no chain block and claims nothing about sourcing', async () => {
    const { container } = mount(result({ updaters: [sysupgrade()] }));
    await screen.findByText('sbin/sysupgrade');
    expect(screen.queryByText('Source chain')).toBeNull();
    const text = container.textContent ?? '';
    expect(text).not.toContain('reached:');
    expect(text).not.toContain('could not be turned into a file');
    expect(text).toContain('mtd write');
  });

  it('says the two readings of a missing chain rather than picking one', async () => {
    const { container } = mount(result({ updaters: [sysupgrade()] }));
    await screen.findByText('sbin/sysupgrade');
    const text = container.textContent ?? '';
    expect(text).toContain('these scripts source nothing, or the result was stored by a build that did not follow');
  });

  it('reads a malformed chain field as absent instead of throwing', () => {
    const junk = { path: 'a', sourced: 'nope', unresolvedSources: 3 } as unknown as UpdaterCandidate;
    expect(sourceChainOf(junk)).toEqual({
      sourced: [],
      unresolved: [],
      bounds: [],
      recorded: false,
      followed: false,
    });
  });
});

describe('UpdatePathPanel — every kind of nothing gets its own sentence', () => {
  it('distinguishes "nobody ran it" from "it ran and found no updater"', async () => {
    expect(updatePathState(null, true)).toBe('not-run');
    expect(updatePathState({ available: true, updaters: [] }, true)).toBe('no-updaters');
    expect(updatePathState({ available: false }, true)).toBe('unavailable');
    expect(updatePathState(null, false)).toBe('loading');

    const { container } = mount(null);
    await waitFor(() => expect(screen.getByText(/Nobody has run the update-path provider/)).toBeTruthy());
    expect(container.textContent ?? '').toContain('no updater has been looked for, so nothing here has been cleared');
  });

  it('refuses to read an empty updater list as a firmware with no update path', async () => {
    const { container } = mount(result({ updaters: [], reason: 'no updater matched' }));
    await waitFor(() => expect(screen.getByText(/located no updater candidate/)).toBeTruthy());
    expect(container.textContent ?? '').toContain('not a verdict that the device has no update path');
  });
});

/**
 * The distinction this file exists to protect, and the one real bytes exposed: the Tenda camera's
 * `usr/bin/force_upgrade` genuinely sources nothing, and until the provider said so an empty chain and a result
 * written before the pass existed were the same absence on screen.
 */
describe('sourceChainOf — "no chain" and "nobody looked" are different answers', () => {
  it('reads a followed-but-empty candidate as an answer, not a gap', () => {
    const chain = sourceChainOf({ path: 'usr/bin/force_upgrade', sourcesFollowed: true });
    expect(chain.recorded).toBe(false);
    expect(chain.followed).toBe(true);
  });

  it('reads a candidate from a build that never followed edges as unknown', () => {
    const chain = sourceChainOf({ path: 'sbin/sysupgrade' });
    expect(chain.recorded).toBe(false);
    expect(chain.followed).toBe(false);
  });

  it('treats a recorded chain as followed even without the flag, so an older result is not called unknown', () => {
    const chain = sourceChainOf({
      path: 'sbin/sysupgrade',
      sourced: [{ file: 'lib/upgrade/fwtool.sh', via: ['sbin/sysupgrade'], verifyCommands: ['ucert -V'] }],
    });
    expect(chain.recorded).toBe(true);
    expect(chain.followed).toBe(true);
  });
});
