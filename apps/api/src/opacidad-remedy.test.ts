import { describe, expect, it } from 'vitest';
import {
  EXECUTABLE_REMEDIES,
  isExecutableRemedy,
  remedyForBlockedProbe,
  remedyForBlockedProbes,
  remedyForCredMatch,
  remedyForDeviceTree,
  remedyForFwHunt,
  remedyForGrypeOutcome,
  remedyForKmod,
  remedyForNoRootfs,
  remedyForProbeVerdict,
  remedyForWebTaint,
  remedyForYaraScan,
} from './opacidad-remedy.js';
import type { CredMatchState } from './providers/credmatch.js';
import type { ProbeVerdict } from './providers/dynprobe.js';
import type { SymReachBlockedBy } from './providers/symreach.js';
import type { YaraScanState } from './providers/yarascan.js';

describe('the executable split', () => {
  it('queues only work a campaign can actually schedule', () => {
    expect([...EXECUTABLE_REMEDIES].sort()).toEqual(['escalate-full-system', 'install-tool', 'raise-bound', 'retry']);
    for (const remedy of ['settled', 'reacquire-input', 'unbounded-search', 'defect'] as const) {
      expect(isExecutableRemedy(remedy)).toBe(false);
    }
  });

  it('treats an undeclared remedy as unknown, never as executable and never as settled', () => {
    // The whole reason the field is optional forever: a run persisted before it exists declares nothing, and a
    // campaign that reads silence as "answered" retires debt it never measured.
    expect(isExecutableRemedy(undefined)).toBe(false);
  });
});

describe('credential cross-reference', () => {
  it('separates missing input from an image whose accounts hold no testable hash', () => {
    const cases: [Exclude<CredMatchState, 'scanned'>, string][] = [
      ['no_target', 'reacquire-input'],
      ['no_account_files', 'settled'],
      ['no_hashes', 'settled'],
      ['no_candidates', 'reacquire-input'],
    ];
    for (const [state, remedy] of cases) expect(remedyForCredMatch(state)).toBe(remedy);
  });
});

describe('YARA', () => {
  it('reads four of its six blocked states as this deployment, not this firmware', () => {
    const cases: [Exclude<YaraScanState, 'scanned'>, string][] = [
      ['tool_absent', 'install-tool'],
      ['no_corpus', 'install-tool'],
      ['corpus_empty', 'install-tool'],
      ['no_rules_applied', 'install-tool'],
      ['no_target', 'reacquire-input'],
      ['scan_failed', 'retry'],
    ];
    for (const [state, remedy] of cases) expect(remedyForYaraScan(state)).toBe(remedy);
  });
});

describe('a blocked reachability probe', () => {
  it('keeps a malformed request apart from a missing tool', () => {
    const cases: [SymReachBlockedBy, string][] = [
      ['platform', 'install-tool'],
      ['harness', 'retry'],
      ['request', 'defect'],
    ];
    for (const [blockedBy, remedy] of cases) expect(remedyForBlockedProbe(blockedBy)).toBe(remedy);
  });

  it('declares nothing for a result stored before the discriminant existed', () => {
    expect(remedyForBlockedProbe(undefined)).toBeUndefined();
  });

  it('reports the worst cause when one step covered several objects', () => {
    expect(remedyForBlockedProbes(['request', 'harness', 'platform'])).toBe('install-tool');
    expect(remedyForBlockedProbes(['request', 'harness'])).toBe('retry');
    expect(remedyForBlockedProbes(['request'])).toBe('defect');
    // Nothing named a cause: every object answered inside its budget and simply reached nothing.
    expect(remedyForBlockedProbes([undefined])).toBe('unbounded-search');
    expect(remedyForBlockedProbes([])).toBe('unbounded-search');
  });
});

describe('dynamic reproduction', () => {
  it('retries only the verdict that observed nothing', () => {
    const cases: [ProbeVerdict, string | undefined][] = [
      ['not_attached', 'retry'],
      // The sandbox came up short, which is qemu-user's limit and FirmLab's rung — never an instruction to go and
      // find different firmware.
      ['emulation_artifact', 'escalate-full-system'],
      ['sink_executed', 'unbounded-search'],
      ['ran_clean', 'unbounded-search'],
      ['crash', undefined],
      ['crash_input_controlled', undefined],
    ];
    for (const [verdict, remedy] of cases) expect(remedyForProbeVerdict(verdict)).toBe(remedy);
  });
});

describe('device tree — the largest block of degraded cells in the corpus', () => {
  const complete = {
    candidateFiles: 3,
    filesRead: 3,
    skippedByFileCap: 0,
    skippedOversize: 0,
    skippedUnreadable: 0,
    traversalComplete: true,
    directoriesVisited: 12,
    fileCap: 8,
    selectionRule: 'breadth-first, path-sorted',
  };

  it('settles an exhausted search: every candidate read, no FDT magic anywhere', () => {
    expect(remedyForDeviceTree({ extractionScan: complete, rejectedCount: 0, extractionAvailable: true })).toBe(
      'settled',
    );
  });

  it('settles an image with no extraction output at all — the raw scan was the whole search', () => {
    expect(remedyForDeviceTree({ rejectedCount: 0, extractionAvailable: false })).toBe('settled');
  });

  it('leaves something to ask when the walk was capped or unfinished', () => {
    expect(
      remedyForDeviceTree({
        extractionScan: { ...complete, skippedByFileCap: 2 },
        rejectedCount: 0,
        extractionAvailable: true,
      }),
    ).toBe('raise-bound');
    expect(
      remedyForDeviceTree({
        extractionScan: { ...complete, traversalComplete: false },
        rejectedCount: 0,
        extractionAvailable: true,
      }),
    ).toBe('raise-bound');
  });

  it('names the raw-image read cap without allocating a 512 MiB fixture', () => {
    expect(
      remedyForDeviceTree({
        rawImageScan: { imageBytes: 11, bytesRead: 0, readCap: 10, complete: false },
        rejectedCount: 0,
        extractionAvailable: false,
      }),
    ).toBe('raise-bound');
  });

  it('declares nothing when output existed but no walk was recorded', () => {
    // Absence of a walk is absence of evidence about the walk. Calling it settled would retire a place nobody read.
    expect(remedyForDeviceTree({ rejectedCount: 0, extractionAvailable: true })).toBeUndefined();
  });

  it('declares nothing for a validated FDT header that could not be read to completion', () => {
    // Truncated tree or a parser that stops early — undecidable here, and the two need opposite responses.
    expect(
      remedyForDeviceTree({ extractionScan: complete, rejectedCount: 1, extractionAvailable: true }),
    ).toBeUndefined();
  });
});

describe('web attack surface', () => {
  it('settles a rootfs that was fully walked and holds no handler', () => {
    expect(remedyForWebTaint({ partialWalk: false, handlers: 0 })).toBe('settled');
  });

  it('asks for more when the walk itself was short', () => {
    expect(remedyForWebTaint({ partialWalk: true, handlers: 0 })).toBe('raise-bound');
    expect(remedyForWebTaint({ partialWalk: true, handlers: 402 })).toBe('raise-bound');
  });
});

describe('FwHunt', () => {
  const base = {
    available: true,
    modulePassRan: true,
    modulesCarved: 136,
    modulesScanned: 136,
    modulesFailed: 0,
    modulesSkipped: 0,
  };

  it('settles a variable store that carves no EFI module', () => {
    expect(remedyForFwHunt({ ...base, modulePassRan: false, modulesCarved: 0, modulesScanned: 0 })).toBe('settled');
  });

  it('queues a module pass that left modules unattempted or covered less than half', () => {
    expect(remedyForFwHunt({ ...base, modulesScanned: 100, modulesSkipped: 36 })).toBe('raise-bound');
    expect(remedyForFwHunt({ ...base, modulesScanned: 40 })).toBe('raise-bound');
    expect(remedyForFwHunt({ ...base, modulePassRan: false, modulesScanned: 0 })).toBe('raise-bound');
  });

  it('does not queue modules that exhaust their per-module timeout — they do not converge on a rerun', () => {
    expect(remedyForFwHunt({ ...base, modulesScanned: 131, modulesFailed: 5 })).toBe('unbounded-search');
  });

  it('reports an absent tool as the deployment gap it is', () => {
    expect(remedyForFwHunt({ ...base, available: false })).toBe('install-tool');
  });
});

describe('kernel-module surface', () => {
  it('does not read a module-less rootfs as a missing disassembler', () => {
    // Measured on the deployed corpus: `callSitePass.available` is false both when radare2 is absent and when the
    // pass was never reached, and every module-less image was reporting a deployment gap.
    expect(remedyForKmod({ modulesFound: 0, callSitePassAvailable: false, symbolTableUnreadable: 0 })).toBeUndefined();
  });

  it('settles an exhaustive module inventory or a kernel that compiled module loading out', () => {
    const base = { modulesFound: 0, callSitePassAvailable: false, symbolTableUnreadable: 0 };
    expect(
      remedyForKmod({
        ...base,
        inventoryScan: { complete: true, entriesVisited: 812, cap: 40_000, skippedUnreadable: 0 },
        moduleSupport: 'enabled',
      }),
    ).toBe('settled');
    expect(remedyForKmod({ ...base, moduleSupport: 'disabled' })).toBe('settled');
  });

  it('raises a capped module walk and leaves unreadable directories undeclared', () => {
    const base = { modulesFound: 0, callSitePassAvailable: false, symbolTableUnreadable: 0 };
    expect(
      remedyForKmod({
        ...base,
        inventoryScan: { complete: false, entriesVisited: 40_000, cap: 40_000, skippedUnreadable: 0 },
        moduleSupport: 'enabled',
      }),
    ).toBe('raise-bound');
    expect(
      remedyForKmod({
        ...base,
        inventoryScan: { complete: false, entriesVisited: 100, cap: 40_000, skippedUnreadable: 1 },
      }),
    ).toBeUndefined();
  });

  it('names the missing disassembler when there were modules to disassemble', () => {
    expect(remedyForKmod({ modulesFound: 12, callSitePassAvailable: false, symbolTableUnreadable: 0 })).toBe(
      'install-tool',
    );
  });

  it('settles an unreadable symbol table — that is the module, not the deployment', () => {
    expect(remedyForKmod({ modulesFound: 12, callSitePassAvailable: true, symbolTableUnreadable: 3 })).toBe('settled');
  });
});

describe('extraction that recovered no rootfs', () => {
  it('settles volumes that came out and hold no rootfs', () => {
    expect(remedyForNoRootfs({ isDecoy: false, diagnosed: true, volumes: 81, unopenedBlobs: 0 })).toBe('settled');
  });

  it('names a hollow image as needing different bytes', () => {
    expect(remedyForNoRootfs({ isDecoy: true, diagnosed: true, volumes: 0, unopenedBlobs: 0 })).toBe('reacquire-input');
  });

  it('requests different bytes when the SquashFS metadata proves the carve is truncated', () => {
    expect(
      remedyForNoRootfs({
        isDecoy: false,
        diagnosed: true,
        volumes: 0,
        unopenedBlobs: 1,
        blobs: [{ short: true, idTableInZeroFill: false }],
      }),
    ).toBe('reacquire-input');
  });

  it('declares nothing when a carved filesystem could not be opened', () => {
    // An extractor gap and a truncated volume arrive here identically; guessing would put one of them in a queue
    // that cannot fix it.
    expect(remedyForNoRootfs({ isDecoy: false, diagnosed: true, volumes: 1, unopenedBlobs: 1 })).toBeUndefined();
    expect(remedyForNoRootfs({ isDecoy: false, diagnosed: false, volumes: 0, unopenedBlobs: 0 })).toBeUndefined();
  });
});

describe("the SBOM lane's CVE half", () => {
  it('queues a grype that ran and threw for a retry', () => {
    expect(remedyForGrypeOutcome('run_failed')).toBe('retry');
  });

  it('keeps a missing binary and an unprovisioned database on the deployment', () => {
    expect(remedyForGrypeOutcome('tool_absent')).toBe('install-tool');
    expect(remedyForGrypeOutcome('db_absent')).toBe('install-tool');
  });

  it('declares nothing for a grype that answered, or for a result stored before the discriminant existed', () => {
    expect(remedyForGrypeOutcome('matched')).toBeUndefined();
    expect(remedyForGrypeOutcome(undefined)).toBeUndefined();
  });

  it('separates the executable retry from the deployment chore the three used to share', () => {
    // The defect: all three `grypeAvailable:false` cases were `install-tool`, so a campaign never re-ran a broken
    // execution and reported it as something an operator had to go and fix.
    expect(isExecutableRemedy(remedyForGrypeOutcome('run_failed'))).toBe(true);
    expect(remedyForGrypeOutcome('run_failed')).not.toBe(remedyForGrypeOutcome('db_absent'));
  });
});
