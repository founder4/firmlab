import { describe, expect, it } from 'vitest';
import { type ExtractJobFacts, type RootfsStage, gateOnRootfs, rootfsGateBody } from './rootfs-gate.js';

const SBOM: RootfsStage = { stage: 'sbom', needs: 'SBOM scanning' };

/** A job row as `listJobs` hands it over — only the four fields the decision reads. */
function job(partial: Partial<ExtractJobFacts> & { status: string }): ExtractJobFacts {
  return { kind: 'extract', error: null, resultJson: null, ...partial };
}

/** The stored ExtractResult of Xiaomi-Repeater_2023 (`d3dc23fe`), trimmed to the fields the gate reads. */
const XIAOMI_RESULT = JSON.stringify({
  extractor: 'binwalk',
  outputDir: '/data/extract/d3dc23fe',
  rootfsPath: null,
  tree: null,
  summary: null,
  noRootfsDiagnosis: {
    verdict:
      '112460.7z: A raw LZMA stream of 973728 bytes, declaring 2175968 bytes uncompressed, was carved and never unpacked — binwalk names these `.7z` and does not always recurse into them. The payload is UNEXAMINED, which is not the same as absent.',
    volumes: [],
    totalFiles: 0,
    blobs: [],
  },
});

describe('gateOnRootfs — a rootfs that is there', () => {
  it('passes the rootfs through when a completed extraction produced one', () => {
    const gate = gateOnRootfs(SBOM, [
      job({ status: 'done', resultJson: '{"rootfsPath":"/data/extract/x/squashfs-root"}' }),
    ]);
    expect(gate).toEqual({ ok: true, state: 'ready', rootfsPath: '/data/extract/x/squashfs-root' });
  });

  it('ignores jobs of other kinds entirely', () => {
    const gate = gateOnRootfs(SBOM, [
      job({ kind: 'sbom', status: 'done', resultJson: '{"rootfsPath":"/nope"}' }),
      job({ status: 'done', resultJson: '{"rootfsPath":"/data/extract/x/squashfs-root"}' }),
    ]);
    expect(gate.ok && gate.rootfsPath).toBe('/data/extract/x/squashfs-root');
  });

  /**
   * The order of the two questions is the one behaviour this must not lose. `listJobs` is newest-first, so reading
   * the newest extract job first would refuse a rootfs that is sitting on disk and perfectly readable, because a
   * later re-run happened to fail. A recovered rootfs stays usable however the next attempt went.
   */
  it('still runs off an older successful extraction when a newer attempt failed', () => {
    const gate = gateOnRootfs(SBOM, [
      job({ status: 'error', error: 'binwalk exited 1' }),
      job({ status: 'done', resultJson: '{"rootfsPath":"/data/extract/x/squashfs-root"}' }),
    ]);
    expect(gate.ok && gate.rootfsPath).toBe('/data/extract/x/squashfs-root');
  });
});

describe('gateOnRootfs — the four ways there is no rootfs', () => {
  it('tells an operator with no extract job at all to run extraction, in the old words', () => {
    const gate = gateOnRootfs(SBOM, []);
    expect(gate.ok).toBe(false);
    if (gate.ok) return;
    expect(gate.state).toBe('extraction-not-run');
    expect(gate.status).toBe(400);
    expect(gate.error).toContain('Run extraction first — SBOM scanning needs an extracted rootfs');
    expect(gate.extractionJobStatus).toBeNull();
    expect(gate.retryable).toBe(true);
  });

  /** The old guard only looked at `status = 'done'`, so a running extraction read as one nobody had started. */
  it.each(['queued', 'running'])('reports an extraction that is still %s as a wait, not a missing step', (status) => {
    const gate = gateOnRootfs(SBOM, [job({ status })]);
    expect(gate.ok).toBe(false);
    if (gate.ok) return;
    expect(gate.state).toBe('extraction-in-progress');
    expect(gate.status).toBe(409);
    expect(gate.error).toContain('still running');
    expect(gate.error).not.toContain('Run extraction first');
    expect(gate.extractionJobStatus).toBe(status);
    expect(gate.retryable).toBe(true);
  });

  it('reports a failed extraction as a bench failure and carries the job error', () => {
    const gate = gateOnRootfs(SBOM, [job({ status: 'error', error: 'binwalk not found on PATH' })]);
    expect(gate.ok).toBe(false);
    if (gate.ok) return;
    expect(gate.state).toBe('extraction-failed');
    expect(gate.status).toBe(409);
    expect(gate.error).toContain('binwalk not found on PATH');
    expect(gate.error).toContain('NOT a property of the firmware');
    expect(gate.error).not.toContain('Run extraction first');
    expect(gate.extractionError).toBe('binwalk not found on PATH');
    expect(gate.retryable).toBe(true);
  });

  /**
   * A job's error text is written by whatever failed, and binwalk's does not end in a period. The first real run
   * of this module against the corpus produced `…unsquashfs not on PATH SBOM scanning cannot read…` — two
   * sentences run together — which no unit test had asked about because none of them read the whole paragraph.
   */
  it('terminates the quoted job error exactly once, whatever punctuation it came with', () => {
    const bare = gateOnRootfs(SBOM, [job({ status: 'error', error: 'extractor unsquashfs not on PATH' })]);
    expect(bare.ok).toBe(false);
    if (bare.ok) return;
    expect(bare.error).toContain('extractor unsquashfs not on PATH. There is no rootfs');

    const punctuated = gateOnRootfs(SBOM, [job({ status: 'error', error: 'timed out after 600s.' })]);
    expect(punctuated.ok).toBe(false);
    if (punctuated.ok) return;
    expect(punctuated.error).toContain('timed out after 600s. There is no rootfs');
    expect(punctuated.error).not.toContain('..');
  });

  /**
   * A `done` row with no readable result is a hole in the RECORD. Folding it into "found no rootfs" would state a
   * measurement nothing measured — the same over-claim in the opposite direction from the bug being fixed.
   */
  it.each([null, '', 'not json at all'])('refuses to claim "no rootfs" from an unreadable result (%s)', (stored) => {
    const gate = gateOnRootfs(SBOM, [job({ status: 'done', resultJson: stored })]);
    expect(gate.ok).toBe(false);
    if (gate.ok) return;
    expect(gate.state).toBe('extraction-result-missing');
    expect(gate.status).toBe(409);
    expect(gate.error).toContain('unknown');
    expect(gate.error).not.toContain('Run extraction first');
    expect(gate.extractionJobStatus).toBe('done');
  });

  /**
   * The measured defect, with the bytes the deployed container actually holds for `d3dc23fe`: extraction ran,
   * completed, and recorded WHY there is no rootfs. Being told to run extraction was a loop.
   */
  it('reports a completed extraction with no rootfs as a measured property, carrying its diagnosis', () => {
    const gate = gateOnRootfs(SBOM, [job({ status: 'done', resultJson: XIAOMI_RESULT })]);
    expect(gate.ok).toBe(false);
    if (gate.ok) return;
    expect(gate.state).toBe('extraction-found-no-rootfs');
    expect(gate.status).toBe(422);
    expect(gate.error).not.toContain('Run extraction first');
    expect(gate.error).toContain('Extraction ran, completed, and found no Linux rootfs');
    // Not a step you skipped, and not a clean result either — both halves have to be said.
    expect(gate.error).toContain('not a step you skipped');
    expect(gate.error).toContain('not a clean result');
    // The diagnosis extraction already produced, verbatim rather than paraphrased.
    expect(gate.error).toContain('A raw LZMA stream of 973728 bytes, declaring 2175968 bytes uncompressed');
    expect(gate.extractionDiagnosis).toContain('was carved and never unpacked');
    expect(gate.retryable).toBe(false);
  });

  /**
   * A stored result is data written by an OLDER build, and every extraction stored before `extract-diagnose.ts`
   * existed carries no diagnosis at all. Saying nothing there would imply the extractor had nothing to report.
   */
  it('says the diagnosis is MISSING when the stored result predates it, rather than implying there was none', () => {
    const gate = gateOnRootfs(SBOM, [job({ status: 'done', resultJson: '{"rootfsPath":null}' })]);
    expect(gate.ok).toBe(false);
    if (gate.ok) return;
    expect(gate.state).toBe('extraction-found-no-rootfs');
    expect(gate.error).toContain('recorded no diagnosis');
    expect(gate.error).toContain('unknown rather than answered');
    expect(gate.extractionDiagnosis).toBeUndefined();
  });
});

describe('gateOnRootfs — the wording each stage owns', () => {
  it('names the stage that was refused, not a generic one', () => {
    const compmap = gateOnRootfs({ stage: 'compmap', needs: 'the component map' }, []);
    expect(compmap.ok).toBe(false);
    if (compmap.ok) return;
    expect(compmap.error).toContain('the component map needs an extracted rootfs');
    expect(compmap.stage).toBe('compmap');
  });

  /** yarascan and credmatch each carried a sentence worth keeping; it belongs to the stage, not to one state. */
  it('appends a stage note to every state, not just the one it was written under', () => {
    const stage: RootfsStage = {
      stage: 'yarascan',
      needs: 'the rule-based scan',
      note: 'Nothing was scanned, which is not the same as nothing being found.',
    };
    for (const jobs of [[], [job({ status: 'running' })], [job({ status: 'done', resultJson: XIAOMI_RESULT })]]) {
      const gate = gateOnRootfs(stage, jobs);
      expect(gate.ok).toBe(false);
      if (gate.ok) continue;
      expect(gate.error).toContain('Nothing was scanned, which is not the same as nothing being found.');
    }
  });
});

describe('rootfsGateBody', () => {
  /**
   * `error` is the only field the web client and the MCP client read today, so the body has to be honest with that
   * field alone; everything else is additive. A body whose `error` were a stub would render as a blank panel, which
   * is exactly what "clean" looks like.
   */
  it('leads with the whole sentence and adds the structure beside it', () => {
    const gate = gateOnRootfs(SBOM, [job({ status: 'done', resultJson: XIAOMI_RESULT })]);
    expect(gate.ok).toBe(false);
    if (gate.ok) return;
    const body = rootfsGateBody(gate);
    expect(body.error).toBe(gate.error);
    expect(body.state).toBe('extraction-found-no-rootfs');
    expect(body.stage).toBe('sbom');
    expect(body.extractionJobStatus).toBe('done');
    expect(body.retryable).toBe(false);
    expect(String(body.extractionDiagnosis)).toContain('never unpacked');
    expect(body).not.toHaveProperty('extractionError');
  });

  it('omits the extraction error when there was not one', () => {
    const gate = gateOnRootfs(SBOM, []);
    expect(gate.ok).toBe(false);
    if (gate.ok) return;
    const body = rootfsGateBody(gate);
    expect(body).not.toHaveProperty('extractionError');
    expect(body).not.toHaveProperty('extractionDiagnosis');
    expect(body.extractionJobStatus).toBeNull();
  });
});
