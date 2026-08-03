/**
 * Why a rootfs-backed stage cannot run — the verdict a route has to give instead of `Run extraction first`.
 *
 * Measured 2026-08-03 on both Xiaomi eCos images in the deployed corpus (`d3dc23fe`, `550b279d`): extraction had
 * run, completed, and recorded its diagnosis — *"A raw LZMA stream of 973728 bytes, declaring 2175968 bytes
 * uncompressed, was carved and never unpacked"* — and `sbom`, `gitleaks`, `fsaudit`, `compmap` and `services` all
 * answered `400 {"error":"Run extraction first — …"}`. Extraction is not what was missing. A **rootfs** was, and it
 * was missing as a MEASURED property with a diagnosis already computed and stored on the job row. Telling an
 * operator to run a stage that already ran sends them in a circle, and it is the same conflation that had already
 * been fixed one layer up in the web's `section-index.ts` while surviving here in the route guards.
 *
 * So `rootfsPath: null` gets the `extract-diagnose.ts` treatment: one null covering situations that need different
 * responses is split into the states that actually differ on the job ledger.
 *
 *  • **No extract job at all.** "Run extraction" is the correct instruction, and this is the only case where it is.
 *  • **Extraction queued or running.** Not a missing step and not a finished answer — a wait. The old guard read a
 *    running extraction as one that had never started, because it only looked at `status = 'done'`.
 *  • **Extraction failed.** A broken run, which is a statement about this bench (a tool, a timeout, a disk), never
 *    about the firmware. The operator reads the job log and re-runs.
 *  • **Extraction is marked done and stored no readable result.** Also a bench defect, and deliberately NOT folded
 *    into "found no rootfs": we do not know what that run found, so claiming the image has no rootfs would be
 *    inventing a measurement out of a lost record.
 *  • **Extraction ran, completed, and produced no rootfs.** A measured property of the image, carrying the
 *    diagnosis extraction already produced. This must not read as "you forgot a step", and it must not read as a
 *    negative about the firmware either — the stage is inapplicable, and inapplicable is not clean.
 *
 * **The HTTP shape, and why it stays outside 2xx.** A 400 whose body says "you already did this" is still a 400, so
 * the honest alternative was considered: answer 200 with a result saying the stage cannot run. It was rejected, and
 * on evidence rather than taste. Every caller of these endpoints — the web's `post<{jobId}>` in `apps/web/src/api.ts`
 * and the MCP server's `FirmLabClient.runJob` — reads `{ jobId }` out of a 2xx and then polls that job. A 200 with
 * no job id makes `AnalysisActionsPanel` poll `undefined` forever: the card spins, no error is ever raised, and the
 * panel renders EMPTY — which is precisely the "looks clean" failure this module exists to prevent. Returning a
 * fabricated provider-result shape from a route that ran no provider would be worse still: it would write a claim
 * about the image that no code measured.
 *
 * The honesty therefore goes into the body and into WHICH status, one meaning per code, identical across every
 * route that binds this:
 *
 *  • **400** — a precondition the caller can satisfy right now: no extraction has been asked for. Unchanged from
 *    before, wording included, because this is the one case the old guard got right.
 *  • **409** — the extraction is in a state that conflicts with the request and that state can change: running,
 *    failed, or recorded without a result. Wait, or fix and re-run, then retry unchanged.
 *  • **422** — understood, well-formed, and unprocessable for THIS image: extraction completed and there is no
 *    rootfs. Retrying this stage cannot change the answer; only an extraction that recovers a rootfs would.
 *
 * The status is decided here, next to the sentence, so five routes cannot drift into five opinions about it.
 *
 * Pure and store-free: it takes job rows as plain structural data and returns a verdict, so the wording and the
 * status are unit-tested rather than confirmed by eye. (A module that imports `store.js` cannot be unit-tested at
 * all here — vitest cannot resolve `node:sqlite`.)
 */

/** The fields of a job row this decision reads. Structural on purpose — nothing here imports the store. */
export interface ExtractJobFacts {
  kind: string;
  status: string;
  error?: string | null;
  resultJson?: string | null;
}

/** What a stage needs the rootfs FOR, as the phrase that completes "… needs an extracted rootfs". */
export interface RootfsStage {
  /** The job kind / route segment, so a structured consumer can say which stage was refused. */
  stage: string;
  /** Lower-case noun phrase naming the work: `SBOM scanning`, `the component map`. */
  needs: string;
  /**
   * An extra sentence appended to every refusal for this stage. Where a route already carried one worth keeping —
   * yarascan's "Nothing was scanned, which is not the same as nothing being found" — it belongs to the stage, not
   * to one of the five states.
   */
  note?: string;
}

export type RootfsGateState =
  | 'ready'
  | 'extraction-not-run'
  | 'extraction-in-progress'
  | 'extraction-failed'
  | 'extraction-result-missing'
  | 'extraction-found-no-rootfs';

/** HTTP status per blocked state. One meaning per code — see the module doc. */
export type RootfsGateStatus = 400 | 409 | 422;

export interface RootfsGateBlocked {
  ok: false;
  state: Exclude<RootfsGateState, 'ready'>;
  status: RootfsGateStatus;
  /**
   * The composed sentence. Sent as `error` by every route that binds this, because every existing caller renders
   * that field and nothing else — the structured fields below are additive, and the body has to be honest without
   * them.
   */
  error: string;
  /** The stage that was refused, by job kind. */
  stage: string;
  /** Status of the extract job the verdict was read from; null when there is no extract job at all. */
  extractionJobStatus: 'queued' | 'running' | 'done' | 'error' | null;
  /**
   * `noRootfsDiagnosis.verdict` off the stored `ExtractResult`, verbatim, when that run recorded one. Optional
   * forever: a stored result is data written by an OLDER build, and every extraction stored before
   * `extract-diagnose.ts` existed carries none. Absent means "no diagnosis was recorded", never "nothing to say".
   */
  extractionDiagnosis?: string;
  /** The extract job's own error text, when it failed. */
  extractionError?: string;
  /**
   * True when running this stage again, unchanged, could produce a different answer once the operator acts. False
   * for `extraction-found-no-rootfs`: that is a property of the image, and retrying the STAGE cannot move it.
   */
  retryable: boolean;
}

export interface RootfsGateReady {
  ok: true;
  state: 'ready';
  rootfsPath: string;
}

export type RootfsGate = RootfsGateReady | RootfsGateBlocked;

/** Job statuses, narrowed from the row's free-form string. */
function narrowStatus(status: string): 'queued' | 'running' | 'done' | 'error' | null {
  return status === 'queued' || status === 'running' || status === 'done' || status === 'error' ? status : null;
}

/** The rootfs path a stored extract result claims, or null — including when the result is unparseable. */
function rootfsOf(resultJson: string | null | undefined): string | null {
  if (!resultJson) return null;
  try {
    const parsed = JSON.parse(resultJson) as { rootfsPath?: string | null };
    return parsed.rootfsPath ?? null;
  } catch {
    return null;
  }
}

/** The `noRootfsDiagnosis.verdict` a stored extract result carries, if any. */
function diagnosisOf(resultJson: string | null | undefined): string | undefined {
  if (!resultJson) return undefined;
  try {
    const parsed = JSON.parse(resultJson) as { noRootfsDiagnosis?: { verdict?: string } };
    const verdict = parsed.noRootfsDiagnosis?.verdict;
    return typeof verdict === 'string' && verdict.length > 0 ? verdict : undefined;
  } catch {
    return undefined;
  }
}

/** Did this done job store something JSON-parseable at all? A `done` row with no record is its own state. */
function hasReadableResult(resultJson: string | null | undefined): boolean {
  if (!resultJson) return false;
  try {
    return typeof JSON.parse(resultJson) === 'object';
  } catch {
    return false;
  }
}

/** Append the stage's standing note, when it has one. */
function withNote(sentence: string, stage: RootfsStage): string {
  return stage.note ? `${sentence} ${stage.note}` : sentence;
}

/**
 * End a quoted fragment so the sentence after it starts cleanly.
 *
 * A job's error text is written by whatever failed and is not punctuation-terminated: interpolating binwalk's
 * `extractor unsquashfs not on PATH` straight into a paragraph ran it into the next sentence, which is how the
 * first real run of this module read. Adding a period unconditionally would produce `…on PATH..` for the errors
 * that do end in one.
 */
function terminate(fragment: string): string {
  return /[.!?]$/.test(fragment.trimEnd()) ? fragment.trimEnd() : `${fragment.trimEnd()}.`;
}

/**
 * Pure: decide whether a rootfs-backed stage can run, and if not, say which of the five reasons it is.
 *
 * `jobs` is the image's job list as `listJobs` returns it — **newest first**. The extract jobs are filtered here
 * rather than by the caller so that all five routes read the ledger by the same rule.
 *
 * The order of the two questions matters and preserves what the old guard could do: a rootfs recovered by ANY
 * completed extraction is still on disk and still usable, so that is checked first. Only when no extraction ever
 * produced one does the newest extract job get to explain why. Reading the newest job first instead would refuse a
 * perfectly good rootfs because a later re-run happened to fail.
 */
export function gateOnRootfs(stage: RootfsStage, jobs: readonly ExtractJobFacts[]): RootfsGate {
  const extracts = jobs.filter((j) => j.kind === 'extract');

  for (const job of extracts) {
    if (job.status !== 'done') continue;
    const rootfsPath = rootfsOf(job.resultJson);
    if (rootfsPath) return { ok: true, state: 'ready', rootfsPath };
  }

  const latest = extracts[0];
  if (!latest) {
    return {
      ok: false,
      state: 'extraction-not-run',
      status: 400,
      // Kept word for word, because this is the one situation in which it was already true.
      error: withNote(
        `Run extraction first — ${stage.needs} needs an extracted rootfs. No extraction job has run for this image, so nothing has been carved to read.`,
        stage,
      ),
      stage: stage.stage,
      extractionJobStatus: null,
      retryable: true,
    };
  }

  const status = narrowStatus(latest.status);

  if (status === 'queued' || status === 'running') {
    return {
      ok: false,
      state: 'extraction-in-progress',
      status: 409,
      error: withNote(
        `Extraction is still running for this image, so there is no completed carve for ${stage.needs} to read yet. Wait for that job to finish and run this stage again — extraction has neither failed nor been skipped.`,
        stage,
      ),
      stage: stage.stage,
      extractionJobStatus: status,
      retryable: true,
    };
  }

  if (status === 'error') {
    const jobError = latest.error ?? undefined;
    return {
      ok: false,
      state: 'extraction-failed',
      status: 409,
      error: withNote(
        `Extraction FAILED for this image${jobError ? `: ${terminate(jobError)}` : '.'} There is no rootfs for ${stage.needs} to read, because the failed run never finished writing one. That is a broken extraction on this bench — a tool, a timeout, a disk — and NOT a property of the firmware: nothing has been established about what this image contains. Read the extract job's log, fix what it names, and re-run extraction.`,
        stage,
      ),
      stage: stage.stage,
      extractionJobStatus: 'error',
      ...(jobError ? { extractionError: jobError } : {}),
      retryable: true,
    };
  }

  if (!hasReadableResult(latest.resultJson)) {
    return {
      ok: false,
      state: 'extraction-result-missing',
      status: 409,
      error: withNote(
        `The most recent extraction for this image is recorded as finished but stored no readable result, so whether it found a rootfs is unknown and there is nothing to point ${stage.needs} at. This is a gap in the record on this bench, not a measurement of the image — it deliberately does not say "no rootfs", because nothing here measured that. Re-run extraction to get an answer.`,
        stage,
      ),
      stage: stage.stage,
      extractionJobStatus: 'done',
      retryable: true,
    };
  }

  const diagnosis = diagnosisOf(latest.resultJson);
  const why = diagnosis
    ? `Extraction's own diagnosis of the missing rootfs: ${diagnosis}`
    : 'Extraction recorded no diagnosis of the missing rootfs — that run predates the diagnosis, so WHY there is no rootfs is unknown rather than answered. Re-run extraction to find out.';
  return {
    ok: false,
    state: 'extraction-found-no-rootfs',
    status: 422,
    error: withNote(
      `Extraction ran, completed, and found no Linux rootfs in this image, so ${stage.needs} has nothing to read. This is not a step you skipped — extraction already ran — and it is not a clean result for the firmware either: the stage is inapplicable to this image, and inapplicable is not the same as nothing being found. Re-running this stage cannot change the answer; only an extraction that recovers a rootfs would. ${why}`,
      stage,
    ),
    stage: stage.stage,
    extractionJobStatus: 'done',
    ...(diagnosis ? { extractionDiagnosis: diagnosis } : {}),
    retryable: false,
  };
}

/**
 * The response body a route sends for a blocked gate.
 *
 * `error` first and always: it is the only field the web client and the MCP client read today, so it carries the
 * whole sentence. The rest is additive structure for a caller that wants to branch on the state rather than parse
 * prose — and, for `extraction-found-no-rootfs`, the diagnosis extraction produced, unedited.
 */
export function rootfsGateBody(blocked: RootfsGateBlocked): Record<string, unknown> {
  return {
    error: blocked.error,
    state: blocked.state,
    stage: blocked.stage,
    extractionJobStatus: blocked.extractionJobStatus,
    retryable: blocked.retryable,
    ...(blocked.extractionDiagnosis ? { extractionDiagnosis: blocked.extractionDiagnosis } : {}),
    ...(blocked.extractionError ? { extractionError: blocked.extractionError } : {}),
  };
}
