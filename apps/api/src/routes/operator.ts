/**
 * Operator routes — the seam through which something FirmLab did not compute enters the ledger.
 *
 * Three surfaces, deliberately separate:
 *
 *   `/images/:id/operator-findings` — assertions. A named author states something, on a stated basis, using a
 *   vocabulary disjoint from the proof-state ladder (`operator-findings.ts` holds the rules and the argument for
 *   them). Create, amend, withdraw; never delete, because a retraction with its reason is more useful than a gap.
 *   Each of the three names its own actor: nothing here assumes the person editing or retracting a claim is the
 *   person who made it, because on this surface most often they are not.
 *
 *   `/images/:id/notes` — a working scratchpad. Reasoning that is not yet a claim, and may never become one:
 *   half-formed hypotheses, "check this next", the thread an agent picks up in a later session. Notes live in
 *   their OWN table rather than as a finding kind, so no query that reads findings can pick one up by accident —
 *   the separation is structural, not a filter someone has to remember to apply.
 *
 *   `DELETE /images/:id/findings` — retirement of one COMPUTED source. It lives here rather than beside the
 *   findings GET because it needs exactly what this file already is: a named author, a stated reason, and the note
 *   table. The asymmetry with the first surface is the design and not an inconsistency — an assertion is somebody's
 *   claim and is retracted; a provider row is a computation and is re-derivable, so removing it loses nothing a
 *   re-run cannot restore. `findings-retire.ts` carries the argument.
 *
 * `authorKind` is set by the transport, never by the request body. The web sends `human`, `mcp/server.ts` sends
 * `agent`, and neither can claim to be the other. That is what makes the read-back caveat in `mcp/format.ts`
 * ("an assertion you recorded yourself is not corroboration of the claim you recorded it for") a fact about the
 * data rather than a hope about the caller.
 *
 * What these routes refuse: to accept a `proofState`, to promote an assertion onto the ladder, to let an
 * assertion count as stage coverage, and to delete one.
 */
import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { describeRetirement, validateRetirement } from '../findings-retire.js';
import {
  amendOperatorFinding,
  loadOperatorFinding,
  recordOperatorFinding,
  retireFindings,
  rowToFinding,
  withdrawOperatorFinding,
} from '../findings.js';
import {
  CLAIM_MEANING,
  NOT_A_MEASUREMENT,
  type OperatorAssertionInput,
  authorKindOf,
  describeAssertion,
  partitionByProvenance,
  validateAssertion,
} from '../operator-findings.js';
import {
  deleteImageNote,
  getImage,
  getImageNote,
  insertImageNote,
  listFindings,
  listImageNotes,
  updateImageNote,
} from '../store.js';

const MAX_NOTE = 20000;
const MAX_NOTE_AUTHOR = 80;

export async function operatorRoutes(app: FastifyInstance): Promise<void> {
  /**
   * The operator ledger for one image, partitioned. Active assertions and withdrawn ones are returned in separate
   * arrays because a withdrawn claim must never be summed into a total, and returning one flat list with a status
   * field invites exactly that.
   */
  app.get('/images/:id/operator-findings', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const { asserted, withdrawn, measured } = partitionByProvenance(listFindings(id).map(rowToFinding));
    return {
      notAMeasurement: NOT_A_MEASUREMENT,
      claimMeanings: CLAIM_MEANING,
      /** Measured findings on this image, for context only — this route does not serve them. */
      measuredFindingCount: measured.length,
      assertions: asserted.map((f) => ({ ...f, attribution: f.assertion ? describeAssertion(f.assertion) : '' })),
      withdrawn: withdrawn.map((f) => ({ ...f, attribution: f.assertion ? describeAssertion(f.assertion) : '' })),
    };
  });

  app.post('/images/:id/operator-findings', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const parsed = validateAssertion((req.body ?? {}) as OperatorAssertionInput);
    if (!parsed.ok) return reply.status(400).send({ error: parsed.error });

    // A dispute must name a finding that exists on THIS image. An assertion pointing at nothing reads, to every
    // later consumer, exactly like one pointing at something.
    if (parsed.value.disputesFindingId) {
      const target = listFindings(id).find((f) => f.id === parsed.value.disputesFindingId);
      if (!target) {
        return reply
          .status(400)
          .send({ error: `No finding '${parsed.value.disputesFindingId}' on this image — a dispute must name one.` });
      }
    }

    const finding = recordOperatorFinding(id, parsed.value, authorKindOf(req.headers as Record<string, unknown>));
    return reply.status(201).send({
      finding,
      attribution: finding.assertion ? describeAssertion(finding.assertion) : '',
      notAMeasurement: NOT_A_MEASUREMENT,
    });
  });

  /**
   * Amend an assertion. The original author and assertion time are immutable; the claim, its basis — and a second
   * author — move.
   *
   * `amendedBy` is required and comes from the body the way `withdrawnBy` does; `amendedByKind` comes from the
   * transport the way it does on creation, so a request cannot sign its edit as a human. The two halves are
   * deliberately different sources: a name is something a caller states, a kind is something the seam knows.
   */
  app.patch('/images/:id/operator-findings/:findingId', async (req, reply) => {
    const { id, findingId } = req.params as { id: string; findingId: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const loaded = loadOperatorFinding(id, findingId);
    if (!loaded.ok) return reply.status(loaded.status).send({ error: loaded.error });
    if (loaded.assertion.status === 'withdrawn') {
      return reply.status(409).send({
        error:
          'This assertion is withdrawn. A retraction is part of the record and is not edited back into a claim — record a new assertion instead.',
      });
    }
    // assertedBy is carried over, not taken from the body: an edit must not be able to reassign authorship.
    const parsed = validateAssertion({
      ...((req.body ?? {}) as OperatorAssertionInput),
      assertedBy: loaded.assertion.assertedBy,
    });
    if (!parsed.ok) return reply.status(400).send({ error: parsed.error });
    const body = (req.body ?? {}) as { amendedBy?: unknown };
    const amended = amendOperatorFinding(
      loaded.row,
      loaded.assertion,
      parsed.value,
      typeof body.amendedBy === 'string' ? body.amendedBy : '',
      authorKindOf(req.headers as Record<string, unknown>),
    );
    if (!amended.ok) return reply.status(400).send({ error: amended.error });
    const finding = amended.finding;
    return { finding, attribution: finding.assertion ? describeAssertion(finding.assertion) : '' };
  });

  /**
   * Withdraw an assertion. The row stays; it is excluded from every count and rendered as retracted, with who
   * retracted it and why. `docs/BACKLOG.md` holds an entry withdrawn because it had been written from a filename
   * without opening the file — a ledger that could only delete would have kept the wrong claim or lost the lesson.
   */
  app.post('/images/:id/operator-findings/:findingId/withdraw', async (req, reply) => {
    const { id, findingId } = req.params as { id: string; findingId: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const loaded = loadOperatorFinding(id, findingId);
    if (!loaded.ok) return reply.status(loaded.status).send({ error: loaded.error });
    const body = (req.body ?? {}) as { withdrawnBy?: unknown; reason?: unknown };
    const result = withdrawOperatorFinding(
      loaded.row,
      loaded.assertion,
      typeof body.withdrawnBy === 'string' ? body.withdrawnBy : '',
      typeof body.reason === 'string' ? body.reason : '',
    );
    if (!result.ok) return reply.status(400).send({ error: result.error });
    return {
      finding: result.finding,
      attribution: result.finding.assertion ? describeAssertion(result.finding.assertion) : '',
    };
  });

  // === Working notes — explicitly not findings ===

  app.get('/images/:id/notes', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    return {
      notes: listImageNotes(id),
      notFindings:
        'Notes are working reasoning, not claims. They are never counted, never reported, and never rendered as findings. Promote one to an operator assertion when you are ready to stand behind it.',
    };
  });

  app.post('/images/:id/notes', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const body = (req.body ?? {}) as { author?: unknown; body?: unknown };
    const author = typeof body.author === 'string' ? body.author.trim() : '';
    const text = typeof body.body === 'string' ? body.body.trim() : '';
    if (!author) return reply.status(400).send({ error: 'author is required.' });
    if (author.length > MAX_NOTE_AUTHOR) return reply.status(400).send({ error: 'author is too long.' });
    if (!text) return reply.status(400).send({ error: 'body is required — an empty note records nothing.' });
    if (text.length > MAX_NOTE) return reply.status(400).send({ error: `body is longer than ${MAX_NOTE} characters.` });
    const now = Date.now();
    const note = { id: randomUUID().slice(0, 12), imageId: id, author, body: text, createdAt: now, updatedAt: now };
    insertImageNote(note);
    return reply.status(201).send({ note });
  });

  app.patch('/images/:id/notes/:noteId', async (req, reply) => {
    const { id, noteId } = req.params as { id: string; noteId: string };
    const note = getImageNote(noteId);
    if (!note || note.imageId !== id) return reply.status(404).send({ error: 'Note not found' });
    const body = (req.body ?? {}) as { body?: unknown };
    const text = typeof body.body === 'string' ? body.body.trim() : '';
    if (!text) return reply.status(400).send({ error: 'body is required.' });
    if (text.length > MAX_NOTE) return reply.status(400).send({ error: `body is longer than ${MAX_NOTE} characters.` });
    const now = Date.now();
    updateImageNote(noteId, text, now);
    return { note: { ...note, body: text, updatedAt: now } };
  });

  /**
   * Notes CAN be deleted, unlike assertions. A note was never a claim anyone relied on, so nothing is lost by
   * removing it — the asymmetry with withdrawal is the whole reason the two are separate surfaces.
   */
  app.delete('/images/:id/notes/:noteId', async (req, reply) => {
    const { id, noteId } = req.params as { id: string; noteId: string };
    const note = getImageNote(noteId);
    if (!note || note.imageId !== id) return reply.status(404).send({ error: 'Note not found' });
    deleteImageNote(noteId);
    return { deleted: noteId };
  });

  /**
   * Retire one computed source's findings, leaving a note in their place.
   *
   * `{ source, retiredBy, reason }`, all three required, plus `dryRun: true` to see what would go without it
   * going. The reply always carries the full list of what was (or would be) removed — a retirement that matched
   * nothing returns `removed: []` and says so, because a mistyped source silently succeeding is the failure this
   * route is most likely to have.
   *
   * It exists because `syncFindings` can only ever re-sync a source something still PLANS: rows belonging to a
   * question the app has stopped asking have no path out. It is deliberately not a sweep — see `findings-retire.ts`
   * for why "not planned this run" must never be read as "never to be asked again".
   */
  app.delete('/images/:id/findings', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const parsed = validateRetirement(req.body);
    if (!parsed.ok) return reply.status(400).send({ error: parsed.error });
    const dryRun = (req.body as { dryRun?: unknown })?.dryRun === true;
    const { removed, note } = retireFindings(id, parsed.value, dryRun);
    return {
      source: parsed.value.source,
      dryRun,
      removedCount: removed.length,
      removed,
      summary: describeRetirement(parsed.value, removed, dryRun),
      ...(note ? { note } : {}),
    };
  });
}
