/**
 * Report routes. Serve (1) the self-contained HTML analysis report and (2) a coordinated-disclosure Markdown draft,
 * both as downloadable attachments. The disclosure draft is assembled from the confirmed findings plus whatever the
 * research track discovered (provenance, security contact, KEV context) — a draft the operator reviews and sends.
 */
import type { ImageIdentity } from '@firmlab/core';
import type { FastifyInstance } from 'fastify';
import { rowToFinding } from '../findings.js';
import { buildDisclosureReport } from '../providers/disclosure.js';
import { generateReport } from '../providers/report.js';
import { getImage, listFindings, listJobs } from '../store.js';

/** Latest successful research result (provenance + security contacts + KEV matches), or null. */
function latestResearch(imageId: string): {
  provenance?: { vendors: string[]; models: string[]; versions: string[] };
  securityContacts?: { domain: string; checked: boolean; found: boolean; contact: string[] }[];
  kev?: { matches?: { cveID: string; product: string }[] };
} | null {
  const done = listJobs(imageId).find((j) => j.kind === 'research' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  try {
    return JSON.parse(done.resultJson);
  } catch {
    return null;
  }
}

export async function reportRoutes(app: FastifyInstance): Promise<void> {
  app.get('/images/:id/report', async (req, reply) => {
    const { id } = req.params as { id: string };
    const html = generateReport(id);
    if (html === null) return reply.status(404).send({ error: 'Image not found' });
    return reply
      .header('content-type', 'text/html; charset=utf-8')
      .header('content-disposition', `attachment; filename="firmlab-report-${id}.html"`)
      .send(html);
  });

  app.get('/images/:id/disclosure-report', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const research = latestResearch(id);
    const identity: ImageIdentity | null = row.identityJson ? JSON.parse(row.identityJson) : null;
    const md = buildDisclosureReport({
      image: { filename: row.filename, sha256: row.sha256 },
      identity,
      findings: listFindings(id).map(rowToFinding),
      ...(research?.provenance ? { provenance: research.provenance } : {}),
      ...(research?.securityContacts ? { securityContacts: research.securityContacts } : {}),
      ...(research?.kev?.matches ? { kevMatches: research.kev.matches } : {}),
      generatedAt: new Date().toISOString(),
    });
    return reply
      .header('content-type', 'text/markdown; charset=utf-8')
      .header('content-disposition', `attachment; filename="firmlab-disclosure-${id}.md"`)
      .send(md);
  });
}
