/**
 * Findings report route. Serves a self-contained HTML report for an image as a downloadable attachment.
 */
import type { FastifyInstance } from 'fastify';
import { generateReport } from '../providers/report.js';

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
}
