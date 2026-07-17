/**
 * Storage usage endpoint — reports how much of the data volume the images + carved rootfs occupy, plus the
 * configured retention limits, so the UI can surface usage and the operator can spot an over-full volume.
 */
import type { FastifyInstance } from 'fastify';
import { storageUsage } from '../retention.js';

export async function storageRoutes(app: FastifyInstance): Promise<void> {
  app.get('/storage', async () => ({ usage: storageUsage() }));
}
