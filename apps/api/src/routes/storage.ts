/**
 * Storage usage endpoint — reports how much of the data volume the images + carved rootfs occupy, plus the
 * configured retention limits, so the UI can surface usage and the operator can spot an over-full volume.
 *
 * The research advisory cache is reported alongside them. It is the one directory under the data root that grows
 * without an image behind it — which is why it has eviction caps of its own — so a usage view that omitted it
 * would attribute a full volume entirely to firmware. It is measured, never swept: a GET here deletes nothing,
 * and when the bounded walk truncates the figure comes back labelled as a floor rather than as the total.
 */
import type { FastifyInstance } from 'fastify';
import { storageUsage } from '../retention.js';

export async function storageRoutes(app: FastifyInstance): Promise<void> {
  app.get('/storage', async () => ({ usage: storageUsage() }));
}
