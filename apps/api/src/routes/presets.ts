/**
 * Saved emulation presets — persist a named, reusable emulation recipe config per image (mode + optional target
 * binary + args), so an operator can re-run a known-good bring-up without re-entering it. Pure persistence: running
 * a preset reuses the existing /emulate + /emulate-system endpoints with the stored config (the web loads a preset
 * and dispatches it), so there is no new execution path here.
 */
import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { type PresetRow, deletePreset, getImage, insertPreset, listPresets } from '../store.js';

const MODES = ['user-qemu', 'chroot-qemu', 'system-qemu', 'renode', 'uefi-chipsec'];

export async function presetsRoutes(app: FastifyInstance): Promise<void> {
  app.get('/images/:id/presets', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    return { presets: listPresets(id).map(toView) };
  });

  app.post('/images/:id/presets', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const body = (req.body ?? {}) as { name?: string; mode?: string; binary?: string; args?: string[] };
    const name = (body.name ?? '').trim();
    if (!name) return reply.status(400).send({ error: 'A preset name is required' });
    if (!body.mode || !MODES.includes(body.mode)) {
      return reply.status(400).send({ error: `mode must be one of: ${MODES.join(', ')}` });
    }
    const row: PresetRow = {
      id: randomUUID().slice(0, 12),
      imageId: id,
      name: name.slice(0, 80),
      mode: body.mode,
      binary: body.binary ? String(body.binary).slice(0, 512) : null,
      argsJson: Array.isArray(body.args) ? JSON.stringify(body.args.map(String).slice(0, 40)) : null,
      createdAt: Date.now(),
    };
    insertPreset(row);
    return reply.status(201).send({ preset: toView(row) });
  });

  app.delete('/presets/:presetId', async (req) => {
    const { presetId } = req.params as { presetId: string };
    deletePreset(presetId);
    return { deleted: presetId };
  });
}

function toView(row: PresetRow): {
  id: string;
  name: string;
  mode: string;
  binary: string | null;
  args: string[];
  createdAt: number;
} {
  return {
    id: row.id,
    name: row.name,
    mode: row.mode,
    binary: row.binary,
    args: row.argsJson ? (JSON.parse(row.argsJson) as string[]) : [],
    createdAt: row.createdAt,
  };
}
