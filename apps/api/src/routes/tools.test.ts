import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { toolRoutes } from './tools.js';

vi.mock('../tools.js', () => ({
  detectTools: vi.fn().mockResolvedValue([]),
}));

interface PlanResponse {
  plans: Array<{
    classId: string;
    stages: Array<{ worker: string; reason: string; built: boolean; provider?: string }>;
  }>;
}

describe('GET /tools — pre-run class capability plans', () => {
  it('exposes distinct embedded Linux, UEFI and RTOS routes from the opacidad plan', async () => {
    const app = Fastify();
    await app.register(toolRoutes);

    const response = await app.inject({ method: 'GET', url: '/tools' });
    const body = response.json<PlanResponse>();

    expect(response.statusCode).toBe(200);
    expect(body.plans).toHaveLength(9);

    const linux = body.plans.find((plan) => plan.classId === 'embedded-linux');
    const uefi = body.plans.find((plan) => plan.classId === 'uefi-bios');
    const rtos = body.plans.find((plan) => plan.classId === 'rtos');
    expect(linux?.stages.map((stage) => stage.provider)).toContain('sbom');
    expect(uefi?.stages.map((stage) => stage.provider)).toContain('chipsec');
    expect(rtos?.stages.map((stage) => stage.provider)).toContain('rtos');
    expect(new Set([linux, uefi, rtos].map((plan) => plan?.stages.map((stage) => stage.provider).join(','))).size).toBe(
      3,
    );

    await app.close();
  });

  it('localises the reasons without changing routing or built state', async () => {
    const app = Fastify();
    await app.register(toolRoutes);

    const [englishResponse, spanishResponse] = await Promise.all([
      app.inject({ method: 'GET', url: '/tools' }),
      app.inject({ method: 'GET', url: '/tools?lang=es' }),
    ]);
    const english = englishResponse.json<PlanResponse>().plans;
    const spanish = spanishResponse.json<PlanResponse>().plans;

    expect(
      spanish.map(({ classId, stages }) => ({
        classId,
        stages: stages.map(({ worker, built, provider }) => ({ worker, built, provider })),
      })),
    ).toEqual(
      english.map(({ classId, stages }) => ({
        classId,
        stages: stages.map(({ worker, built, provider }) => ({ worker, built, provider })),
      })),
    );
    expect(spanish[0]?.stages[0]?.reason).not.toBe(english[0]?.stages[0]?.reason);

    await app.close();
  });
});
