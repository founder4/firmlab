import { describe, expect, it } from 'vitest';
import { parseFlowManifest } from './flow-manifest.js';

describe('parseFlowManifest', () => {
  const sample = [
    '{"id":"f1","host":"cdn.x.com","url":"https://cdn.x.com/ota/fw.bin","method":"GET","status":200,"contentType":"application/octet-stream","contentLength":2097152,"tls":"tls-unpinned","body":"bodies/f1.bin"}',
    '', // blank line tolerated
    'not json at all', // malformed line skipped
    '{"host":"y.com"}', // missing id/url skipped
    '{"id":"f2","url":"https://y.com/status","method":"GET","status":200,"contentType":"application/json","contentLength":40,"tls":"tls-unpinned","body":null}',
  ].join('\n');

  it('parses well-formed flow records', () => {
    const flows = parseFlowManifest(sample);
    expect(flows).toHaveLength(2);
    expect(flows[0]).toMatchObject({
      id: 'f1',
      url: 'https://cdn.x.com/ota/fw.bin',
      contentLength: 2097152,
      tls: 'tls-unpinned',
      body: 'bodies/f1.bin',
    });
  });

  it('skips blank, malformed, and id/url-less lines', () => {
    const flows = parseFlowManifest(sample);
    expect(flows.map((f) => f.id)).toEqual(['f1', 'f2']);
    expect(flows[1]?.body).toBeNull();
  });

  it('normalizes an unknown tls value to null and defaults a missing method to GET', () => {
    const flows = parseFlowManifest('{"id":"f3","url":"http://z/fw","tls":"weird","contentLength":10}');
    expect(flows[0]?.tls).toBeNull();
    expect(flows[0]?.method).toBe('GET');
  });
});
