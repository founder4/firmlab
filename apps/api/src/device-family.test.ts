import { describe, expect, it } from 'vitest';
import { deviceFamilyKey } from './device-family.js';

describe('deviceFamilyKey', () => {
  it('shares an evidenced vendor across image versions', () => {
    const identity = { vendor: 'Acme Networks, Inc.', firmwareClass: 'embedded-linux', arch: 'mips' } as const;
    expect(deviceFamilyKey(identity, 'image-a')).toBe('acme-networks-inc:embedded-linux:mips');
    expect(deviceFamilyKey(identity, 'image-b')).toBe('acme-networks-inc:embedded-linux:mips');
  });

  it('never groups unrelated images merely because vendor is unknown', () => {
    const identity = { firmwareClass: 'embedded-linux', arch: 'mips' } as const;
    expect(deviceFamilyKey(identity, 'AAAA')).toBe('image-aaaa:embedded-linux:mips');
    expect(deviceFamilyKey(identity, 'BBBB')).toBe('image-bbbb:embedded-linux:mips');
    expect(deviceFamilyKey(identity, 'AAAA')).not.toBe(deviceFamilyKey(identity, 'BBBB'));
  });
});
