import { describe, expect, it } from 'vitest';
import { parseSecurityTxt } from './securitytxt.js';

describe('parseSecurityTxt', () => {
  it('extracts Contact, Policy and Encryption (case-insensitive keys)', () => {
    const s = parseSecurityTxt(
      'acme.com',
      [
        '# our security policy',
        'Contact: mailto:security@acme.com',
        'contact: https://acme.com/report',
        'Policy: https://acme.com/security-policy',
        'ENCRYPTION: https://acme.com/pgp.txt',
        'Expires: 2027-01-01T00:00:00Z',
      ].join('\n'),
    );
    expect(s.contact).toEqual(['mailto:security@acme.com', 'https://acme.com/report']);
    expect(s.policy).toEqual(['https://acme.com/security-policy']);
    expect(s.encryption).toEqual(['https://acme.com/pgp.txt']);
    expect(s.found).toBe(true);
    expect(s.checked).toBe(true);
  });

  it('found is false when there is no Contact line', () => {
    const s = parseSecurityTxt('acme.com', '# nothing actionable here\nExpires: 2027-01-01');
    expect(s.contact).toHaveLength(0);
    expect(s.found).toBe(false);
  });
});
