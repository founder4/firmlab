import { describe, expect, it } from 'vitest';
import {
  type UefiIoc,
  type UefiModule,
  loadUefiIocs,
  parseUefiDecode,
  runChipsec,
  scanUefi,
  summarizeByType,
} from './chipsec.js';

// A faithful excerpt of a real `chipsec_util uefi decode` .UEFI.lst (chipsec 1.13.16, on OVMF): two firmware
// volumes, a mix of file types, named + unnamed entries, plus section-level noise the parser must ignore.
const LST = `
EFI_FV +00000000h {8c8ce578-8a3d-4f1c-9935-896185c32dd3}: Size 001AC000h, Attr 0004FEFFh, HdrSize 0048h
    MD5   : 65dc83fabe7e6698b45991e276454e80
    +00000000h b'Non-UEFI_Padding' section of binary {None} : Type F0h Comments Attempting to identify modules

    +00000078h b'EFI_FILE' {9E21FD93-9C72-4C15-8C4B-E77F1DB2D792}
    Type 0Bh, Attr 00000000h, State F8h, Size 171554h, Checksum AA42h
        +00000018h b'S_GUID_DEFINED' section of binary {9e21fd93-9c72-4c15-8c4b-e77f1db2d792} : Type 02h GUID {ee4e5898-3914-4259-9d6e-dc7bd79403cf}
                +000000E8h b'EFI_FILE' {52C05B14-0B98-496C-BC3B-04B50211D680} b'PeiCore'
                Type 04h, Attr 00000010h, State F8h, Size 00613Ah, Checksum AA5Fh

                +00006268h b'EFI_FILE' {9B3ADA4F-AE56-4C24-8DEA-F03B7558AE50} b'PcdPeim'
                Type 06h, Attr 00000010h, State F8h, Size 001F7Ah, Checksum AA72h

EFI_FV +001AC000h {8c8ce578-8a3d-4f1c-9935-896185c32dd3}: Size 00084000h, Attr 0004FEFFh, HdrSize 0048h
                +00000078h b'EFI_FILE' {462CAA21-7614-4503-836E-8AB6F4662331} b'UiApp'
                Type 09h, Attr 00000010h, State F8h, Size 0176FEh, Checksum AA31h

                +00018678h b'EFI_FILE' {A210F973-229D-4F4D-AA37-9895E6C9EABA} b'DxeCore'
                Type 07h, Attr 00000000h, State F8h, Size 00A1B2h, Checksum AA55h

                +00021678h b'EFI_FILE' {C57AD6B7-0515-40A8-9D21-551652854E37} b'Shell'
                Type 09h, Attr 00000010h, State F8h, Size 0A0100h, Checksum AA10h
`;

describe('parseUefiDecode', () => {
  const { volumes, modules } = parseUefiDecode(LST);

  it('counts the firmware volumes', () => {
    expect(volumes).toBe(2);
  });

  it('enumerates every EFI_FILE (not section GUIDs) with its type', () => {
    expect(modules).toHaveLength(6);
    const byGuid = Object.fromEntries(modules.map((m) => [m.guid, m]));
    expect(byGuid['52C05B14-0B98-496C-BC3B-04B50211D680']).toEqual({
      guid: '52C05B14-0B98-496C-BC3B-04B50211D680',
      name: 'PeiCore',
      type: 'PEI_CORE',
    });
    expect(byGuid['A210F973-229D-4F4D-AA37-9895E6C9EABA']?.type).toBe('DXE_DRIVER');
    expect(byGuid['9E21FD93-9C72-4C15-8C4B-E77F1DB2D792']?.type).toBe('FIRMWARE_VOLUME_IMAGE');
  });

  it('ignores S_GUID_DEFINED / section lines and the None placeholder', () => {
    const guids = modules.map((m) => m.guid);
    expect(guids).not.toContain('EE4E5898-3914-4259-9D6E-DC7BD79403CF');
    expect(guids.some((g) => g.toLowerCase().includes('none'))).toBe(false);
  });

  it('upper-cases GUIDs and handles unnamed entries', () => {
    const fvImage = modules.find((m) => m.guid === '9E21FD93-9C72-4C15-8C4B-E77F1DB2D792');
    expect(fvImage?.name).toBeUndefined();
  });

  it('returns no modules for a non-UEFI blob', () => {
    expect(parseUefiDecode('random bytes, not a firmware volume').modules).toHaveLength(0);
  });
});

describe('summarizeByType', () => {
  it('groups modules by EFI filetype label', () => {
    const mods: UefiModule[] = [
      { guid: 'A', type: 'DXE_DRIVER' },
      { guid: 'B', type: 'DXE_DRIVER' },
      { guid: 'C', type: 'APPLICATION' },
      { guid: 'D' },
    ];
    expect(summarizeByType(mods)).toEqual({ DXE_DRIVER: 2, APPLICATION: 1, unknown: 1 });
  });
});

describe('scanUefi', () => {
  const { volumes, modules } = parseUefiDecode(LST);

  it('emits an honest static_confirmed inventory finding', () => {
    const inv = scanUefi(volumes, modules, []).find((f) => f.kind === 'uefi-inventory');
    expect(inv?.proofState).toBe('static_confirmed');
    expect(inv?.severity).toBe('info');
    expect((inv?.evidence as { moduleCount: number }).moduleCount).toBe(6);
  });

  it('flags embedded UEFI applications as a review lead, not a verdict', () => {
    const app = scanUefi(volumes, modules, []).find((f) => f.kind === 'uefi-embedded-app');
    expect(app?.proofState).toBe('needs_runtime_reproduction');
    expect(app?.severity).toBe('info');
    // UiApp + Shell are the two Type-09 modules.
    expect((app?.evidence as { apps: unknown[] }).apps).toHaveLength(2);
  });

  it('matches an IOC feed by GUID → critical static_confirmed', () => {
    const iocs: UefiIoc[] = [{ guid: 'a210f973-229d-4f4d-aa37-9895e6c9eaba', label: 'TestImplant DXE' }];
    const hit = scanUefi(volumes, modules, iocs).find((f) => f.kind === 'uefi-ioc');
    expect(hit?.severity).toBe('critical');
    expect(hit?.proofState).toBe('static_confirmed');
    expect(hit?.title).toContain('TestImplant DXE');
  });

  it('matches an IOC feed by name substring (case-insensitive)', () => {
    const iocs: UefiIoc[] = [{ name: 'pcdpeim', label: 'Fake PCD implant', severity: 'high' }];
    const hits = scanUefi(volumes, modules, iocs).filter((f) => f.kind === 'uefi-ioc');
    expect(hits).toHaveLength(1);
    expect(hits[0]?.severity).toBe('high');
  });

  it('emits no inventory finding when nothing decoded', () => {
    expect(scanUefi(0, [], [])).toHaveLength(0);
  });
});

describe('loadUefiIocs', () => {
  it('returns an empty feed when the env var is unset (no fabricated built-ins)', () => {
    expect(loadUefiIocs({})).toEqual([]);
  });

  it('ignores a malformed / missing feed file honestly', () => {
    expect(loadUefiIocs({ FIRMLAB_UEFI_IOC: '/nonexistent/iocs.json' })).toEqual([]);
  });
});

describe('runChipsec', () => {
  it('degrades honestly to blocked when chipsec is absent', async () => {
    // No chipsec_util on PATH in CI → available:false, blocked, never a fabricated tree.
    const res = await runChipsec('/tmp/does-not-exist.fd', { env: { PATH: '/nonexistent' } });
    if (!res.available) {
      expect(res.ran).toBe(false);
      expect(res.proofState).toBe('blocked_by_platform');
      expect(res.moduleCount).toBe(0);
      expect(res.findings).toHaveLength(0);
    }
  });
});
