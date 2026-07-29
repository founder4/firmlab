import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { type DeviceTreeResult, type UbootResult, api } from '../api';
import { mockedApi } from '../test-api-mock';
import { HardwareInterfaces, bootPromptWindow, parseConsoleArg } from './HardwareInterfaces';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

describe('parseConsoleArg', () => {
  it('reads the tty and baud out of a real Tenda command line', () => {
    // The literal bootargs the device-tree provider read off Tenda-Camera.bin.
    const args = 'console=ttySAK0,115200n8 root=/dev/mtdblock5 rootfstype=squashfs init=/sbin/init mem=64M';
    expect(parseConsoleArg(args)).toEqual({ tty: 'ttySAK0', baud: '115200' });
  });

  it('returns the LAST console argument, because that is the one Linux gives /dev/console', () => {
    // A board declaring both a framebuffer and a serial console: naming the first would send an analyst to tty0.
    expect(parseConsoleArg('console=tty0 console=ttyS0,57600n8')).toEqual({ tty: 'ttyS0', baud: '57600' });
  });

  it('handles a console with no baud rate, and does not invent one', () => {
    expect(parseConsoleArg('console=ttyS0 root=/dev/sda1')).toEqual({ tty: 'ttyS0' });
  });

  it('does not match a substring of another argument', () => {
    expect(parseConsoleArg('earlycon=uart8250 noconsole=ttyS9')).toBeNull();
  });

  it('is null for absent or empty bootargs rather than throwing', () => {
    expect(parseConsoleArg(undefined)).toBeNull();
    expect(parseConsoleArg('')).toBeNull();
  });
});

describe('bootPromptWindow', () => {
  it('separates the three states a bootdelay can express', () => {
    expect(bootPromptWindow({ bootdelay: '3' })).toEqual({ state: 'open', seconds: 3 });
    expect(bootPromptWindow({ bootdelay: '0' })).toEqual({ state: 'none', seconds: 0 });
    expect(bootPromptWindow({ bootdelay: '-1' })).toEqual({ state: 'disabled' });
  });

  it('reports unknown — not "disabled" — when the env carries no bootdelay', () => {
    // The whole point of the tri-state: "we did not read it" must never render as "the prompt is closed".
    expect(bootPromptWindow(undefined)).toEqual({ state: 'unknown' });
    expect(bootPromptWindow({})).toEqual({ state: 'unknown' });
    expect(bootPromptWindow({ bootdelay: 'auto' })).toEqual({ state: 'unknown' });
  });
});

/**
 * The REAL result of `runDeviceTreeAnalysis` over `GL.iNet-BE3600_4.9.0.bin`, captured by running the provider
 * against the 111 MB image rather than written from the type.
 *
 * The first version of this fixture was invented, and it was wrong in the one field the screen leads with: it gave
 * the image `bootargs = "console=ttyMSM0,115200n8 …"`. The real command line is `clk_ignore_unused` and declares no
 * console at all — this board's console is known ONLY because `stdout-path = serial0` resolves to
 * `/soc/serial@78af000`. Every corpus image would have exercised the branch the invented fixture never reached, and
 * the component's provenance line was gated on both sources being present, so the actual case rendered a bare node
 * path with nothing explaining it. That is CLAUDE.md's trap exactly: a fixture written from the same assumption as
 * the code, agreeing with it.
 *
 * Note also `status: "(absent)"` on two nodes — the kernel's `of_device_is_available` rule treats a missing status
 * as enabled, and the provider spells that literally rather than dropping the field.
 */
const gliNetTree = (): DeviceTreeResult => ({
  available: true,
  found: true,
  searched: ['fit-chain', 'extraction/*.dtb'],
  reason: 'read the selected FIT configuration',
  blobs: [
    {
      origin: 'fit → ubi → kernel → inner fit → flat_dt',
      model: 'GL.iNet BE3600, Inc. IPQ5332/AP-MI04.1-C2',
      compatible: ['qcom,ipq5332-ap-mi04.1-c2', 'qcom,ipq5332'],
      bootargs: 'clk_ignore_unused',
      stdoutPath: 'serial0',
      consolePath: '/soc/serial@78af000',
      nodeCount: 378,
      selected: true,
      peripherals: [
        {
          path: '/soc/serial@78af000',
          kind: 'uart',
          compatible: ['qcom,msm-uartdm-v1.4', 'qcom,msm-uartdm'],
          status: 'ok',
          enabled: true,
          console: true,
        },
        {
          path: '/soc/watchdog@b017000',
          kind: 'watchdog',
          compatible: ['qcom,kpss-wdt'],
          status: '(absent)',
          enabled: true,
        },
        { path: '/soc/spi@78b5000', kind: 'spi', compatible: ['qcom,spi-qup-v2.2.1'], status: 'ok', enabled: true },
        { path: '/soc/nand@79b0000', kind: 'flash', compatible: ['qcom,ipq5332-nand'], status: 'ok', enabled: true },
        {
          path: '/soc/serial@78b0000',
          kind: 'uart',
          compatible: ['qcom,msm-uartdm-v1.4', 'qcom,msm-uartdm'],
          status: 'disabled',
          enabled: false,
        },
        {
          path: '/soc/i2c@78b6000',
          kind: 'i2c',
          compatible: ['qcom,i2c-qup-v2.2.1'],
          status: 'disabled',
          enabled: false,
        },
        {
          path: '/soc/sdhci@7804000',
          kind: 'mmc',
          compatible: ['qcom,sdhci-msm-v5'],
          status: 'disabled',
          enabled: false,
        },
      ],
      // The real tree declares no partition table, and the provider says so in a sentence rather than returning [].
      partitions: [],
      partitionNote:
        'This tree declares no partition table. The flash map is not described here — it may live in the bootloader, a vendor-specific node, or an on-flash partition table — so this is silence about the layout, not a device with no partitions.',
    },
  ],
});

/**
 * A tree that DOES declare a flash map, so the read-only caveat and the offset/size columns stay covered. Built by
 * rewriting the blob rather than mutating it: `exactOptionalPropertyTypes` means an absent `partitionNote` and one
 * assigned `undefined` are different types, which is the same rule that keeps stored-result fields honest.
 */
const treeWithPartitions = (): DeviceTreeResult => {
  const base = gliNetTree();
  const blob = base.blobs?.[0];
  if (!blob) return base;
  const { partitionNote: _dropped, ...rest } = blob;
  return {
    ...base,
    blobs: [
      {
        ...rest,
        partitions: [
          { nodeName: 'partition@0', label: '0:SBL1', offset: 0, size: 262144, declaredReadOnly: true },
          { nodeName: 'partition@40000', label: 'rootfs', offset: 262144, size: 33554432, declaredReadOnly: false },
        ],
        partitionNode: '/soc/nand@79b0000/partitions',
      },
    ],
  };
};

describe('HardwareInterfaces', () => {
  it('leads with the console an analyst came for, and says what a declaration does not prove', async () => {
    mockApi.deviceTree.mockResolvedValue(gliNetTree());
    mockApi.ubootEnv.mockResolvedValue({ found: true, vars: { bootdelay: '3' } } as UbootResult);
    render(<HardwareInterfaces imageId="447719f7" />);

    // The real BE3600 declares NO `console=`, so the answer comes from stdout-path resolution alone.
    const lead = await screen.findByText('/soc/serial@78af000', { selector: '.hw-answer .mono' });
    expect(lead).toBeTruthy();
    // Provenance must render from the one source that exists — this is the branch the invented fixture never hit.
    expect(screen.getByText(/The device tree resolves/i)).toBeTruthy();
    expect(screen.getByText(/does not name a console, so the baud rate is not declared/i)).toBeTruthy();
    // The refusal has to be on screen, not only in the module doc.
    expect(screen.getByText(/pads are populated/i)).toBeTruthy();
    expect(screen.getByText(/does not connect to hardware/i)).toBeTruthy();
  });

  it('names JTAG as unanswerable so its absence from the bus table is not read as a negative', async () => {
    mockApi.deviceTree.mockResolvedValue(gliNetTree());
    mockApi.ubootEnv.mockResolvedValue(null);
    render(<HardwareInterfaces imageId="447719f7" />);

    expect(await screen.findByText('JTAG / SWD')).toBeTruthy();
    expect(screen.getByText(/Not determinable from firmware/i)).toBeTruthy();
  });

  it('reports an interruptible bootloader prompt, and reports a missing env as unknown', async () => {
    mockApi.deviceTree.mockResolvedValue(gliNetTree());
    mockApi.ubootEnv.mockResolvedValue({ found: true, vars: { bootdelay: '3' } } as UbootResult);
    const { unmount } = render(<HardwareInterfaces imageId="447719f7" />);
    expect(await screen.findByText(/bootdelay=3/)).toBeTruthy();
    unmount();

    mockApi.ubootEnv.mockResolvedValue(null);
    render(<HardwareInterfaces imageId="447719f7" />);
    expect(await screen.findByText(/no U-Boot environment was decoded/i)).toBeTruthy();
  });

  it('shows enabled and disabled buses distinctly rather than listing only what is on', async () => {
    mockApi.deviceTree.mockResolvedValue(gliNetTree());
    mockApi.ubootEnv.mockResolvedValue(null);
    render(<HardwareInterfaces imageId="447719f7" />);

    await waitFor(() => expect(screen.getByText('/soc/spi@78b5000')).toBeTruthy());
    // Four enabled, three disabled in the real tree — and the disabled ones are LISTED, not filtered away: a UART
    // the board declares and disables is exactly what an analyst with a soldering iron wants to know about.
    expect(screen.getAllByText('enabled').length).toBe(4);
    expect(screen.getAllByText('disabled').length).toBe(3);
    // `(absent)` is shown beside `enabled` because it adds provenance; the word `disabled` is not repeated twice.
    expect(screen.getAllByText('(absent)').length).toBe(1);
  });

  it('qualifies read-only in the flash map instead of letting it read as write protection', async () => {
    mockApi.deviceTree.mockResolvedValue(treeWithPartitions());
    mockApi.ubootEnv.mockResolvedValue(null);
    render(<HardwareInterfaces imageId="447719f7" />);

    expect(await screen.findByText('0:SBL1')).toBeTruthy();
    expect(screen.getByText('0x40000')).toBeTruthy();
    expect(screen.getByText('32 MiB')).toBeTruthy();
    expect(screen.getByText(/is not write protection/i)).toBeTruthy();
  });

  it('a tree that was read and found nothing states the reason and where it looked', async () => {
    mockApi.deviceTree.mockResolvedValue({
      available: true,
      found: false,
      blobs: [],
      reason: 'no valid FDT completed a walk',
      searched: ['raw image', 'extraction/*.dtb'],
    } as DeviceTreeResult);
    mockApi.ubootEnv.mockResolvedValue(null);
    render(<HardwareInterfaces imageId="dddbbb22" />);

    expect(await screen.findByText(/no valid FDT completed a walk/i)).toBeTruthy();
    expect(screen.getByText(/raw image, extraction/)).toBeTruthy();
    // A provider that ran and came back empty must NOT read as one that never ran — the DVRF page said exactly
    // that in three places while the banner beside it said the opposite.
    expect(screen.getAllByText(/was read for this image and none could be parsed/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/has been read for this image yet/i)).toBeNull();
  });

  /**
   * The rejected FDT headers. Verbatim from `447719f7`, where the provider's own `reason` ends with
   * "(see rejected)" — a sentence pointing at a field nothing rendered — and where `found` is TRUE, so that
   * sentence was not on screen either. One of the two entries is the same 60082-byte tree the panel renders
   * above, seen from the raw image with the UBI eraseblock headers still interleaved through it.
   */
  it('shows the headers that validated and would not walk, even when a tree WAS read', async () => {
    mockApi.deviceTree.mockResolvedValue({
      ...gliNetTree(),
      rejected: [
        {
          origin: 'raw image offset 10186216',
          sizeBytes: 60082,
          reason:
            'FDT header valid but the tree could not be read to completion: invalid token 0x1000000 at offset 10224040; a UBI eraseblock header ("UBI#") appears 37820 bytes in.',
        },
      ],
    });
    mockApi.ubootEnv.mockResolvedValue(null);
    render(<HardwareInterfaces imageId="447719f7" />);

    expect(await screen.findByText('1 FDT header validated but would not read')).toBeTruthy();
    expect(screen.getByText('raw image offset 10186216')).toBeTruthy();
    expect(screen.getByText(/UBI eraseblock header/)).toBeTruthy();
    // The claim the block exists to prevent.
    expect(screen.getByText(/not a finding that there is no tree there/i)).toBeTruthy();
  });

  it('bounds the list and says what it cut, rather than ending where it ran out', async () => {
    mockApi.deviceTree.mockResolvedValue({
      ...gliNetTree(),
      rejected: Array.from({ length: 9 }, (_, i) => ({
        origin: `raw image offset ${1000 + i}`,
        sizeBytes: 64,
        reason: 'FDT header valid but the tree could not be read to completion.',
      })),
    });
    mockApi.ubootEnv.mockResolvedValue(null);
    render(<HardwareInterfaces imageId="447719f7" />);

    expect(await screen.findByText('9 FDT headers validated but would not read')).toBeTruthy();
    expect(screen.getByText('raw image offset 1005')).toBeTruthy();
    expect(screen.queryByText('raw image offset 1006')).toBeNull();
    expect(screen.getByText(/3 more, in the run's stored result/)).toBeTruthy();
  });

  it('renders no such block for a run stored before rejections were recorded', async () => {
    mockApi.deviceTree.mockResolvedValue(gliNetTree());
    mockApi.ubootEnv.mockResolvedValue(null);
    render(<HardwareInterfaces imageId="447719f7" />);
    expect(await screen.findByText(/Board:/)).toBeTruthy();
    expect(screen.queryByText(/would not read/)).toBeNull();
  });

  it('an image nobody has analysed says so, and never renders an empty table as "no interfaces"', async () => {
    mockApi.deviceTree.mockResolvedValue(null);
    mockApi.ubootEnv.mockResolvedValue(null);
    render(<HardwareInterfaces imageId="fresh" />);

    // One consolidated empty state, not the same sentence repeated under every heading.
    expect(await screen.findByText(/Nothing has been read for this image yet/i)).toBeTruthy();
    expect(screen.getByText(/not because the firmware declares no interfaces/i)).toBeTruthy();
    expect(screen.getByRole('button', { name: /Read device tree/i })).toBeTruthy();
  });
});
