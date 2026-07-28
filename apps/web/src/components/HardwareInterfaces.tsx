/**
 * Hardware interfaces — what this firmware DECLARES about the physical ways into the board.
 *
 * The question an analyst with the device on the bench actually asks is "how do I get a console, read the flash, or
 * attach a debugger", and FirmLab already holds most of that answer — scattered. The device tree names the UART the
 * kernel is told to use as its console, the SPI controllers and the flash partition map with its `read-only`
 * declarations; the kernel command line names the tty and its baud rate; the U-Boot environment says whether the
 * bootloader stops for an interactive prompt. Three providers, one question, and until now nothing put them on the
 * same screen.
 *
 * **This section reads the image. It never touches hardware, and it must never imply otherwise.** Everything here is
 * a declaration made by the firmware about the board it was built for: a UART the tree marks `okay` is one the kernel
 * will bring up, which says nothing about whether the pads are populated, whether a header is fitted, or whether the
 * console is authenticated. `read-only` on a partition is a request to the kernel to withhold a writable mtd node —
 * not write protection, and a bootloader or a direct SPI attack ignores it entirely. Those two sentences are in the
 * UI, not only in this comment, because they are exactly the inferences this screen would otherwise invite.
 *
 * JTAG and SWD get a row that says FirmLab has nothing, and that is deliberate rather than an omission: a device tree
 * does not describe the debug port, so a section listing UART and SPI while silently skipping JTAG would read as
 * "no JTAG here". The honest answer to a question this evidence cannot settle is to name the question.
 */
import { useCallback, useEffect, useState } from 'react';
import {
  type AnalysisKind,
  type DeviceTreeBlob,
  type DeviceTreeResult,
  type DtPeripheral,
  type UbootResult,
  api,
} from '../api';

/** The buses a device tree can describe, in the order an analyst on the bench cares about them. */
const BUS_ORDER: NonNullable<DtPeripheral['kind']>[] = ['uart', 'spi', 'i2c', 'mmc', 'usb', 'gpio', 'watchdog'];

const BUS_LABEL: Record<string, string> = {
  uart: 'UART / serial',
  spi: 'SPI',
  i2c: 'I²C',
  mmc: 'MMC / SD',
  usb: 'USB',
  gpio: 'GPIO',
  watchdog: 'Watchdog',
  flash: 'Flash',
};

/**
 * Pure: pull the console tty and its baud rate out of a kernel command line. Exported for the unit test, because
 * this is the one piece of parsing on the screen and a wrong answer here is the sentence an analyst would act on.
 *
 * A `console=` value is `<tty>[,<baud><parity><bits>]` — `ttyS0,115200n8`. Linux honours MULTIPLE `console=`
 * arguments and the LAST one owns /dev/console, so the last is returned rather than the first; returning the first
 * would name the wrong port on any image that declares two, which is common on boards with both a UART and a
 * framebuffer console.
 */
export function parseConsoleArg(bootargs: string | undefined): { tty: string; baud?: string } | null {
  if (!bootargs) return null;
  const matches = [...bootargs.matchAll(/(?:^|\s)console=([^\s]+)/g)];
  const last = matches[matches.length - 1];
  if (!last?.[1]) return null;
  const [tty, params] = last[1].split(',');
  if (!tty) return null;
  const baud = params?.match(/^(\d+)/)?.[1];
  return baud ? { tty, baud } : { tty };
}

/**
 * Pure: does the U-Boot environment leave an interactive prompt open, and for how long? `bootdelay` is seconds to
 * wait for a keypress; `0` means no window and `-1` disables the prompt entirely. Anything above 0 is a console an
 * operator with physical access can interrupt — which is the single most useful fact the env carries for this screen.
 */
export function bootPromptWindow(vars: Record<string, string> | undefined): {
  state: 'open' | 'none' | 'disabled' | 'unknown';
  seconds?: number;
} {
  const raw = vars?.bootdelay;
  if (raw === undefined) return { state: 'unknown' };
  const n = Number.parseInt(raw, 10);
  if (Number.isNaN(n)) return { state: 'unknown' };
  if (n < 0) return { state: 'disabled' };
  if (n === 0) return { state: 'none', seconds: 0 };
  return { state: 'open', seconds: n };
}

/** Format a byte offset/size the way flash maps are read — hex for the offset, KiB/MiB for the size. */
function hex(n: number | undefined): string {
  return n === undefined ? '—' : `0x${n.toString(16)}`;
}

function bytes(n: number | undefined): string {
  if (n === undefined) return '—';
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(n % (1024 * 1024) === 0 ? 0 : 1)} MiB`;
  if (n >= 1024) return `${(n / 1024).toFixed(n % 1024 === 0 ? 0 : 1)} KiB`;
  return `${n} B`;
}

/** The tree a FIT configuration selected, else the first — mirroring what the provider itself considers primary. */
function primaryBlob(result: DeviceTreeResult | null): DeviceTreeBlob | null {
  const blobs = result?.blobs ?? [];
  return blobs.find((b) => b.selected) ?? blobs[0] ?? null;
}

type Load = 'loading' | 'ready' | 'error';

export function HardwareInterfaces({ imageId }: { imageId: string }): JSX.Element {
  const [dt, setDt] = useState<DeviceTreeResult | null>(null);
  const [uboot, setUboot] = useState<UbootResult | null>(null);
  const [load, setLoad] = useState<Load>('loading');
  const [running, setRunning] = useState<AnalysisKind | null>(null);

  const refresh = useCallback(async () => {
    setLoad('loading');
    try {
      // Both are stored provider results, so this reads what has already run rather than running anything. An
      // image nobody has analysed yet lands in the empty state below, which offers the run instead of implying one.
      const [d, u] = await Promise.all([api.deviceTree(imageId), api.ubootEnv(imageId)]);
      setDt(d);
      setUboot(u);
      setLoad('ready');
    } catch {
      setLoad('error');
    }
  }, [imageId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = useCallback(
    async (kind: AnalysisKind) => {
      setRunning(kind);
      try {
        const { jobId } = await api.runAnalysis(imageId, kind);
        const timer = window.setInterval(async () => {
          const j = await api.job(jobId);
          if (j.status === 'done' || j.status === 'error') {
            window.clearInterval(timer);
            setRunning(null);
            await refresh();
          }
        }, 700);
      } catch {
        setRunning(null);
      }
    },
    [imageId, refresh],
  );

  const blob = primaryBlob(dt);
  const peripherals = blob?.peripherals ?? [];
  const partitions = blob?.partitions ?? [];
  const console_ = parseConsoleArg(blob?.bootargs);
  const consoleNode = peripherals.find((p) => p.console) ?? null;
  const prompt = bootPromptWindow(uboot?.vars);
  const treeRan = dt !== null;
  const treeFound = dt?.found === true;

  if (load === 'loading') {
    return (
      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-title">Hardware interfaces</div>
        <div className="skeleton" style={{ height: 96, marginTop: 12 }} />
      </div>
    );
  }

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">Hardware interfaces</div>
      <div className="panel-sub">
        What this firmware <em>declares</em> about the physical ways into the board — read from the device tree, the
        kernel command line and the U-Boot environment. FirmLab does not connect to hardware: everything here describes
        the board the image was <strong>built for</strong>, not the board on your bench.
      </div>

      {load === 'error' && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          Could not read the stored provider results.{' '}
          <button className="btn btn-sm btn-ghost" onClick={() => void refresh()}>
            Retry
          </button>
        </div>
      )}

      {/* The lead answer. An analyst opens this screen to find the console, so it is the first thing on it and it is
          a sentence, not a table row. */}
      <section className="hw-lead" aria-labelledby="hw-console-h">
        <div className="eyebrow" id="hw-console-h">
          Console
        </div>
        {console_ || consoleNode ? (
          <>
            <p className="hw-answer">
              {console_ ? (
                <>
                  <span className="mono">{console_.tty}</span>
                  {console_.baud && (
                    <>
                      {' at '}
                      <span className="mono">{console_.baud}</span> baud
                    </>
                  )}
                </>
              ) : (
                <span className="mono">{consoleNode?.path}</span>
              )}
            </p>
            {/* Provenance renders for WHATEVER evidence exists, not only when both do. The real GL.iNet BE3600
                carries `bootargs = "clk_ignore_unused"` — no `console=` at all — and its console is known solely
                because `stdout-path = serial0` resolves to /soc/serial@78af000. Gating this on both sources left
                the corpus's actual case showing a bare node path with nothing saying where it came from. */}
            <div className="hint hw-prose">
              {console_ && (
                <>
                  Kernel command line names <span className="mono">{console_.tty}</span>
                  {consoleNode ? '; ' : '. '}
                </>
              )}
              {consoleNode && (
                <>
                  {console_ ? 'the tree resolves ' : 'The device tree resolves '}
                  <span className="mono">{blob?.stdoutPath ?? 'stdout-path'}</span> to{' '}
                  <span className="mono">{consoleNode.path}</span>
                  {consoleNode.compatible?.[0] && (
                    <>
                      {' '}
                      (<span className="mono">{consoleNode.compatible[0]}</span>)
                    </>
                  )}
                  .{' '}
                </>
              )}
              {!console_ && consoleNode && (
                <>
                  The kernel command line does not name a console, so the baud rate is not declared anywhere in this
                  image.{' '}
                </>
              )}
              A declared console is a UART the kernel is told to bring up. Whether the pads are populated, a header is
              fitted, or the console asks for a login are three further questions the image cannot answer.
            </div>
          </>
        ) : (
          <p className="hint hw-prose" style={{ margin: 0 }}>
            {treeFound
              ? 'Neither the kernel command line nor the device tree names a console for this image.'
              : 'No console known yet — the device tree has not been read.'}
          </p>
        )}

        <div className="hw-prompt">
          <span className="eyebrow">Bootloader prompt</span>
          {prompt.state === 'open' && (
            <span className="badge badge-medium">
              interruptible — <span className="mono">bootdelay={prompt.seconds}</span>
            </span>
          )}
          {prompt.state === 'none' && (
            <span className="badge">
              no window — <span className="mono">bootdelay=0</span>
            </span>
          )}
          {prompt.state === 'disabled' && (
            <span className="badge badge-ok">
              prompt disabled — <span className="mono">bootdelay=-1</span>
            </span>
          )}
          {prompt.state === 'unknown' && (
            <span className="hint hw-prose">
              not determinable — {uboot?.found ? 'the env carries no bootdelay' : 'no U-Boot environment was decoded'}
            </span>
          )}
        </div>
      </section>

      {/* An image nothing has read gets ONE empty state, not the same sentence under each heading. Repeating
          "no device tree has been read" under Buses and again under Flash map reads as two separate findings. */}
      {!treeRan && (
        <div className="hw-nothing" style={{ marginTop: 18 }}>
          <strong>Nothing has been read for this image yet</strong>
          <span className="hint hw-prose">
            The buses, the flash map and the console all come from the device tree and the U-Boot environment, and
            neither has run. That is why this screen is empty — not because the firmware declares no interfaces.
          </span>
        </div>
      )}

      {/* Buses. A table rather than tiles: these are rows of technical data that get compared column-wise. */}
      <section style={{ marginTop: 20, display: treeRan ? undefined : 'none' }}>
        <div className="eyebrow" style={{ marginBottom: 8 }}>
          Declared buses & debug interfaces
        </div>
        {peripherals.length > 0 ? (
          <div style={{ overflowX: 'auto' }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Interface</th>
                  <th>Node</th>
                  <th>Compatible</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {[...peripherals]
                  .sort((a, b) => {
                    const ai = BUS_ORDER.indexOf(a.kind ?? 'gpio');
                    const bi = BUS_ORDER.indexOf(b.kind ?? 'gpio');
                    return ai === bi ? (a.path ?? '').localeCompare(b.path ?? '') : ai - bi;
                  })
                  .map((p) => (
                    <tr key={p.path}>
                      <td>
                        {BUS_LABEL[p.kind ?? ''] ?? p.kind}
                        {p.console && (
                          <span className="badge badge-accent" style={{ marginLeft: 6 }}>
                            console
                          </span>
                        )}
                      </td>
                      <td className="mono">{p.path}</td>
                      <td className="mono hw-compat">{p.compatible?.join(', ') ?? '—'}</td>
                      <td>
                        <span className={p.enabled ? 'hw-on' : 'hw-off'}>{p.enabled ? 'enabled' : 'disabled'}</span>
                        {/* The literal `status` value is worth showing only when it adds something the word does
                            not: `ok` vs `okay` vs absent is real provenance, but a node whose status IS the string
                            "disabled" would otherwise render as "disabled disabled". */}
                        {p.status && p.status !== (p.enabled ? 'enabled' : 'disabled') && (
                          <span className="hint hw-prose" style={{ marginLeft: 6 }}>
                            {p.status}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="hint hw-prose" style={{ margin: 0 }}>
            {treeFound
              ? 'The device tree declares no bus nodes this reader recognises.'
              : 'No device tree has been read for this image, so no interface is declared either way.'}
          </p>
        )}
        {(blob?.peripheralsDropped ?? 0) > 0 && (
          <p className="hint hw-prose" style={{ marginTop: 6 }}>
            {blob?.peripheralsDropped} further node(s) were not listed — {blob?.peripheralNote ?? 'a cap applied'}.
          </p>
        )}
        {(blob?.nestedNodesSkipped ?? 0) > 0 && (
          <p className="hint hw-prose" style={{ marginTop: 6 }}>
            {blob?.nestedNodesSkipped} node(s) nested under another peripheral were excluded as driver chip-support
            tables rather than board hardware.
          </p>
        )}

        {/* Named, not omitted: a list of buses that silently skipped JTAG would read as "there is no JTAG". */}
        <div className="hw-nothing">
          <strong>JTAG / SWD</strong>
          <span className="hint hw-prose">
            Not determinable from firmware. A device tree does not describe the debug port, and whether it is fused off,
            password-locked or open is a property of the silicon and the board — this row exists so its absence above is
            not read as a negative.
          </span>
        </div>
      </section>

      {/* Flash map. The read-only caveat sits with the column it qualifies, not in a footnote. */}
      <section style={{ marginTop: 20, display: treeRan ? undefined : 'none' }}>
        <div className="eyebrow" style={{ marginBottom: 8 }}>
          Declared flash map
        </div>
        {partitions.length > 0 ? (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="data">
                <thead>
                  <tr>
                    <th>Partition</th>
                    <th className="num">Offset</th>
                    <th className="num">Size</th>
                    <th>Declares read-only</th>
                  </tr>
                </thead>
                <tbody>
                  {partitions.map((p) => (
                    <tr key={`${p.nodeName}-${p.offset ?? '?'}`}>
                      <td>
                        {p.label ?? p.nodeName}
                        {p.label && p.nodeName && p.label !== p.nodeName && (
                          <span className="hint mono" style={{ marginLeft: 6 }}>
                            {p.nodeName}
                          </span>
                        )}
                      </td>
                      <td className="num mono">{hex(p.offset)}</td>
                      <td className="num mono">{bytes(p.size)}</td>
                      <td>{p.declaredReadOnly ? <span className="badge">read-only</span> : <span>—</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="hint hw-prose" style={{ marginTop: 8 }}>
              <strong>`read-only` is not write protection.</strong> It asks the kernel to withhold a writable mtd node.
              A bootloader, a recovery path or a direct SPI write ignores it, and nothing here says the region is
              protected in hardware.
              {blob?.partitionNode && (
                <>
                  {' '}
                  Read from <span className="mono">{blob.partitionNode}</span>.
                </>
              )}
            </p>
          </>
        ) : (
          <p className="hint hw-prose" style={{ margin: 0 }}>
            {blob?.partitionNote ??
              (treeFound
                ? 'This device tree declares no partition map.'
                : 'No device tree has been read for this image.')}
          </p>
        )}
      </section>

      {/* Provenance and the honest empty state, last: what produced this, and what to run when it produced nothing. */}
      <section style={{ marginTop: 20 }}>
        {blob && (
          <p className="hint hw-prose" style={{ margin: 0 }}>
            Board: <span className="mono">{blob.model ?? blob.compatible?.[0] ?? 'unnamed'}</span>
            {blob.origin && (
              <>
                {' · reached via '}
                <span className="mono">{blob.origin}</span>
              </>
            )}
            {blob.nodeCount !== undefined && <> · {blob.nodeCount} nodes</>}
            {(dt?.blobs?.length ?? 0) > 1 && (
              <>
                {' · '}
                {dt?.blobs?.length} trees in this image
                {blob.selected ? ', this one selected by the FIT configuration' : ', none declared as the choice'}
              </>
            )}
          </p>
        )}
        {treeRan && !treeFound && (
          <div className="banner banner-warn" style={{ marginTop: 8 }}>
            No device tree could be read. {dt?.reason}
            {(dt?.searched?.length ?? 0) > 0 && (
              <div className="hint hw-prose" style={{ marginTop: 4 }}>
                Searched: <span className="mono">{dt?.searched?.join(', ')}</span>
              </div>
            )}
          </div>
        )}
        <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
          <button className="btn btn-sm" disabled={running !== null} onClick={() => void run('devicetree')}>
            {running === 'devicetree' ? (
              <span className="spinner" />
            ) : treeRan ? (
              'Re-read device tree'
            ) : (
              'Read device tree'
            )}
          </button>
          <button className="btn btn-sm" disabled={running !== null} onClick={() => void run('uboot')}>
            {running === 'uboot' ? <span className="spinner" /> : uboot ? 'Re-read U-Boot env' : 'Read U-Boot env'}
          </button>
        </div>
      </section>
    </div>
  );
}
