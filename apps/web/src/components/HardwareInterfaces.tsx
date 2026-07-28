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
 *
 * All of that prose lives in the `hardware` namespace, because it is the screen's product rather than its chrome —
 * including the three-way `absence` split, which is the distinction a real image caught this component getting
 * wrong. Node paths, `compatible` strings, tty names, baud rates and the literal `bootdelay` / `read-only` keys are
 * device-tree vocabulary and stay in it.
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
import { type Messages, useMessages } from '../i18n';

/** The buses a device tree can describe, in the order an analyst on the bench cares about them. */
const BUS_ORDER: NonNullable<DtPeripheral['kind']>[] = ['uart', 'spi', 'i2c', 'mmc', 'usb', 'gpio', 'watchdog'];

/**
 * Bus names, not prose — which is why they sit here rather than in the catalogue. `SPI`, `I²C`, `GPIO` and the rest
 * are what the bus is called on a datasheet in any language, and a Spanish "translation" of one would name a thing
 * no schematic uses. `JTAG / SWD` below is here for the same reason.
 */
const BUS_LABEL: Record<string, string> = {
  uart: 'UART',
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

/**
 * The sentence an empty section owes, and it has THREE cases, not two.
 *
 * The first version had two, and a real image caught it: DVRF's device-tree run completed and found nothing, and
 * all three sections below still read "No device tree has been read for this image" — the exact conflation this
 * workbench exists to prevent, written into the UI layer. `treeRan && !treeFound` is a provider that looked and
 * came back empty, which is a different claim from one that never ran, and the banner further down was already
 * saying so while these three contradicted it.
 */
function absenceReason(treeRan: boolean, treeFound: boolean, whenFound: string, t: Messages): string {
  if (treeFound) return whenFound;
  if (treeRan) return t.hardware.absence.ranNotParsed;
  return t.hardware.absence.neverRan;
}

type Load = 'loading' | 'ready' | 'error';

export function HardwareInterfaces({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
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
        <div className="panel-title">{t.sections.hardware}</div>
        <div className="skeleton" style={{ height: 96, marginTop: 12 }} />
      </div>
    );
  }

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">{t.sections.hardware}</div>
      <div className="panel-sub">
        {t.hardware.sub.before} <em>{t.hardware.sub.declares}</em> {t.hardware.sub.middle}{' '}
        <strong>{t.hardware.sub.builtFor}</strong>
        {t.hardware.sub.after}
      </div>

      {load === 'error' && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          {t.hardware.loadError}{' '}
          <button className="btn btn-sm btn-ghost" onClick={() => void refresh()}>
            {t.common.retry}
          </button>
        </div>
      )}

      {/* The lead answer. An analyst opens this screen to find the console, so it is the first thing on it and it is
          a sentence, not a table row. */}
      <section className="hw-lead" aria-labelledby="hw-console-h">
        <div className="eyebrow" id="hw-console-h">
          {t.hardware.console.heading}
        </div>
        {console_ || consoleNode ? (
          <>
            <p className="hw-answer">
              {console_ ? (
                <>
                  <span className="mono">{console_.tty}</span>
                  {console_.baud && (
                    <>
                      {' '}
                      {t.hardware.console.at} <span className="mono">{console_.baud}</span> {t.hardware.console.baud}
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
                  {t.hardware.console.fromCmdline} <span className="mono">{console_.tty}</span>
                  {consoleNode ? '; ' : '. '}
                </>
              )}
              {consoleNode && (
                <>
                  {console_ ? t.hardware.console.treeResolvesAfter : t.hardware.console.treeResolvesFirst}{' '}
                  <span className="mono">{blob?.stdoutPath ?? 'stdout-path'}</span> {t.hardware.console.to}{' '}
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
              {!console_ && consoleNode && <>{t.hardware.console.noBaud} </>}
              {t.hardware.console.caveat}
            </div>
          </>
        ) : (
          <p className="hint hw-prose" style={{ margin: 0 }}>
            {treeFound
              ? t.hardware.console.noneFound
              : treeRan
                ? t.hardware.console.noneParsed
                : t.hardware.console.noneRead}
          </p>
        )}

        <div className="hw-prompt">
          <span className="eyebrow">{t.hardware.prompt.heading}</span>
          {prompt.state === 'open' && (
            <span className="badge badge-medium">
              {t.hardware.prompt.open} — <span className="mono">bootdelay={prompt.seconds}</span>
            </span>
          )}
          {prompt.state === 'none' && (
            <span className="badge">
              {t.hardware.prompt.none} — <span className="mono">bootdelay=0</span>
            </span>
          )}
          {prompt.state === 'disabled' && (
            <span className="badge badge-ok">
              {t.hardware.prompt.disabled} — <span className="mono">bootdelay=-1</span>
            </span>
          )}
          {prompt.state === 'unknown' && (
            <span className="hint hw-prose">
              {t.hardware.prompt.unknown} — {uboot?.found ? t.hardware.prompt.noBootdelay : t.hardware.prompt.noEnv}
            </span>
          )}
        </div>
      </section>

      {/* An image nothing has read gets ONE empty state, not the same sentence under each heading. Repeating
          "no device tree has been read" under Buses and again under Flash map reads as two separate findings. */}
      {!treeRan && (
        <div className="hw-nothing" style={{ marginTop: 18 }}>
          <strong>{t.hardware.nothingRead.title}</strong>
          <span className="hint hw-prose">{t.hardware.nothingRead.body}</span>
        </div>
      )}

      {/* Buses. A table rather than tiles: these are rows of technical data that get compared column-wise. */}
      <section style={{ marginTop: 20, display: treeRan ? undefined : 'none' }}>
        <div className="eyebrow" style={{ marginBottom: 8 }}>
          {t.hardware.buses.heading}
        </div>
        {peripherals.length > 0 ? (
          <div style={{ overflowX: 'auto' }}>
            <table className="data">
              <thead>
                <tr>
                  <th>{t.hardware.buses.interface}</th>
                  <th>{t.hardware.buses.node}</th>
                  {/* The heading names the device tree's own `compatible` property. */}
                  <th>Compatible</th>
                  <th>{t.hardware.buses.status}</th>
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
                            {t.hardware.buses.console}
                          </span>
                        )}
                      </td>
                      <td className="mono">{p.path}</td>
                      <td className="mono hw-compat">{p.compatible?.join(', ') ?? '—'}</td>
                      <td>
                        <span className={p.enabled ? 'hw-on' : 'hw-off'}>
                          {p.enabled ? t.hardware.buses.enabled : t.hardware.buses.disabled}
                        </span>
                        {/* The literal `status` value is worth showing only when it adds something the word does
                            not: `ok` vs `okay` vs absent is real provenance, but a node whose status IS the string
                            "disabled" would otherwise render as "disabled disabled". The comparison is against the
                            device tree's own vocabulary, so it stays in English whatever the interface language. */}
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
            {absenceReason(treeRan, treeFound, t.hardware.buses.none, t)}
          </p>
        )}
        {(blob?.peripheralsDropped ?? 0) > 0 && (
          <p className="hint hw-prose" style={{ marginTop: 6 }}>
            {t.hardware.buses.dropped(
              blob?.peripheralsDropped ?? 0,
              blob?.peripheralNote ?? t.hardware.buses.droppedDefaultRule,
            )}
          </p>
        )}
        {(blob?.nestedNodesSkipped ?? 0) > 0 && (
          <p className="hint hw-prose" style={{ marginTop: 6 }}>
            {t.hardware.buses.nested(blob?.nestedNodesSkipped ?? 0)}
          </p>
        )}

        {/* Named, not omitted: a list of buses that silently skipped JTAG would read as "there is no JTAG". */}
        <div className="hw-nothing">
          <strong>JTAG / SWD</strong>
          <span className="hint hw-prose">{t.hardware.jtag.body}</span>
        </div>
      </section>

      {/* Flash map. The read-only caveat sits with the column it qualifies, not in a footnote. */}
      <section style={{ marginTop: 20, display: treeRan ? undefined : 'none' }}>
        <div className="eyebrow" style={{ marginBottom: 8 }}>
          {t.hardware.flash.heading}
        </div>
        {partitions.length > 0 ? (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="data">
                <thead>
                  <tr>
                    <th>{t.hardware.flash.partition}</th>
                    <th className="num">{t.hardware.flash.offset}</th>
                    <th className="num">{t.hardware.flash.size}</th>
                    <th>{t.hardware.flash.declaresReadOnly}</th>
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
              <strong>{t.hardware.flash.readOnlyStrong}</strong> {t.hardware.flash.readOnlyBody}
              {blob?.partitionNode && (
                <>
                  {' '}
                  {t.hardware.flash.readFrom} <span className="mono">{blob.partitionNode}</span>.
                </>
              )}
            </p>
          </>
        ) : (
          <p className="hint hw-prose" style={{ margin: 0 }}>
            {blob?.partitionNote ?? absenceReason(treeRan, treeFound, t.hardware.flash.none, t)}
          </p>
        )}
      </section>

      {/* Provenance and the honest empty state, last: what produced this, and what to run when it produced nothing. */}
      <section style={{ marginTop: 20 }}>
        {blob && (
          <p className="hint hw-prose" style={{ margin: 0 }}>
            {t.hardware.provenance.board}{' '}
            <span className="mono">{blob.model ?? blob.compatible?.[0] ?? t.hardware.provenance.unnamed}</span>
            {blob.origin && (
              <>
                {' · '}
                {t.hardware.provenance.reachedVia} <span className="mono">{blob.origin}</span>
              </>
            )}
            {blob.nodeCount !== undefined && <> · {t.hardware.provenance.nodes(blob.nodeCount)}</>}
            {(dt?.blobs?.length ?? 0) > 1 && (
              <>
                {' · '}
                {t.hardware.provenance.trees(dt?.blobs?.length ?? 0)}
                {blob.selected ? t.hardware.provenance.selected : t.hardware.provenance.notSelected}
              </>
            )}
          </p>
        )}
        {treeRan && !treeFound && (
          <div className="banner banner-warn" style={{ marginTop: 8 }}>
            {t.hardware.provenance.noneRead} {dt?.reason}
            {(dt?.searched?.length ?? 0) > 0 && (
              <div className="hint hw-prose" style={{ marginTop: 4 }}>
                {t.hardware.provenance.searched} <span className="mono">{dt?.searched?.join(', ')}</span>
              </div>
            )}
          </div>
        )}
        <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
          <button className="btn btn-sm" disabled={running !== null} onClick={() => void run('devicetree')}>
            {running === 'devicetree' ? (
              <span className="spinner" />
            ) : treeRan ? (
              t.hardware.actions.rereadTree
            ) : (
              t.hardware.actions.readTree
            )}
          </button>
          <button className="btn btn-sm" disabled={running !== null} onClick={() => void run('uboot')}>
            {running === 'uboot' ? (
              <span className="spinner" />
            ) : uboot ? (
              t.hardware.actions.rereadUboot
            ) : (
              t.hardware.actions.readUboot
            )}
          </button>
        </div>
      </section>
    </div>
  );
}
