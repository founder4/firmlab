/**
 * FileBrowser — the panel that lets an operator open the file a finding cites.
 *
 * Until this existed, every finding in the ledger pointed at evidence nobody could check. docs/BACKLOG.md still
 * carries the entry that had to be WITHDRAWN because it was written from a filename without opening the file —
 * BeanView's `private_key.pem`, which begins `-----BEGIN PUBLIC KEY-----`. That is the failure this workbench is
 * built against, and it happened here, in this UI, for want of a way to look.
 *
 * Three things the rendering refuses to let a reader mistake:
 *
 *  - **An empty tree is never rendered as an empty firmware.** The extraction verdict sits above the panes and is
 *    not collapsible, because "no extraction has run", "the carve is truncated" and "54 volumes came out and none
 *    is a rootfs" produce identical-looking empty lists and call for opposite next moves.
 *  - **A window is never rendered as a file.** The viewer leads with how much of the file it is holding, and the
 *    pager is right there — the bound is stated AND navigable, rather than stated and dead-ended.
 *  - **A refusal names its rule.** A symlink pointing out of the extraction is shown in the listing (that DVRF
 *    ships `etc/passwd -> /dev/null` is a fact about the firmware) and refused on read, with the rule that refused
 *    it. "Denied" would teach nothing.
 *
 * The row is a monospace grid keyed on the `ls -l` mode string, so `-rwsr-xr-x` and `-rw-r--r--` line up in one
 * column and setuid is visible by scanning rather than by clicking.
 */
import { useCallback, useEffect, useState } from 'react';
import {
  type DirEntryView,
  type ExtractionBrowseState,
  type FilesListing,
  type FilesRead,
  api,
  fmtBytes,
} from '../api';

/** How each extraction state is allowed to look. Only a real rootfs is neutral; nothing here reads as "fine". */
const STATE_TONE: Record<ExtractionBrowseState, string> = {
  'never-run': 'banner-warn',
  'in-progress': 'banner-info',
  failed: 'banner-warn',
  'no-output': 'banner-warn',
  'volumes-only': 'banner-info',
  rootfs: '',
};

const STATE_LABEL: Record<ExtractionBrowseState, string> = {
  'never-run': 'never extracted',
  'in-progress': 'extracting',
  failed: 'extraction failed',
  'no-output': 'nothing on disk',
  'volumes-only': 'carve only — no rootfs',
  rootfs: 'rootfs recovered',
};

function parentOf(p: string): string {
  const i = p.lastIndexOf('/');
  return i < 0 ? '' : p.slice(0, i);
}

export function FileBrowser({ imageId }: { imageId: string }): JSX.Element {
  const [dir, setDir] = useState('');
  const [listing, setListing] = useState<FilesListing | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [read, setRead] = useState<FilesRead | null>(null);
  const [offset, setOffset] = useState(0);
  const [preferHex, setPreferHex] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .files(imageId, dir || undefined)
      .then((r) => {
        if (!alive) return;
        setListing(r);
        setError(null);
      })
      .catch((e: unknown) => alive && setError(e instanceof Error ? e.message : String(e)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [imageId, dir]);

  const open = useCallback(
    (path: string, at: number, hex: boolean) => {
      setSelected(path);
      setOffset(at);
      api
        .readFile(imageId, path, { offset: at, view: hex ? 'hex' : 'text' })
        .then(setRead)
        .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
    },
    [imageId],
  );

  const onEntry = useCallback(
    (entry: DirEntryView) => {
      if (entry.type === 'dir') {
        setDir(entry.path);
        return;
      }
      // A symlink that stays inside is followed to whatever it points at; one that leaves is still openable, so the
      // operator sees the refusal and its rule rather than a row that silently does nothing.
      open(entry.path, 0, preferHex);
    },
    [open, preferHex],
  );

  const extraction = listing?.extraction;
  const crumbs = dir ? dir.split('/') : [];

  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <div className="panel-title">Extracted files</div>
          <div className="panel-sub">
            Open what the extractor wrote to disk and read the bytes a finding cites. Reading a file establishes that
            the content is present in this extraction — it is not evidence about the running device.
          </div>
        </div>
      </div>

      {extraction ? (
        <div className={`banner ${STATE_TONE[extraction.state]}`} style={{ marginBottom: 14 }}>
          <span className="eyebrow">Extraction · {STATE_LABEL[extraction.state]}</span>
          <p style={{ margin: '4px 0 0' }}>{extraction.verdict}</p>
        </div>
      ) : null}

      {error ? (
        <div className="banner banner-warn" style={{ marginBottom: 14 }}>
          {error}
        </div>
      ) : null}

      {listing?.refusal ? (
        <div className="banner banner-warn" style={{ marginBottom: 14 }}>
          <span className="eyebrow">Refused · {listing.refusal.rule}</span>
          <p style={{ margin: '4px 0 0' }}>{listing.refusal.error}</p>
        </div>
      ) : null}

      {extraction && !extraction.browsable ? (
        <div className="empty">
          <div className="empty-title">Nothing on disk to browse</div>
          <p className="empty-body">
            This is not an empty filesystem. Read the verdict above — it says which of the several different reasons
            applies, and what would change it.
          </p>
        </div>
      ) : (
        <div className="fsb">
          <div className="fsb-pane">
            <div className="fsb-pane-head">
              <nav className="fsb-crumbs" aria-label="Extraction path">
                <button
                  type="button"
                  className="fsb-crumb"
                  onClick={() => setDir('')}
                  aria-current={dir ? undefined : 'page'}
                >
                  extract
                </button>
                {crumbs.map((name, i) => {
                  const target = crumbs.slice(0, i + 1).join('/');
                  return (
                    <span key={target} style={{ display: 'contents' }}>
                      <span className="fsb-sep">/</span>
                      <button
                        type="button"
                        className="fsb-crumb"
                        onClick={() => setDir(target)}
                        aria-current={i === crumbs.length - 1 ? 'page' : undefined}
                      >
                        {name}
                      </button>
                    </span>
                  );
                })}
              </nav>
              {listing?.listing ? (
                <span className="hint mono">
                  {listing.listing.dirCount} dir · {listing.listing.fileCount} file · {listing.listing.symlinkCount}{' '}
                  link
                </span>
              ) : null}
            </div>

            {loading && !listing ? (
              <div style={{ padding: 12, display: 'grid', gap: 6 }}>
                <div className="skeleton" style={{ height: 20 }} />
                <div className="skeleton" style={{ height: 20 }} />
                <div className="skeleton" style={{ height: 20 }} />
              </div>
            ) : null}

            {listing?.listing ? (
              <>
                <ul className="fsb-list">
                  {dir ? (
                    <li>
                      <button type="button" className="fsb-row is-dir" onClick={() => setDir(parentOf(dir))}>
                        <span className="fsb-mode">d---------</span>
                        <span className="fsb-name">
                          <span>..</span>
                        </span>
                        <span className="fsb-size" />
                      </button>
                    </li>
                  ) : null}
                  {listing.listing.entries.map((e) => (
                    <li key={e.path}>
                      <button
                        type="button"
                        className={`fsb-row ${e.type === 'dir' ? 'is-dir' : ''}`}
                        onClick={() => onEntry(e)}
                        aria-current={selected === e.path ? 'true' : undefined}
                      >
                        <span className="fsb-mode">{e.modeString}</span>
                        <span className="fsb-name">
                          <span>{e.name}</span>
                          {e.setuid ? <span className="badge badge-crit">setuid</span> : null}
                          {e.symlinkEscapes ? <span className="badge badge-warn">leaves extraction</span> : null}
                          {e.symlinkTarget ? <span className="fsb-link">&rarr; {e.symlinkTarget}</span> : null}
                        </span>
                        <span className="fsb-size">{e.type === 'file' ? fmtBytes(e.size) : ''}</span>
                      </button>
                    </li>
                  ))}
                </ul>
                {listing.listing.note ? <p className="fsb-bound">{listing.listing.note}</p> : null}
                {listing.listing.truncated ? <p className="fsb-bound">{listing.listing.truncationRule}</p> : null}
              </>
            ) : null}
          </div>

          <FileViewer
            read={read}
            selected={selected}
            preferHex={preferHex}
            onPreferHex={(hex) => {
              setPreferHex(hex);
              if (selected) open(selected, offset, hex);
            }}
            onSeek={(at) => selected && open(selected, at, preferHex)}
          />
        </div>
      )}
    </div>
  );
}

/**
 * The viewer. It leads with how much of the file it is holding, because a 64 KB window of a 7 MB binary looks
 * exactly like a whole file once it is on screen — and a reader who cannot see the difference will quote it as one.
 */
function FileViewer({
  read,
  selected,
  preferHex,
  onPreferHex,
  onSeek,
}: {
  read: FilesRead | null;
  selected: string | null;
  preferHex: boolean;
  onPreferHex: (hex: boolean) => void;
  onSeek: (offset: number) => void;
}): JSX.Element {
  if (!selected) {
    return (
      <div className="fsb-pane">
        <div className="fsb-pane-head">
          <span className="eyebrow">Viewer</span>
        </div>
        <div className="empty" style={{ padding: '36px 24px' }}>
          <div className="empty-title">Pick a file</div>
          <p className="empty-body">
            Text and binary are decided from the bytes, not from the extension — the mistake this panel exists to
            prevent was a <span className="mono">.pem</span> that turned out to hold a public key.
          </p>
        </div>
      </div>
    );
  }

  if (read?.refusal) {
    return (
      <div className="fsb-pane">
        <div className="fsb-pane-head">
          <span className="eyebrow">Refused · {read.refusal.rule}</span>
        </div>
        <div className="fsb-view">
          <p style={{ margin: 0, color: 'var(--text-dim)', fontSize: '0.8125rem', lineHeight: 1.55 }}>
            {read.refusal.error}
          </p>
        </div>
      </div>
    );
  }

  const r = read?.read;
  if (!r) {
    return (
      <div className="fsb-pane">
        <div className="fsb-pane-head">
          <span className="eyebrow">Viewer</span>
        </div>
        <div className="fsb-view">
          <div className="skeleton" style={{ height: 120 }} />
        </div>
      </div>
    );
  }

  const end = r.offset + r.bytesRead;
  const headline =
    r.size === 0
      ? 'Empty file — 0 bytes on disk.'
      : r.truncated
        ? `Showing bytes ${r.offset}–${end} of ${r.size}.`
        : `Whole file — all ${r.size} bytes.`;

  return (
    <div className="fsb-pane">
      <div className="fsb-pane-head">
        <span
          className="mono"
          style={{ fontSize: '0.75rem', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}
        >
          {r.path}
        </span>
        {/* biome-ignore lint/a11y/useSemanticElements: a segmented button group, matching the shell's theme toggle. */}
        <div className="segmented" role="group" aria-label="View">
          <button type="button" className={preferHex ? '' : 'active'} onClick={() => onPreferHex(false)}>
            Text
          </button>
          <button type="button" className={preferHex ? 'active' : ''} onClick={() => onPreferHex(true)}>
            Hex
          </button>
        </div>
      </div>

      <div className="fsb-view">
        <div className={`banner ${r.truncated ? 'banner-warn' : ''}`}>
          <strong>{headline}</strong>
          {r.truncationRule ? <p style={{ margin: '4px 0 0' }}>{r.truncationRule}</p> : null}
          {/* The classification carries its reason: "binary decided from the bytes" and "binary guessed from the
              extension" are different claims, and only the first one is being made. */}
          <p className="hint" style={{ margin: '6px 0 0' }}>
            {r.viewReason}
          </p>
          {r.adjustments.map((a) => (
            <p key={a} className="hint" style={{ margin: '2px 0 0' }}>
              {a}
            </p>
          ))}
        </div>

        {r.size === 0 ? null : (
          <pre className={`fsb-content ${r.view === 'text' ? 'is-text' : ''}`}>
            {r.view === 'text' ? r.text : r.hexdump}
          </pre>
        )}

        <div className="fsb-nav">
          <button
            type="button"
            className="btn btn-sm"
            disabled={r.offset === 0}
            onClick={() => onSeek(Math.max(0, r.offset - r.bytesRead))}
          >
            Previous
          </button>
          <button type="button" className="btn btn-sm" disabled={end >= r.size} onClick={() => onSeek(end)}>
            Next
          </button>
          <span className="hint">{r.claim}</span>
        </div>
      </div>
    </div>
  );
}
