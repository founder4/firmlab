/**
 * Second-pass recovery — open the compressed blobs binwalk carves and does not recurse into.
 *
 * `binwalk -Me` walks into the containers it understands and leaves the rest as files: a raw LZMA stream out of a
 * uImage lands as `50040.7z`, an lzop payload as `4F0010.lzo`, and neither is opened. The blob then sits in the
 * output directory as a payload nobody looked at, and the extraction reports no rootfs — which is true and useless,
 * because "no rootfs" and "a rootfs we did not decompress" are the same sentence from the operator's side.
 *
 * So this decompresses what it can and hands the result back for a rescan. Two things it deliberately does NOT do:
 *
 *  • It does not guess a format from the extension. binwalk's `.7z` is usually not 7-Zip at all but a raw LZMA
 *    stream, so the format is read from the magic bytes and a blob whose magic says nothing is left alone rather
 *    than fed to a decompressor that will produce noise.
 *  • It does not claim the payload is interesting. Measured on this corpus, all three recoverable blobs decompress
 *    to something that is NOT a filesystem — BeanView's 3.2 MB lzop yields 225 KB of high-entropy data with no
 *    recognizable structure. The gain is that "unexamined" becomes "examined and not a filesystem", which is a
 *    different and honest statement, not that the images are rescued.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

/**
 * Is this decompressor on PATH? Deliberately not `isToolAvailable`: `unlzma`, `xz` and `gzip` ship with the base
 * image and are not capabilities worth a row in the Capabilities panel, while `lzop` is (it is registered there and
 * unlocks a whole payload family). The check is the same either way — the panel is about what the operator can
 * install to get more, not about every binary this code calls.
 */
function onPath(bin: string): boolean {
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    try {
      fs.accessSync(path.join(dir, bin), fs.constants.X_OK);
      return true;
    } catch {}
  }
  return false;
}

export type BlobFormat = 'lzma-alone' | 'lzop' | 'gzip' | 'xz';

/**
 * Pure: identify a carved blob from its magic bytes.
 *
 * Extension-driven dispatch is what makes this go wrong: binwalk names a raw LZMA stream `.7z`, which is a
 * different format entirely, and an `.lzo` may or may not carry the lzop container header. The magic decides.
 */
export function identifyBlob(head: Uint8Array): BlobFormat | null {
  if (head.length < 6) return null;
  // lzop container: 89 'L' 'Z' 'O' 00 0D 0A 1A 0A
  if (head[0] === 0x89 && head[1] === 0x4c && head[2] === 0x5a && head[3] === 0x4f) return 'lzop';
  // gzip
  if (head[0] === 0x1f && head[1] === 0x8b) return 'gzip';
  // xz: FD '7zXZ' 00
  if (head[0] === 0xfd && head[1] === 0x37 && head[2] === 0x7a && head[3] === 0x58 && head[4] === 0x5a) return 'xz';
  // LZMA "alone": a properties byte encoding lc/lp/pb (<= 224) then a power-of-two dictionary size.
  const props = head[0] as number;
  if (props <= 224 && head.length >= 13) {
    const dict =
      (head[1] as number) | ((head[2] as number) << 8) | ((head[3] as number) << 16) | ((head[4] as number) << 24);
    const dictSize = dict >>> 0;
    if (dictSize > 0 && (dictSize & (dictSize - 1)) === 0) return 'lzma-alone';
  }
  return null;
}

/** The external decompressor each format needs, and whether this deployment has it. */
const TOOL_FOR: Record<BlobFormat, { tool: string; args: (input: string, output: string) => string[] }> = {
  lzop: { tool: 'lzop', args: (i, o) => ['-d', '-f', '-o', o, i] },
  // `unlzma` is part of xz-utils and reads the alone format; `-c` keeps the carved blob intact.
  'lzma-alone': { tool: 'unlzma', args: (i, o) => ['-c', '-k', '-f', i, o] },
  xz: { tool: 'xz', args: (i, o) => ['-d', '-c', '-k', '-f', i, o] },
  gzip: { tool: 'gzip', args: (i, o) => ['-d', '-c', '-f', i, o] },
};

export interface BlobAttempt {
  blob: string;
  format: BlobFormat | null;
  /** Bytes produced, when a decompressor ran and wrote something. */
  bytes?: number;
  outcome: 'decompressed' | 'partial' | 'unreadable-format' | 'tool-absent' | 'failed';
  note: string;
}

export interface RecoverResult {
  attempts: BlobAttempt[];
  /** Directory holding everything this pass produced, for the caller to re-scan. Null when nothing was produced. */
  producedDir: string | null;
}

/** Blobs smaller than this are not worth a decompression pass (headers, fragments). */
const MIN_BLOB_BYTES = 4096;
/** Cap on what one blob may expand to, so a decompression bomb cannot fill the data volume. */
const MAX_OUTPUT_BYTES = 256 * 1024 * 1024;
const BLOB_EXT_RE = /\.(7z|lzma|lzo|xz|gz)$/i;

/** Read the first bytes of a file for magic identification. */
function readHead(abs: string, n = 32): Uint8Array | null {
  try {
    const fd = fs.openSync(abs, 'r');
    try {
      const b = Buffer.alloc(n);
      const read = fs.readSync(fd, b, 0, n, 0);
      return b.subarray(0, read);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}

/** Collect carved compressed blobs under `root`, bounded and de-duplicated by name+size. */
function collectCompressedBlobs(root: string, maxDepth = 4): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];
  while (stack.length > 0 && out.length < 16) {
    const { dir, depth } = stack.pop() as { dir: string; depth: number };
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (depth < maxDepth) stack.push({ dir: abs, depth: depth + 1 });
        continue;
      }
      if (!e.isFile() || !BLOB_EXT_RE.test(e.name)) continue;
      let size = 0;
      try {
        size = fs.statSync(abs).size;
      } catch {
        continue;
      }
      if (size < MIN_BLOB_BYTES) continue;
      // A re-run leaves the same carve under `_img.extracted` and `_img-0.extracted`; decompressing both would
      // double the work to reach the same bytes.
      const key = `${e.name}@${size}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(abs);
    }
  }
  return out;
}

/** One carved payload that came out of the image and was never opened. A size, not a claim about its contents. */
export interface UnopenedPayload {
  /** Path relative to the extraction output dir. */
  path: string;
  format: BlobFormat | null;
  bytes: number;
}

export interface PayloadSurvey {
  payloads: UnopenedPayload[];
  totalBytes: number;
  /** The sentence a successful extraction owes: what came out of the image that nobody looked inside. */
  note: string;
}

/**
 * Survey — never decompress — the compressed payloads sitting beside a rootfs that WAS recovered.
 *
 * The recovery pass above runs only when no rootfs was found, which leaves a real gap: an image that yields a small
 * rootfs *and* leaves multi-MB payloads unopened reports the rootfs and says nothing about the rest, so "we found a
 * rootfs" gets read as "we found everything". Measured on the corpus: the Tenda camera's extract dir holds two
 * **16.4 MB `.xz`** blobs and ~40 `.gz` beside a 97-file tree; the IMOU holds two 8.3 MB `.xz` and an 8 MB raw-LZMA
 * beside a 113-file tree. Both were invisible.
 *
 * The fix is deliberately NOT to decompress everything on every image — that is expensive, and the corpus already
 * showed those particular blobs are a kernel and two corrupt streams rather than a hidden rootfs. It is to STATE the
 * unopened bytes, the same way `diagnoseNoRootfs` states them after a failed extraction. So this reads sizes and
 * magic only.
 *
 * Payloads inside ANY extracted filesystem are excluded, not merely inside the one that was returned. A compressed
 * file the firmware legitimately ships is part of the filesystem and is already browsable — and, less obviously, a
 * re-extraction leaves the PREVIOUS run's tree behind as a sibling (`_img.extracted` beside `_img-0.extracted`), so
 * excluding only the current `rootfsPath` counts an older run's entire rootfs as unopened payload. The real IMOU
 * carve showed exactly that: `_IMOU-Ranger-2C.bin.extracted/squashfs-root/usr/lib/modules.7z` was reported as
 * unopened while the live rootfs was `_IMOU-Ranger-2C.bin-0.extracted/squashfs-root`. A directory is treated as a
 * filesystem root by the same >=2-of-`bin`/`etc`/`sbin`/`lib` rule `findRootfs` uses, so the exclusion follows what
 * the tree IS rather than what this run happened to name.
 */
const FS_ROOT_MARKERS = ['bin', 'etc', 'sbin', 'lib'];

/** Does this directory look like an extracted filesystem root (>=2 of bin/etc/sbin/lib)? */
function looksLikeFsRoot(dir: string): boolean {
  try {
    const names = new Set(
      fs
        .readdirSync(dir, { withFileTypes: true })
        .filter((e) => e.isDirectory())
        .map((e) => e.name),
    );
    return FS_ROOT_MARKERS.filter((m) => names.has(m)).length >= 2;
  } catch {
    return false;
  }
}

/** Is `abs` inside any extracted filesystem root at or below `outputDir`? */
function insideAnyFsRoot(abs: string, outputDir: string): boolean {
  let dir = path.dirname(path.resolve(abs));
  const stop = path.resolve(outputDir);
  while (dir.startsWith(stop) && dir !== stop) {
    if (looksLikeFsRoot(dir)) return true;
    dir = path.dirname(dir);
  }
  return false;
}

export function surveyUnopenedPayloads(outputDir: string, rootfsPath: string | null): PayloadSurvey {
  const inRootfs = rootfsPath ? path.resolve(rootfsPath) + path.sep : null;
  const payloads: UnopenedPayload[] = [];
  for (const abs of collectCompressedBlobs(outputDir)) {
    if (inRootfs && path.resolve(abs).startsWith(inRootfs)) continue;
    if (insideAnyFsRoot(abs, outputDir)) continue;
    let bytes = 0;
    try {
      bytes = fs.statSync(abs).size;
    } catch {
      continue;
    }
    const head = readHead(abs);
    payloads.push({ path: path.relative(outputDir, abs), format: head ? identifyBlob(head) : null, bytes });
  }
  payloads.sort((a, b) => b.bytes - a.bytes);
  const totalBytes = payloads.reduce((n, p) => n + p.bytes, 0);
  const note =
    payloads.length === 0
      ? 'No compressed payload was left unopened beside the recovered rootfs.'
      : `${payloads.length} compressed payload(s) totalling ${(totalBytes / (1024 * 1024)).toFixed(1)} MB were carved out of this image and NOT opened. The rootfs above is a real result; it is not the whole image, and nothing here says what these contain — only that nobody looked.`;
  return { payloads, totalBytes, note };
}

/**
 * Decompress the carved blobs a binwalk pass left unopened, into `<outputDir>/recovered`.
 *
 * Returns the per-blob record either way: a blob whose format is unreadable, or whose decompressor is not installed,
 * is reported as such rather than skipped, because "we did not look" and "we looked and found nothing" are the two
 * answers this provider exists to keep apart.
 */
export async function recoverFromCompressedBlobs(outputDir: string, handle: JobHandle): Promise<RecoverResult> {
  const blobs = collectCompressedBlobs(outputDir);
  if (blobs.length === 0) return { attempts: [], producedDir: null };

  const producedDir = path.join(outputDir, 'recovered');
  const attempts: BlobAttempt[] = [];
  let produced = false;

  for (const blob of blobs) {
    const head = readHead(blob);
    const format = head ? identifyBlob(head) : null;
    if (!format) {
      attempts.push({
        blob,
        format: null,
        outcome: 'unreadable-format',
        note: 'the magic bytes match no compression format this pass knows, so it was left alone rather than fed to a decompressor that would produce noise',
      });
      continue;
    }
    const spec = TOOL_FOR[format];
    if (!onPath(spec.tool)) {
      attempts.push({
        blob,
        format,
        outcome: 'tool-absent',
        note: `${format} payload, and ${spec.tool} is not installed here — the payload is unexamined, which is not the same as empty`,
      });
      continue;
    }

    fs.mkdirSync(producedDir, { recursive: true });
    const out = path.join(producedDir, `${path.basename(blob)}.out`);
    try {
      // Every decompressor here writes to stdout with `-c`, except lzop which takes `-o`; both are covered by the
      // arg builders, so the only difference is where the bytes land.
      const args = spec.args(blob, out);
      if (args.includes('-c')) {
        const { stdout } = await execFileAsync(
          spec.tool,
          args.filter((a) => a !== out),
          {
            timeout: 5 * 60 * 1000,
            maxBuffer: MAX_OUTPUT_BYTES,
            encoding: 'buffer',
          },
        );
        fs.writeFileSync(out, stdout);
      } else {
        await execFileAsync(spec.tool, args, { timeout: 5 * 60 * 1000, maxBuffer: 16 * 1024 * 1024 });
      }
    } catch (err) {
      // A decompressor that dies partway still produced something, and a truncated payload is itself the finding —
      // AliExpress's kernel LZMA stops at 384 KB of a declared 7.6 MB, which says the image is damaged rather than
      // unreadable. On the `-c` path those bytes are on the failed process's STDOUT and are lost unless taken from
      // the error, which is the same rescue dynprobe-run.ts does with gdb's output.
      const e = err as { stdout?: Buffer | string; stderr?: Buffer | string; message?: string };
      const partial = e.stdout ? Buffer.from(e.stdout as Buffer) : null;
      if (partial && partial.length > 0 && !fs.existsSync(out)) {
        fs.mkdirSync(producedDir, { recursive: true });
        fs.writeFileSync(out, partial);
      }
      // The tool's own first line of stderr says what happened; the reconstructed command line does not.
      const stderr = e.stderr
        ? Buffer.from(e.stderr as Buffer)
            .toString('utf8')
            .trim()
            .split('\n')[0]
        : '';
      const message = stderr || (e.message ?? String(err)).split('\n')[0];
      const bytes = fs.existsSync(out) ? fs.statSync(out).size : 0;
      attempts.push({
        blob,
        format,
        ...(bytes > 0 ? { bytes } : {}),
        outcome: bytes > 0 ? 'partial' : 'failed',
        note:
          bytes > 0
            ? `${format} stream stopped after ${bytes} bytes — a truncated or damaged payload, not a missing tool (${message})`
            : `${spec.tool} could not open it: ${message}`,
      });
      if (bytes > 0) produced = true;
      continue;
    }

    const bytes = fs.existsSync(out) ? fs.statSync(out).size : 0;
    attempts.push({
      blob,
      format,
      bytes,
      outcome: 'decompressed',
      note: `${format} payload opened to ${bytes} bytes; rescanned for a filesystem`,
    });
    if (bytes > 0) produced = true;
  }

  for (const a of attempts) handle.log(`  recover ${path.basename(a.blob)} [${a.outcome}]: ${a.note}`);
  return { attempts, producedDir: produced ? producedDir : null };
}
