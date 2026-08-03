/**
 * Traditional DES `crypt(3)` ("descrypt"), in process — the one hash scheme this workbench cannot shell out for.
 *
 * `credmatch.ts` hashes its candidates with `openssl passwd`, which is the right call for every `$id$` scheme. It
 * is not an option for DES: **OpenSSL 3.0 removed `openssl passwd -crypt`** (`passwd: Unknown option: -crypt` on
 * the 3.0.20 in the deployed container), and DES is precisely the scheme the firmware in this corpus is full of —
 * the Tenda camera's `/etc/shadow` is a 13-character DES hash. Leaving it to a tool would have made the single
 * most common legacy scheme permanently `blocked_by_platform` on a modern base image, so it is computed here.
 *
 * That is also why it is a cipher module and not a provider one: it is pure arithmetic over bytes with no I/O, no
 * tool, no policy and nothing to degrade — hand it a password and a salt and it returns the same 13 characters
 * libcrypt does, on every platform, forever. It is verified against `crypt(3)` itself (glibc via perl 5.36) over
 * real vectors, including the two properties the caller depends on: **DES reads only the first 8 bytes of the
 * password**, so a 30-character string and its 8-character prefix hash identically, and it reads only the low 7
 * bits of each of those bytes.
 *
 * What it refuses to claim: this is DES, and DES is broken. Reproducing a hash here proves a plaintext maps to a
 * stored hash — a fact about the bytes — and nothing whatsoever about a device, an account being enabled, or a
 * service being reachable. It also computes exactly one scheme: anything with a `$` in it belongs to `openssl`,
 * and asking for it here is a programming error, not a fallback.
 */

// The DES tables, as FIPS 46-3 numbers them: every entry is a 1-based bit position, counted from the MOST
// significant bit of the value being permuted. They are transcribed rather than derived, so the unit tests check
// them against a real `crypt(3)` instead of against a second copy of the same transcription.

/**
 * Final permutation, 64 → 64. There is deliberately no `IP` table: the initial permutation is applied to the
 * all-zero block, which it leaves all-zero, and every intermediate FP/IP pair of the 25 chained encryptions
 * cancels — so the only permutation that survives is this one, once, at the end.
 */
const FP = [
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21,
  61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49,
  17, 57, 25,
];

/** The round function's output permutation, 32 → 32. Folded into `SP` below. */
const P = [
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
];

/** Permuted choice 1, 64 → 56 (drops the key's parity bits). */
const PC1 = [
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55,
  47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];

/** Permuted choice 2, 56 → 48 (one round's subkey). */
const PC2 = [
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30,
  40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/** Left-rotation applied to each key half, per round. */
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/** The eight substitution boxes, each 4 rows × 16 columns, flattened row-major. */
const SBOX = [
  [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1,
    14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
  ],
  [
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14,
    7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
  ],
  [
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6,
    4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
  ],
  [
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6,
    9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
  ],
  [
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1,
    11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
  ],
  [
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14,
    15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
  ],
  [
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4,
    11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
  ],
  [
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11,
    4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
  ],
];

/**
 * The crypt(3) base-64 alphabet. Note it is NOT RFC 4648: `.` and `/` lead, and the digits precede the letters —
 * a hash decoded with the wrong alphabet is wrong in a way that still looks like a hash.
 */
export const CRYPT64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/** How many characters of the password DES actually reads. Everything past this is discarded by the cipher. */
export const DES_PASSWORD_BYTES = 8;

/**
 * S-box output already carrying the `P` permutation, so a round is eight table reads and eight ORs instead of a
 * 32-iteration bit shuffle. Built once at module load from the tables above — the tables stay verbatim, which is
 * what keeps them checkable against the standard by eye.
 */
const SP: Int32Array[] = (() => {
  const tables: Int32Array[] = [];
  for (let box = 0; box < 8; box++) {
    const table = new Int32Array(64);
    const sbox = SBOX[box] as number[];
    for (let input = 0; input < 64; input++) {
      // DES addresses an S-box by the outer two bits (row) and the inner four (column).
      const row = ((input >> 4) & 2) | (input & 1);
      const col = (input >> 1) & 0xf;
      const value = sbox[row * 16 + col] as number;
      // Place the nibble where this box's output belongs in the 32-bit pre-permutation word, then permute.
      let pre = 0;
      for (let bit = 0; bit < 4; bit++) {
        if ((value >> (3 - bit)) & 1) pre |= 1 << (31 - (box * 4 + bit));
      }
      let out = 0;
      for (let k = 0; k < 32; k++) {
        if ((pre >>> (32 - (P[k] as number))) & 1) out |= 1 << (31 - k);
      }
      table[input] = out;
    }
    tables.push(table);
  }
  return tables;
})();

/** Rotate a 28-bit key half left by `n`. */
function rotl28(v: number, n: number): number {
  return ((v << n) | (v >>> (28 - n))) & 0x0fffffff;
}

/**
 * The 16 round subkeys, each as eight 6-bit groups (the shape the round function consumes).
 *
 * The key is the password, not a passphrase hash: byte `i` is `(password[i] & 0x7f) << 1`, i.e. the low seven bits
 * of the character shifted into the parity position DES then ignores. A password shorter than 8 bytes is padded
 * with NULs; one longer is truncated — that truncation is the caller-visible behaviour this module exists to be
 * exact about.
 */
function keySchedule(password: string): Int32Array[] {
  const bytes = Buffer.from(password, 'latin1');
  const keyBits = new Uint8Array(64);
  for (let i = 0; i < 8; i++) {
    const byte = i < bytes.length ? (((bytes[i] as number) & 0x7f) << 1) & 0xff : 0;
    for (let b = 0; b < 8; b++) keyBits[i * 8 + b] = (byte >> (7 - b)) & 1;
  }

  let c = 0;
  let d = 0;
  for (let i = 0; i < 28; i++) c = (c << 1) | (keyBits[(PC1[i] as number) - 1] as number);
  for (let i = 0; i < 28; i++) d = (d << 1) | (keyBits[(PC1[28 + i] as number) - 1] as number);

  const subkeys: Int32Array[] = [];
  for (let round = 0; round < 16; round++) {
    const shift = SHIFTS[round] as number;
    c = rotl28(c, shift);
    d = rotl28(d, shift);
    const key = new Int32Array(8);
    for (let i = 0; i < 48; i++) {
      const pos = (PC2[i] as number) - 1;
      const bit = pos < 28 ? (c >>> (27 - pos)) & 1 : (d >>> (27 - (pos - 28))) & 1;
      const group = (i / 6) | 0;
      if (bit) key[group] = (key[group] as number) | (1 << (5 - (i % 6)));
    }
    subkeys.push(key);
  }
  return subkeys;
}

/**
 * The expansion E, 32 → 48, delivered as eight 6-bit groups.
 *
 * E is regular: group `i` is bits `4i … 4i+5` of the right half, 1-indexed and wrapping, so rotating the word left
 * by one puts every group at a fixed shift. Group 0 is the only special case, because it is the one that wraps.
 */
function expand(r: number, out: Int32Array): void {
  const rot = ((r << 1) | (r >>> 31)) >>> 0;
  out[0] = ((rot & 3) << 4) | (rot >>> 28);
  for (let i = 1; i < 8; i++) out[i] = (rot >>> (28 - 4 * i)) & 0x3f;
}

/** Read bit `i` (0-based, from the most significant end) of a 48-bit value held as eight 6-bit groups. */
function getBit48(groups: Int32Array, i: number): number {
  return ((groups[(i / 6) | 0] as number) >>> (5 - (i % 6))) & 1;
}

/** Write bit `i` of a 48-bit value held as eight 6-bit groups. */
function setBit48(groups: Int32Array, i: number, value: number): void {
  const idx = (i / 6) | 0;
  const mask = 1 << (5 - (i % 6));
  if (value) groups[idx] = (groups[idx] as number) | mask;
  else groups[idx] = (groups[idx] as number) & ~mask;
}

/** Decode one crypt-base64 character; an out-of-alphabet character contributes 0 rather than throwing. */
function a64(ch: string | undefined): number {
  const i = ch === undefined ? -1 : CRYPT64.indexOf(ch);
  return i < 0 ? 0 : i;
}

/**
 * Pure: compute a traditional DES `crypt(3)` hash — `crypt("Td2N3ww1", "E0") === "E0HKrpNhcmto6"`.
 *
 * The construction, and why it looks the way it does:
 *
 *  - The plaintext is the all-zero block, encrypted 25 times under the password-derived key. Only the KEY and the
 *    salt vary, which is what makes the scheme a hash rather than a cipher.
 *  - The 12-bit salt (two crypt-base64 characters) perturbs the expansion: for each set salt bit `i`, bits `i` and
 *    `i+24` of E's 48-bit output are swapped. That is the whole of the salt's effect, and it is the reason a
 *    stock DES engine — `node:crypto`'s `des-ecb`, say — cannot be used to compute this.
 *  - `IP` and `FP` are inverses, so chaining 25 encryptions cancels every intermediate pair. `IP` of the all-zero
 *    block is the all-zero block, so it is omitted entirely and `FP` is applied once, at the end.
 *
 * The salt must be two characters of the crypt alphabet; anything else is read as 0, which is what libcrypt does
 * and is why a malformed hash produces a wrong answer rather than an exception. The caller is expected to have
 * validated the hash shape (`isDesHash`) before getting here.
 */
export function desCrypt(password: string, salt: string): string {
  const subkeys = keySchedule(password);
  const saltValue = a64(salt[0]) | (a64(salt[1]) << 6);

  let left = 0;
  let right = 0;
  const groups = new Int32Array(8);
  for (let iteration = 0; iteration < 25; iteration++) {
    for (let round = 0; round < 16; round++) {
      expand(right, groups);
      for (let i = 0; i < 12; i++) {
        if (!((saltValue >> i) & 1)) continue;
        const a = getBit48(groups, i);
        const b = getBit48(groups, i + 24);
        if (a !== b) {
          setBit48(groups, i, b);
          setBit48(groups, i + 24, a);
        }
      }
      const key = subkeys[round] as Int32Array;
      let f = 0;
      for (let i = 0; i < 8; i++) {
        f |= (SP[i] as Int32Array)[((groups[i] as number) ^ (key[i] as number)) & 0x3f] as number;
      }
      const next = (left ^ f) >>> 0;
      left = right;
      right = next;
    }
    // DES swaps the halves after the sixteenth round; between chained encryptions that swap is all that survives.
    const swap = left;
    left = right;
    right = swap;
  }

  // The preoutput block, then the final permutation. Dropping FP here is invisible to every structural check —
  // the result is still 13 characters of the crypt alphabet, and still deterministic — and wrong for every input,
  // which is exactly why the vectors below are `crypt(3)`'s own output and not this function's.
  const preoutput = new Uint8Array(64);
  for (let i = 0; i < 32; i++) preoutput[i] = (left >>> (31 - i)) & 1;
  for (let i = 0; i < 32; i++) preoutput[32 + i] = (right >>> (31 - i)) & 1;
  const permuted = new Uint8Array(64);
  for (let i = 0; i < 64; i++) permuted[i] = preoutput[(FP[i] as number) - 1] as number;

  // 64 bits encoded six at a time, most significant first, with the last group padded with two zero bits.
  let out = salt.slice(0, 2);
  for (let i = 0; i < 11; i++) {
    let v = 0;
    for (let b = 0; b < 6; b++) {
      const idx = i * 6 + b;
      v = (v << 1) | (idx < 64 ? (permuted[idx] as number) : 0);
    }
    out += CRYPT64[v] as string;
  }
  return out;
}

/** A traditional DES crypt hash: exactly 13 characters of the crypt alphabet, with no `$` scheme marker. */
const DES_HASH_RE = /^[./0-9A-Za-z]{13}$/;

/** Pure: is this shadow/passwd field a traditional DES crypt hash? */
export function isDesHash(value: string): boolean {
  return DES_HASH_RE.test(value);
}

/**
 * Pure: the part of a candidate DES actually hashes.
 *
 * This is not an optimisation, it is the finding's wording. `current_force_upgrade_pwd=Td2N3ww1.0_tenda_force_upgrade`
 * yields the candidate `Td2N3ww1.0_tenda_force_upgrade`, which reproduces the Tenda camera's stored hash — but the
 * secret is `Td2N3ww1`, because those are the only eight bytes that entered the cipher. Reporting the whole string
 * as "the password" would be reporting a coincidence of the harvest as if it were the credential.
 */
export function desEffectivePassword(candidate: string): string {
  return Buffer.from(candidate, 'latin1').subarray(0, DES_PASSWORD_BYTES).toString('latin1');
}
