/**
 * Shared domain types for the FirmLab firmware analysis core.
 *
 * These describe the deterministic, tool-independent analysis products (entropy profile, structural
 * signature map, filesystem model, string/secret hits). Heavier tool-backed products (SBOM, decompiler
 * output, emulation) reference these via ids but live in the API layer.
 */

/** A coarse classification of what kind of firmware an image is, steering downstream analysis. */
export type FirmwareClass = 'embedded-linux' | 'rtos' | 'uefi-bios' | 'bootloader' | 'unknown';

/** CPU architecture guessed from headers / embedded ELFs. */
export type Architecture =
  | 'mips'
  | 'mipsel'
  | 'mips64'
  | 'arm'
  | 'arm64'
  | 'x86'
  | 'x86_64'
  | 'ppc'
  | 'riscv'
  | 'sparc'
  | 'unknown';

export type Endianness = 'big' | 'little' | 'unknown';

/** A single entropy sample over one window of the image. */
export interface EntropySample {
  /** Byte offset of the window start. */
  offset: number;
  /** Shannon entropy in bits/byte, 0..8. */
  entropy: number;
}

/** Full entropy profile of an image plus derived interpretation. */
export interface EntropyProfile {
  windowSize: number;
  step: number;
  samples: EntropySample[];
  /** Mean entropy across the image. */
  mean: number;
  /** Max entropy observed. */
  max: number;
  /** Min entropy observed. */
  min: number;
  /**
   * Contiguous high-entropy regions (likely compressed/encrypted). A region that spans most of the image
   * with very high mean entropy is a strong hint the firmware is encrypted as a whole.
   */
  highEntropyRegions: EntropyRegion[];
  /** Human-readable interpretation flags. */
  likelyEncrypted: boolean;
  likelyCompressed: boolean;
}

export interface EntropyRegion {
  start: number;
  end: number;
  meanEntropy: number;
}

/** Confidence that a signature match is a true structural boundary, not a coincidental byte pattern. */
export type SignatureConfidence = 'high' | 'medium' | 'low';

/** A recognized magic-byte signature at an offset in the image. */
export interface SignatureHit {
  offset: number;
  /** Stable id of the signature rule that fired, e.g. `squashfs`, `uimage`, `gzip`. */
  id: string;
  /** Human label, e.g. "SquashFS filesystem, little-endian". */
  description: string;
  /** Category used to color/group the structural map. */
  category: SignatureCategory;
  confidence: SignatureConfidence;
  /** Optional fields decoded from the header (size, version, compression, arch…). */
  meta?: Record<string, string | number>;
}

export type SignatureCategory =
  | 'filesystem'
  | 'compression'
  | 'executable'
  | 'bootloader'
  | 'kernel'
  | 'container'
  | 'crypto'
  | 'certificate'
  | 'image'
  | 'other';

/** One contiguous segment of the structural map (derived from signature hits + entropy). */
export interface StructureSegment {
  start: number;
  end: number;
  label: string;
  category: SignatureCategory;
  confidence: SignatureConfidence;
  meta?: Record<string, string | number>;
}

/** A node in an extracted firmware root filesystem. */
export interface FsNode {
  path: string;
  name: string;
  type: 'dir' | 'file' | 'symlink' | 'device' | 'other';
  size: number;
  /** Unix mode bits when known (from the extractor), else undefined. */
  mode?: number;
  /** True if setuid/setgid — a first-class firmware attack-surface signal. */
  setuid?: boolean;
  setgid?: boolean;
  symlinkTarget?: string;
  /** SHA-1 of file contents when the extractor hashed it (files under a size cap), for content-level diffing. */
  sha1?: string;
  children?: FsNode[];
}

export interface FsSummary {
  totalFiles: number;
  totalDirs: number;
  totalSymlinks: number;
  setuidBinaries: FsNode[];
  worldWritable: FsNode[];
  /** Interesting config/secret-bearing files by convention (etc/passwd, shadow, *.pem …). */
  notable: FsNode[];
}

/** A string / potential-secret hit inside a binary blob. */
export interface StringHit {
  offset: number;
  value: string;
  /** Set when the string matched a secret/credential heuristic. */
  secretKind?: string;
  severity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

/** Top-level identity of an analyzed image. */
export interface ImageIdentity {
  firmwareClass: FirmwareClass;
  arch: Architecture;
  endianness: Endianness;
  vendor?: string;
  model?: string;
  filesystems: string[];
  bootloader?: string;
  kernel?: string;
}
