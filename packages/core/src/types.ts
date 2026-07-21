/**
 * Shared domain types for the FirmLab firmware analysis core.
 *
 * These describe the deterministic, tool-independent analysis products (entropy profile, structural
 * signature map, filesystem model, string/secret hits). Heavier tool-backed products (SBOM, decompiler
 * output, emulation) reference these via ids but live in the API layer.
 */

/**
 * A coarse classification of what kind of firmware an image is, steering downstream analysis.
 *
 * The non-`embedded-linux` classes exist because a Linux/JFFS2 lens is actively wrong for them: an ESP SoC
 * flash dump, a bare-metal MCU image, a whole-image-encrypted OTA, and a FIT/UBI container each need a
 * different extractor and a different reasoning model. Collapsing them all to `embedded-linux` (the historical
 * behaviour of a looser-than-binwalk signature layer with no entropy gate) is the single most damaging
 * misclassification the workbench made — see docs/AUTONOMOUS-WORKERS.md §3.1.
 */
export type FirmwareClass =
  | 'embedded-linux' // a Linux rootfs is present or directly extractable (SquashFS/CramFS/ext/UBIFS/…)
  | 'openwrt-fit-ubi' // an OpenWrt-style FIT container wrapping a UBI image — needs a multi-stage carve first
  | 'esp-soc' // an Espressif ESP32/ESP8266 SoC flash dump (partition table + NVS + app images), not Linux
  | 'baremetal' // a bare-metal MCU image (e.g. RP2350 PICOBIN) — no filesystem, ISA-aware disassembly required
  | 'rtos' // an RTOS / Cortex-M blob emulable under Renode
  | 'uefi-bios' // a UEFI/BIOS platform firmware (firmware volumes), analyzed offline by chipsec
  | 'bootloader'
  | 'encrypted' // whole-image high entropy with no container header — not extractable without the key
  | 'unknown';

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
  | 'xtensa' // ESP32/ESP8266 classic cores
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

/**
 * How well a security finding has been proven — the honest audit→reproduce→prove-or-downgrade discipline made
 * explicit. Static analysis surfaces leads; emulation upgrades them; a target that cannot be emulated here is
 * downgraded honestly rather than overstated. Emulated proof is never conflated with device compromise: a
 * shell under qemu-user proves the sandbox, not the device.
 */
export type ProofState =
  | 'needs_runtime_reproduction' // plausible lead, not reproduced — the default for a static finding
  | 'static_confirmed' // reproducible from the firmware bytes alone (the secret/property is literally present)
  | 'confirmed_in_emulation' // reproduced under qemu-user / chroot service — proves the sandbox, NOT the device
  | 'confirmed_full_system' // reproduced in a full-system boot
  | 'blocked_by_platform' // the arch/blob cannot be emulated here; a dynamic claim would need hardware
  | 'blocked_by_security' // a valid control (validator/ACL) stops it
  | 'false_positive'; // evidence contradicts it, or pure device-class speculation with no artifact behind it

export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/**
 * A normalized security finding for an image, surfaced by any analysis provider and carrying an explicit proof
 * state. A finding always lives with its image and is backed by the provider evidence that produced it; the
 * corpus and (later) agent layers reference findings, never fabricate them.
 */
export interface Finding {
  id: string;
  imageId: string;
  /** The analysis that surfaced it: 'secrets' | 'gitleaks' | 'sbom' | 'binary' | 'emulation'. */
  source: string;
  /** Stable kind within the source, e.g. 'hardcoded-credential', 'cve', 'weak-hardening'. */
  kind: string;
  title: string;
  severity: FindingSeverity;
  proofState: ProofState;
  /** Structured evidence (the raw hit, CVE id, file path, emulation output…). */
  evidence?: Record<string, unknown>;
  /** Why it sits at this proof state — especially for downgrades. */
  rationale?: string;
  createdAt: number;
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
  /**
   * A one-line, honest explanation of why this class was chosen and what it implies for the operator —
   * especially "this is not Linux, so the standard rootfs pipeline does not apply". Powers the UI's
   * honest-degradation banner so "0 findings" is never confused with "clean" (docs/AUTONOMOUS-WORKERS.md §4).
   */
  classRationale?: string;
}
