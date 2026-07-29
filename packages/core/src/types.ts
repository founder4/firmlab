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

/**
 * HOW a finding came to be known — a second axis, orthogonal to `ProofState`, and the two must never merge.
 *
 * `ProofState` answers *how far it was proven*. It says nothing about the means, and two findings on the same
 * rung can rest on completely different kinds of observation: `static_confirmed` covers both "these bytes are a
 * private key" (read directly) and "angr proved this sink is on a live path" (a solver's conclusion about a
 * program nobody ran). A reader who has to weigh a finding needs both, and until this existed only the rung was
 * a field — the means were prose in `rationale`, where nothing could group, filter or audit by them.
 *
 * The one that matters most is the distinction the workbench is otherwise blind to: something a program DID
 * (`emulated_run`, `probe_response`) versus something a tool CONCLUDED (`symbolic_execution`) versus something a
 * third party SAID (`external_advisory`). A CVE from a database and a crash reproduced under qemu are not the
 * same kind of knowledge, however their severities compare.
 *
 * Absent is a real value and means "not recorded", never "static". A finding written before this field existed,
 * or by a provider that has not been taught its channel, must not be silently read as having been observed in
 * the bytes — that would manufacture provenance out of a missing field, which this codebase has paid for once.
 */
export type EvidenceChannel =
  | 'static_bytes' // read directly out of the image or the extracted rootfs, as shipped
  | 'symbolic_execution' // a solver concluded it; no program was executed
  | 'emulated_run' // the program ran under emulation and was observed doing this
  | 'probe_response' // a service answered a request the workbench sent it
  | 'captured_traffic' // seen on the wire, in or out of a booted guest
  | 'external_advisory' // a published source says so (OSV, NVD, KEV, a vendor bulletin)
  | 'operator_report'; // a person or an agent reported it — see `OperatorAssertion` for who and on what basis

export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/**
 * The one value a finding's provenance field may hold that is NOT on the `ProofState` ladder.
 *
 * Every rung of `ProofState` is a claim code made after looking at something — bytes, a booted image, a blocked
 * probe. An operator finding has no such backing: a person says so. Reusing a rung for it would make the ladder
 * mean two incompatible things at once, and the whole workbench is built on the ladder meaning exactly one.
 *
 * So the field widens by exactly one value instead, and the value is deliberately self-describing: any reader
 * that predates this feature renders the literal string `operator_assertion` rather than silently mapping it to a
 * measurement. That is the safe direction to degrade — a stale UI shows an unfamiliar label, never
 * `static_confirmed` over an assertion nobody measured.
 */
export const OPERATOR_ASSERTION = 'operator_assertion';

/**
 * What a finding's provenance field may hold: a code-decided proof state, or the operator-assertion sentinel.
 * `ProofState` itself is untouched and still means "code decided this" — the ladder has not grown a rung.
 */
export type FindingProvenance = ProofState | typeof OPERATOR_ASSERTION;

/**
 * What kind of assertion a person is making. Deliberately a DISJOINT vocabulary from `ProofState`: not one token
 * is shared, so no substring, prefix or careless `includes()` can turn an assertion into a proof state, and a
 * reader that confuses the two has to work at it.
 *
 * The four are not degrees of confidence — they are provenances, and each one bounds a different reader question
 * ("could FirmLab have checked this itself?"). `asserted_from_device` is the reason this whole class exists:
 * an observation on physical hardware is knowledge this workbench structurally cannot produce, which is exactly
 * why `confirmed_full_system` stops at "full-system emulation" and never claims the device.
 */
export type OperatorClaim =
  | 'asserted_unverified' // a person believes it; nothing on the bench backs it
  | 'asserted_from_device' // observed on the physical hardware — outside anything FirmLab can measure
  | 'asserted_from_external_evidence' // a vendor advisory, datasheet, or third-party report says so
  | 'disputes_finding'; // a person says a code-decided finding is wrong, and why

/** Who wrote an assertion. Decided by the transport, never by the caller — see `mcp/server.ts`. */
export type OperatorAuthorKind = 'human' | 'agent';

/**
 * The record attached to an operator finding: who asserted it, when, on what basis, and whether it still stands.
 *
 * Withdrawal is a state here rather than a `DELETE`, because a ledger that can only forget cannot record "this
 * was wrong, and here is why" — and that sentence is often the most useful row in the file.
 */
export interface OperatorAssertion {
  /** The named person or agent making the claim. An assertion without an author is not an assertion. */
  assertedBy: string;
  /** Whether a human typed it or an agent recorded it — an agent's own note is not corroboration of its claim. */
  authorKind: OperatorAuthorKind;
  assertedAt: number;
  claim: OperatorClaim;
  /** Why the author believes it. Required: a claim with no stated basis is a rumour with a timestamp. */
  rationale: string;
  /** `withdrawn` rows stay in the ledger and are excluded from every count. */
  status: 'active' | 'withdrawn';
  /** Set only for `disputes_finding`: the code-decided finding this assertion contradicts. */
  disputesFindingId?: string;
  withdrawnBy?: string;
  withdrawnAt?: number;
  /** Why it was retracted — the part a deletion would have thrown away. */
  withdrawnReason?: string;
  /** Last amendment, if the author edited the claim after asserting it. */
  amendedAt?: number;
}

/**
 * A normalized security finding for an image, surfaced by any analysis provider and carrying an explicit proof
 * state. A finding always lives with its image and is backed by the provider evidence that produced it; the
 * corpus and (later) agent layers reference findings, never fabricate them.
 *
 * The one exception is an operator finding, which carries `proofState: 'operator_assertion'` and an `assertion`
 * record naming its author. It is evidence that a person asserted something — never a measurement.
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
  /** A code-decided proof state, or `operator_assertion` when `assertion` is set. Never both meanings at once. */
  proofState: FindingProvenance;
  /** Structured evidence (the raw hit, CVE id, file path, emulation output…). */
  evidence?: Record<string, unknown>;
  /** Why it sits at this proof state — especially for downgrades. */
  rationale?: string;
  /**
   * How this was known, alongside how far it was proven. Optional forever, and absent means NOT RECORDED — a
   * provider that has not been taught its channel, or a row written before the field existed. Never read an
   * absence as `static_bytes`.
   */
  evidenceChannel?: EvidenceChannel;
  /**
   * What was changed about the SUBJECT to obtain this observation. Absent or empty means the firmware as
   * shipped, and that is the whole point of the field: a service that answers only because the workbench
   * flushed the guest's firewall, or a response obtained after the workbench rewrote the traffic, is a
   * different claim from the same observation made against an untouched image — and `ProofState` cannot say so,
   * because the rung reached really is the rung reached.
   *
   * Free sentences rather than a taxonomy, deliberately: there are no interventions in this workbench yet, and
   * inventing a vocabulary for behaviour that does not exist would be guessing at the shape of the thing this
   * field exists to keep honest. The PRESENCE of an entry is the signal; the wording is the provider's, in its
   * own words, the way a finding's rationale is.
   */
  interventions?: string[];
  /**
   * Present iff this row was authored by a person or an agent rather than computed. Optional forever: every
   * finding stored before this field existed has no assertion, and its absence means "code decided this".
   */
  assertion?: OperatorAssertion;
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
