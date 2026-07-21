/**
 * @firmlab/core — deterministic, tool-independent firmware analysis primitives.
 *
 * Everything here is pure (bytes/strings in, structured data out) so it runs anywhere Node runs, needs no
 * Docker toolchain, and is fully unit-tested. The API layer composes these into analysis jobs and augments
 * them with tool-backed providers (binwalk, radare2/Ghidra, syft/grype, QEMU/Renode) when available.
 */
export * from './types.js';
export * from './entropy.js';
export * from './signatures.js';
export * from './structure.js';
export * from './strings.js';
export * from './binwalk.js';
export * from './filesystem.js';
export * from './mcu.js';
export { analyzeBuffer } from './analyze.js';
export type { StaticAnalysis } from './analyze.js';
