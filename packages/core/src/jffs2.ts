/**
 * Pure JFFS2 node-header corroboration shared by signature scanning and image classification.
 *
 * The JFFS2 magic is only two bytes and occurs hundreds of times by chance in a large opaque blob. The next
 * 16-bit word is a format-defined node type, so it provides the cheapest structural distinction between a real
 * node header and incidental magic. Keeping that decision here prevents the scanner and classifier from
 * silently applying different standards, while letting the classifier re-check hits persisted by older builds.
 */

/** Signature ids whose byte order determines how the following JFFS2 node type is decoded. */
export type Jffs2SignatureId = 'jffs2-le' | 'jffs2-be';

/** Valid JFFS2 node types, including the compatibility and accuracy bits stored in the on-media word. */
const JFFS2_NODE_TYPES = new Set([0xe001, 0xe002, 0x2003, 0x2004, 0x2006, 0xe008, 0xe009]);

/**
 * Return whether a magic match at `offset` is followed by a valid JFFS2 node type in the matching byte order.
 * A truncated header is not corroborated. The caller remains responsible for matching the two magic bytes.
 */
export function isJffs2Node(buf: Uint8Array, offset: number, id: Jffs2SignatureId): boolean {
  const first = buf[offset + 2];
  const second = buf[offset + 3];
  if (first === undefined || second === undefined) return false;
  const nodeType = id === 'jffs2-le' ? first | (second << 8) : (first << 8) | second;
  return JFFS2_NODE_TYPES.has(nodeType);
}
