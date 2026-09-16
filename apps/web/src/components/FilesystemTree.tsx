/**
 * Collapsible extracted-rootfs tree. Directories expand on click; setuid/setgid binaries and symlinks are
 * badged inline because they are the audit-relevant nodes. Backed by the FsNode tree the extractor produces.
 *
 * The row is a `<button>`, not a clickable `<div>`: it is the control that reveals the rest of the rootfs, so it has
 * to be reachable by keyboard and to state whether what it hides is currently shown. `aria-expanded` is set only
 * where there IS something to expand — a leaf or an empty directory carrying `aria-expanded="false"` would announce
 * collapsed content that does not exist.
 */
import { useState } from 'react';
import type { FsNode } from '../api';
import { fmtBytes } from '../api';

export function FilesystemTree({ root }: { root: FsNode }): JSX.Element {
  return (
    <div className="mono" style={{ fontSize: 13 }}>
      {(root.children ?? []).map((child) => (
        <TreeNode key={child.path} node={child} depth={0} />
      ))}
    </div>
  );
}

function TreeNode({ node, depth }: { node: FsNode; depth: number }): JSX.Element {
  const [open, setOpen] = useState(depth < 1);
  const isDir = node.type === 'dir';
  const hasChildren = isDir && (node.children?.length ?? 0) > 0;

  return (
    <div>
      <button
        type="button"
        onClick={() => hasChildren && setOpen((o) => !o)}
        aria-expanded={hasChildren ? open : undefined}
        style={{
          display: 'flex',
          width: '100%',
          alignItems: 'center',
          gap: 8,
          padding: '3px 6px',
          paddingLeft: 6 + depth * 16,
          border: 0,
          borderRadius: 6,
          background: 'transparent',
          font: 'inherit',
          textAlign: 'left',
          cursor: hasChildren ? 'pointer' : 'default',
        }}
        className="tree-row"
      >
        <span style={{ width: 12, color: 'var(--text-faint)' }}>{hasChildren ? (open ? '▾' : '▸') : ''}</span>
        <span style={{ color: isDir ? 'var(--accent)' : 'var(--text)' }}>
          {isDir ? '📁' : node.type === 'symlink' ? '🔗' : '📄'} {node.name}
        </span>
        {node.setuid && <span className="badge badge-crit">setuid</span>}
        {node.setgid && <span className="badge badge-high">setgid</span>}
        {node.type === 'symlink' && node.symlinkTarget && <span className="hint">→ {node.symlinkTarget}</span>}
        {node.type === 'file' && (
          <span className="hint" style={{ marginLeft: 'auto' }}>
            {fmtBytes(node.size)}
          </span>
        )}
      </button>
      {open && hasChildren && (
        <div>
          {node.children?.map((c) => (
            <TreeNode key={c.path} node={c} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}
