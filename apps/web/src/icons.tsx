/**
 * Icon set — a single coherent line-icon family (16px, 1.6 stroke, currentColor) so the chrome reads as one
 * system instead of the old grab-bag of unicode glyphs. Each icon is deliberately plain and functional; the
 * app's identity lives in type and the offset-gutter motif, not in decorative iconography.
 */
import type { JSX } from 'react';

type P = { size?: number };
const S = ({ size = 16, children }: { size?: number; children: JSX.Element | JSX.Element[] }): JSX.Element => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.7"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    {children}
  </svg>
);

export const Icon = {
  dashboard: (p: P) => (
    <S {...p}>
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </S>
  ),
  corpus: (p: P) => (
    <S {...p}>
      <ellipse cx="12" cy="5" rx="8" ry="3" />
      <path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5" />
      <path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" />
    </S>
  ),
  capabilities: (p: P) => (
    <S {...p}>
      <path d="M12 2a3 3 0 0 0-3 3v1.2A6 6 0 0 0 6 9H4a2 2 0 0 0 0 4h.4A6 6 0 0 0 6 15l-1 1.5a2 2 0 1 0 3 2L9 17a6 6 0 0 0 6 0l1 1.5a2 2 0 1 0 3-2L18 15a6 6 0 0 0 1.6-2H20a2 2 0 0 0 0-4h-2a6 6 0 0 0-3-2.8V5a3 3 0 0 0-3-3Z" />
      <circle cx="12" cy="11" r="2.2" />
    </S>
  ),
  settings: (p: P) => (
    <S {...p}>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1V21a2 2 0 1 1-4 0v-.1A1.6 1.6 0 0 0 7 19.4a1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0-1.1-2.7H1a2 2 0 1 1 0-4h.1A1.6 1.6 0 0 0 2.6 7a1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.6 1.6 0 0 0 7 2.6h.1A1.6 1.6 0 0 0 9 1.1V1a2 2 0 1 1 4 0v.1A1.6 1.6 0 0 0 15 2.6a1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8v.1a1.6 1.6 0 0 0 1.5 1H23a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1Z" />
    </S>
  ),
  overview: (p: P) => (
    <S {...p}>
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M3 9h18M9 21V9" />
    </S>
  ),
  structure: (p: P) => (
    <S {...p}>
      <rect x="2.5" y="7" width="4.5" height="10" rx="1" />
      <rect x="8.5" y="7" width="7" height="10" rx="1" />
      <rect x="17" y="7" width="4.5" height="10" rx="1" />
    </S>
  ),
  entropy: (p: P) => (
    <S {...p}>
      <path d="M3 17c2-6 3.5 2 5.5-3S12 5 14 12s3-1 4 2" />
      <path d="M3 20h18" opacity="0.5" />
    </S>
  ),
  filesystem: (p: P) => (
    <S {...p}>
      <path d="M4 5h5l2 2h9a1 1 0 0 1 1 1v9a2 2 0 0 1-2 2H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Z" />
    </S>
  ),
  secrets: (p: P) => (
    <S {...p}>
      <rect x="4" y="10" width="16" height="10" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3" />
      <circle cx="12" cy="15" r="1.3" />
    </S>
  ),
  binaries: (p: P) => (
    <S {...p}>
      <rect x="4" y="3" width="16" height="18" rx="2" />
      <path d="M8 7h2v4H8zM8 15h4M14 7h2v.01M14 11h2M14 15h2" />
    </S>
  ),
  sbom: (p: P) => (
    <S {...p}>
      <path d="M12 2 3 7v10l9 5 9-5V7Z" />
      <path d="M3 7l9 5 9-5M12 12v10" opacity="0.75" />
    </S>
  ),
  simulate: (p: P) => (
    <S {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M10 8.5v7l6-3.5Z" />
    </S>
  ),
  diff: (p: P) => (
    <S {...p}>
      <path d="M6 3v12a3 3 0 0 0 3 3h6" />
      <circle cx="6" cy="18" r="2.5" />
      <circle cx="18" cy="6" r="2.5" />
      <path d="M18 8.5V15" />
      <path d="M15 18h6M18 15v6" opacity="0.5" />
    </S>
  ),
  agent: (p: P) => (
    <S {...p}>
      <rect x="4" y="8" width="16" height="11" rx="2" />
      <path d="M12 8V4M9 4h6" />
      <circle cx="9" cy="13" r="1" />
      <circle cx="15" cy="13" r="1" />
    </S>
  ),
  sun: (p: P) => (
    <S {...p}>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </S>
  ),
  moon: (p: P) => (
    <S {...p}>
      <path d="M21 12.8A8.5 8.5 0 1 1 11.2 3a6.5 6.5 0 0 0 9.8 9.8Z" />
    </S>
  ),
  monitor: (p: P) => (
    <S {...p}>
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M8 20h8M12 16v4" />
    </S>
  ),
  help: (p: P) => (
    <S {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.2 9a2.8 2.8 0 0 1 5.4 1c0 1.8-2.6 2.2-2.6 3.6" />
      <path d="M12 17h.01" />
    </S>
  ),
  upload: (p: P) => (
    <S {...p}>
      <path d="M12 15V4M8 8l4-4 4 4" />
      <path d="M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3" />
    </S>
  ),
  search: (p: P) => (
    <S {...p}>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </S>
  ),
  chevron: (p: P) => (
    <S {...p}>
      <path d="m9 6 6 6-6 6" />
    </S>
  ),
  back: (p: P) => (
    <S {...p}>
      <path d="M19 12H5M11 6l-6 6 6 6" />
    </S>
  ),
  shield: (p: P) => (
    <S {...p}>
      <path d="M12 3 5 6v5c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6Z" />
    </S>
  ),
  capture: (p: P) => (
    <S {...p}>
      <circle cx="12" cy="12" r="1.5" />
      <path d="M8.5 15.5a5 5 0 0 1 0-7M15.5 8.5a5 5 0 0 1 0 7" />
      <path d="M6 18a9 9 0 0 1 0-12M18 6a9 9 0 0 1 0 12" />
    </S>
  ),
  plus: (p: P) => (
    <S {...p}>
      <path d="M12 5v14M5 12h14" />
    </S>
  ),
  close: (p: P) => (
    <S {...p}>
      <path d="M6 6l12 12M18 6 6 18" />
    </S>
  ),
  trash: (p: P) => (
    <S {...p}>
      <path d="M4 7h16M10 11v6M14 11v6" />
      <path d="M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12" />
      <path d="M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2" />
    </S>
  ),
  download: (p: P) => (
    <S {...p}>
      <path d="M12 4v11M8 11l4 4 4-4" />
      <path d="M5 19h14" />
    </S>
  ),
  play: (p: P) => (
    <S {...p}>
      <path d="M7 5l12 7-12 7Z" />
    </S>
  ),
  refresh: (p: P) => (
    <S {...p}>
      <path d="M4 12a8 8 0 0 1 14-5l2 2M20 12a8 8 0 0 1-14 5l-2-2" />
      <path d="M18 4v5h-5M6 20v-5h5" />
    </S>
  ),
};

export type IconName = keyof typeof Icon;
