import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { setLocale } from '../i18n';
import { IsolationPosture } from './IsolationPosture';

beforeEach(() => setLocale('en'));

describe('IsolationPosture', () => {
  it.each(['-n', '-rn'] as const)('shows a usable %s namespace without claiming full containment', (netns) => {
    render(<IsolationPosture phase4={{ isolation: 'partial', netns, resourceLimits: true }} />);
    expect(screen.getByText('Isolated from the host network')).toBeInTheDocument();
    expect(screen.getByText('Available')).toBeInTheDocument();
    expect(screen.getByText(/Filesystem, host processes and credentials are not isolated/)).toBeInTheDocument();
  });

  it('distinguishes partial containment with host networking', () => {
    render(<IsolationPosture phase4={{ isolation: 'partial', netns: null, resourceLimits: true }} />);
    expect(screen.getByText('Host network available')).toBeInTheDocument();
    expect(screen.queryByText('Isolated from the host network')).not.toBeInTheDocument();
  });

  it('does not infer network isolation from an older level field', () => {
    render(<IsolationPosture phase4={{ isolation: 'full' }} />);
    expect(screen.getAllByText('Not reported by this server')).toHaveLength(2);
  });

  it('keeps an absent posture unknown', () => {
    render(<IsolationPosture phase4={undefined} />);
    expect(screen.getAllByText('Not reported by this server')).toHaveLength(2);
  });

  it('translates absent resource restrictions and host networking in Spanish', () => {
    setLocale('es');
    render(<IsolationPosture phase4={{ isolation: 'none', netns: null, resourceLimits: false }} />);
    expect(screen.getByText('Red del host disponible')).toBeInTheDocument();
    expect(screen.getByText('No disponibles')).toBeInTheDocument();
  });
});
