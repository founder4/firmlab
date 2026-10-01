import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { GhidraResult } from '../api';
import { setLocale } from '../i18n';
import { GhidraFunctions } from './GhidraFunctions';

beforeEach(() => setLocale('en'));

describe('GhidraFunctions', () => {
  it('bounds large saved listings and pseudocode without changing provider coverage', () => {
    const result: GhidraResult = {
      available: true,
      binary: 'bin/a',
      functionCount: 41,
      eligibleCount: 90,
      functions: Array.from({ length: 41 }, (_, i) => ({
        name: `fn${i}`,
        signature: '',
        pseudocode: 'x'.repeat(9000),
      })),
    };
    render(<GhidraFunctions result={result} />);
    expect(screen.getAllByRole('option')).toHaveLength(40);
    expect(document.querySelector('pre')?.textContent).toHaveLength(8000);
    expect(screen.getByText(/Display limited to 8,000 characters/)).toBeInTheDocument();
    expect(screen.getByText(/first 40 saved functions/)).toBeInTheDocument();
    expect(result.functionCount).toBe(41);
    expect(result.eligibleCount).toBe(90);
  });

  it('tolerates older saved function metadata with missing code', () => {
    render(
      <GhidraFunctions
        result={{
          available: true,
          binary: 'a',
          functionCount: 1,
          functions: [{ name: 'main' } as GhidraResult['functions'][number]],
        }}
      />,
    );
    expect(screen.getByText('No pseudocode was produced for this function.')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Function to read'), { target: { value: '0' } });
    expect(screen.getByRole('option', { name: 'main' })).toBeInTheDocument();
  });
});
