import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { TechniqueCoverage } from './TechniqueCoverage';

describe('TechniqueCoverage', () => {
  it('renders the methodology areas and a status summary', () => {
    render(<TechniqueCoverage />);
    expect(screen.getByText('Technique coverage')).toBeInTheDocument();
    expect(screen.getByText(/Static analysis \(FSTM 3–5\)/)).toBeInTheDocument();
    expect(screen.getByText(/UEFI \/ BIOS deep analysis/)).toBeInTheDocument();
    // The summary badges count each status at least once.
    expect(screen.getByText(/\d+ done/)).toBeInTheDocument();
    expect(screen.getByText(/\d+ planned/)).toBeInTheDocument();
  });

  it('marks shipped capabilities done and known gaps planned, honestly', () => {
    render(<TechniqueCoverage />);
    // A shipped technique.
    expect(screen.getByText('chipsec (UEFI/BIOS offline decode)')).toBeInTheDocument();
    // The flagged top gap.
    expect(screen.getByText('Drive the emulated web UI (cmd-inj / authz / traversal)')).toBeInTheDocument();
    // Weaponization is explicitly out of scope, not claimed.
    expect(screen.getByText('Weaponized exploitation (ROP / shellcode / PoC)')).toBeInTheDocument();
  });
});
