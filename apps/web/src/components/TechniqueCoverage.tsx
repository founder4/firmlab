/**
 * Technique coverage checklist — an in-app map of firmware/IoT pentest techniques (OWASP FSTM stages + ISTG
 * categories + class-specific deep analysis) against what FirmLab actually does. Each item carries a status:
 * done (a provider/agent does it), partial (manual or half-covered), planned (a real gap we intend to build), or
 * out-of-scope (hardware/radio/weaponization that a software workbench shouldn't claim). Kept in sync with
 * docs/METHODOLOGY-GAPS.md. Curated data (the workbench's capability design, not per-deployment tool detection).
 */

type CovStatus = 'done' | 'partial' | 'planned' | 'out-of-scope';

interface Technique {
  name: string;
  status: CovStatus;
  note: string;
}

interface CovGroup {
  area: string;
  items: Technique[];
}

const COVERAGE: CovGroup[] = [
  {
    area: 'Recon & acquisition (FSTM 1–2)',
    items: [
      { name: 'Provenance fingerprint (vendor / model / version)', status: 'done', note: 'providers/provenance' },
      { name: 'OSINT vuln correlation — OSV + NVD + CISA KEV', status: 'done', note: 'research/ (allowlisted, cited)' },
      { name: 'Disclosure contact discovery (RFC 9116 security.txt)', status: 'done', note: 'providers/securitytxt' },
      { name: 'FCC-ID lookup (public filings)', status: 'done', note: 'providers/fcc' },
      { name: 'Firmware upload', status: 'done', note: 'manual ingest' },
      { name: 'OTA interception & carving from live update', status: 'planned', note: 'Phase-6 Capture (designed)' },
    ],
  },
  {
    area: 'Static analysis (FSTM 3–5)',
    items: [
      { name: 'Entropy / structure map / class + arch identity', status: 'done', note: '@firmlab/core' },
      { name: 'Filesystem extraction (squashfs/jffs2/ubifs/cramfs/cpio)', status: 'done', note: 'providers/extract' },
      { name: 'Secret & credential scan (+ gitleaks deep scan)', status: 'done', note: 'core + gitleaks' },
      { name: 'SBOM + CVE (syft → OSV/NVD/grype)', status: 'done', note: 'providers/sbom + research' },
      { name: 'Binary hardening (NX / canary / PIC / RELRO)', status: 'done', note: 'radare2 checksec' },
      { name: 'Ghidra / radare2 triage + taint scaffold', status: 'done', note: 'providers/decompile + zeroday' },
      {
        name: 'Init-script / config-security heuristics (firmwalker-style)',
        status: 'done',
        note: 'providers/fsaudit',
      },
      { name: 'Certificate / key artifact analysis', status: 'done', note: 'providers/certs (X.509)' },
      { name: 'Component dependency map (bins/libs/scripts)', status: 'done', note: 'providers/compmap' },
      { name: 'Bootloader / U-Boot env + default bootargs', status: 'done', note: 'providers/uboot' },
    ],
  },
  {
    area: 'Emulation (FSTM 6)',
    items: [
      { name: 'User-mode QEMU (single binary)', status: 'done', note: 'providers/emulate' },
      { name: 'Chroot service + libnvram shim', status: 'done', note: 'providers/emulate-system' },
      { name: 'Full-system boot (firmadyne kernel)', status: 'done', note: 'providers/emulate-system' },
      { name: 'Renode (RTOS / Cortex-M)', status: 'done', note: 'providers/renode' },
      { name: 'chipsec (UEFI/BIOS offline decode)', status: 'done', note: 'providers/chipsec' },
      { name: 'Service enumeration (boot-time attack surface)', status: 'done', note: 'providers/servicemap' },
      { name: 'Saved emulation presets', status: 'done', note: 'routes/presets + PresetsPanel' },
      { name: 'Run-command-in-emulation / interactive shell', status: 'planned', note: 'live introspection' },
    ],
  },
  {
    area: 'Dynamic & runtime (FSTM 7–8)',
    items: [
      { name: 'Coverage-guided fuzzing (AFL++ file/stdin/network)', status: 'done', note: 'providers/fuzz' },
      { name: 'Auto-run under OS-primitive isolation', status: 'done', note: 'providers/isolate' },
      {
        name: 'Drive the emulated service — command injection + path traversal',
        status: 'done',
        note: 'providers/webprobe',
      },
      { name: 'Web auth-bypass / default-creds / POST-body injection', status: 'planned', note: 'webprobe follow-up' },
      { name: 'Interactive GDB in emulation (breakpoints on unsafe fns)', status: 'planned', note: 'runtime gap' },
      { name: 'Symbolic reachability of taint leads (angr)', status: 'planned', note: 'proves reachability' },
      { name: 'Cross-binary dataflow / stack-global layout', status: 'planned', note: 'taint extension' },
      { name: 'cmplog / compcov + auto harness generation', status: 'planned', note: 'fuzzing depth' },
    ],
  },
  {
    area: 'Comparison / n-day localization',
    items: [
      { name: 'Firmware tree + binary diff across versions', status: 'done', note: 'providers/diff' },
      { name: 'Function-level decompilation diff (BinDiff-style)', status: 'planned', note: 'localize the patch' },
      { name: 'Kernel module (.ko) CVE surface correlation', status: 'planned', note: 'beyond userland SBOM' },
    ],
  },
  {
    area: 'UEFI / BIOS deep analysis',
    items: [
      { name: 'Firmware-volume + EFI module inventory', status: 'done', note: 'chipsec' },
      { name: 'Embedded-application bootkit lead', status: 'done', note: 'chipsec scan' },
      { name: 'IOC feed hook (FIRMLAB_UEFI_IOC)', status: 'done', note: 'operator-supplied GUID/name IOCs' },
      { name: 'Secure Boot / NVRAM posture + test-key detection', status: 'done', note: 'providers/chipsec (offline)' },
      { name: 'Threat-rule scanning (FwHunt code-pattern rules)', status: 'planned', note: 'integrate fwhunt-scan' },
      { name: 'LogoFAIL parsers / SMM callout analysis', status: 'planned', note: 'efiXplorer-class' },
    ],
  },
  {
    area: 'RTOS / bare-metal deep analysis',
    items: [
      { name: 'MCU fingerprint + real-catalog platform select', status: 'done', note: 'core/mcu + renode' },
      { name: 'Boot liveness (UART decides success)', status: 'done', note: 'renode' },
      { name: 'Vector-table / base-address / memory-map + RTOS-kernel detect', status: 'done', note: 'providers/rtos' },
      { name: 'Peripheral / MMIO fuzzing (Fuzzware / µEmu)', status: 'planned', note: 'exercise the HAL' },
    ],
  },
  {
    area: 'Reporting & disclosure',
    items: [
      { name: 'Self-contained HTML analysis report', status: 'done', note: 'providers/report' },
      { name: 'Coordinated-disclosure Markdown draft', status: 'done', note: 'providers/disclosure' },
      { name: 'Cited external-intelligence brief (LLM)', status: 'done', note: 'agent/intel' },
      { name: 'PDF export', status: 'planned', note: 'convenience' },
    ],
  },
  {
    area: 'Hardware / radio & exploitation',
    items: [
      { name: 'Live-device UART console bridge (host-side)', status: 'planned', note: 'Phase-6 transport' },
      { name: 'JTAG / SWD / SPI extraction · chip-off', status: 'out-of-scope', note: 'hardware lab' },
      { name: 'BLE / ZigBee / Wi-Fi / SDR capture', status: 'out-of-scope', note: 'Phase-6 dongle' },
      { name: 'Side-channel / fault injection (glitching)', status: 'out-of-scope', note: 'lab hardware' },
      { name: 'Weaponized exploitation (ROP / shellcode / PoC)', status: 'out-of-scope', note: 'defensive by design' },
    ],
  },
];

const STATUS_META: Record<CovStatus, { label: string; badge: string; symbol: string }> = {
  done: { label: 'done', badge: 'badge-ok', symbol: '✓' },
  partial: { label: 'partial', badge: 'badge-medium', symbol: '◐' },
  planned: { label: 'planned', badge: 'badge-accent', symbol: '▢' },
  'out-of-scope': { label: 'n/a', badge: '', symbol: '—' },
};

export function TechniqueCoverage(): JSX.Element {
  const all = COVERAGE.flatMap((g) => g.items);
  const count = (s: CovStatus): number => all.filter((t) => t.status === s).length;

  return (
    <div className="panel" style={{ marginTop: 20 }}>
      <div className="panel-title">Technique coverage</div>
      <div className="panel-sub">
        Firmware / IoT pentest techniques (OWASP FSTM + ISTG) mapped against what FirmLab does. See{' '}
        <span className="mono">docs/METHODOLOGY-GAPS.md</span> for the full analysis.
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '4px 0 16px' }}>
        <span className="badge badge-ok">{count('done')} done</span>
        <span className="badge badge-medium">{count('partial')} partial</span>
        <span className="badge badge-accent">{count('planned')} planned</span>
        <span className="badge">{count('out-of-scope')} out of scope</span>
      </div>

      {COVERAGE.map((group) => (
        <div key={group.area} style={{ marginBottom: 18 }}>
          <div className="nav-section" style={{ margin: '0 0 8px' }}>
            {group.area}
          </div>
          <table className="data">
            <tbody>
              {group.items.map((t) => {
                const meta = STATUS_META[t.status];
                return (
                  <tr key={t.name} style={t.status === 'out-of-scope' ? { opacity: 0.62 } : undefined}>
                    <td style={{ width: 92 }}>
                      <span className={`badge ${meta.badge}`}>
                        {meta.symbol} {meta.label}
                      </span>
                    </td>
                    <td>{t.name}</td>
                    <td className="hint mono" style={{ width: 190 }}>
                      {t.note}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}
