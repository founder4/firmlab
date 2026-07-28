/**
 * techniques — the in-app map of this workbench against OWASP FSTM (9 stages) and OWASP ISTG (8 categories).
 * English source of truth.
 *
 * **Why the four status words are the load-bearing part.** Every row is a claim about what FirmLab does and does
 * not do, so a status that reads stronger than it is turns a coverage checklist into a sales page. `partial` must
 * never sound finished, `planned` must never sound available, and `out-of-scope` must read as a DELIBERATE
 * boundary — weaponised exploitation, chip-off and radio work are refused by design, not forgotten — rather than as
 * a gap. Those four are prose and are translated; nothing else on this screen that names the methodology is.
 *
 * **What is never translated.** `OWASP FSTM`, `ISTG` and the stage numbers in the area headings are the published
 * names of an external standard, and the entire purpose of this screen is that a reader can lay it beside the
 * published methodology and line the two up row for row. Translate an identifier and the mapping stops being a
 * mapping. The same holds for tool names (`binwalk`, `angr`, `AFL++`, `FwHunt`, `Ghidra`, `chipsec`, `Renode`,
 * `mitmproxy`), which appear inside technique names and travel through untouched.
 *
 * **Why the note column is split in two.** Most notes are a POINTER into this repository — `providers/report`,
 * `agent/intel`, `core/mcu + renode`. Those are identifiers, not sentences: they render in `mono`, they are
 * verbatim in every language, and they therefore live beside the checklist data rather than here. Only the notes
 * that are prose come through this catalogue, in `notes` below. The catalogue-integrity test states the same rule
 * from the other side — it refuses a Spanish string identical to its English source — so a pointer copied in here
 * would fail the suite, which is the shape of the design being enforced rather than a nuisance.
 *
 * Curated capability design, kept in sync with docs/METHODOLOGY-GAPS.md, and deliberately not per-deployment tool
 * detection: this says what the workbench is built to do, Capabilities says what this deployment can run.
 */
export const techniques = {
  title: 'Technique coverage',

  /** Around `docs/METHODOLOGY-GAPS.md`, which is a path and renders in `mono`. */
  sub: {
    beforeDoc: 'Firmware / IoT pentest techniques (OWASP FSTM + ISTG) mapped against what FirmLab does. See',
    afterDoc: 'for the full analysis.',
  },

  /**
   * The summary badges. Functions because the count agrees with a noun in Spanish and with nothing in English,
   * which is exactly the case a placeholder scheme gets wrong.
   */
  summary: {
    done: (n: number) => `${n} done`,
    partial: (n: number) => `${n} partial`,
    planned: (n: number) => `${n} planned`,
    outOfScope: (n: number) => `${n} out of scope`,
  },

  /**
   * The per-row badge. Short, because it sits in a narrow column — but `out-of-scope` still has to read as a
   * boundary and not as "we could not do it", which is what `planned` means and is a different answer. The long
   * form of that boundary is spelled out in the summary above the table.
   */
  status: {
    done: 'done',
    partial: 'partial',
    planned: 'planned',
    // `n/a` read as "not available" — which is what `planned` means. This is a DELIBERATE boundary
    // (weaponised exploitation, chip-off, radio work), so the badge says the exclusion is a decision.
    'out-of-scope': 'by design',
  },

  /** Stage and category numbers belong to OWASP, not to us. They travel through every language untouched. */
  areas: {
    recon: 'Recon & acquisition (FSTM 1–2)',
    static: 'Static analysis (FSTM 3–5)',
    emulation: 'Emulation (FSTM 6)',
    dynamic: 'Dynamic & runtime (FSTM 7–8)',
    comparison: 'Comparison / n-day localization',
    uefi: 'UEFI / BIOS deep analysis',
    rtos: 'RTOS / bare-metal deep analysis',
    reporting: 'Reporting & disclosure',
    hardware: 'Hardware / radio & exploitation',
  },

  /**
   * One entry per technique. The key is the id the checklist is built from, so a row added to the table without a
   * name here is a compile error rather than a blank cell.
   */
  items: {
    provenance: { name: 'Provenance fingerprint (vendor / model / version)' },
    osint: { name: 'OSINT vuln correlation — OSV + NVD + CISA KEV' },
    securityTxt: { name: 'Disclosure contact discovery (RFC 9116 security.txt)' },
    fccId: { name: 'FCC-ID lookup (public filings)' },
    upload: { name: 'Firmware upload' },
    lanDiscovery: { name: 'LAN device discovery + capture-backend detection' },
    otaIntercept: { name: 'OTA interception + firmware-flow carving + auto-ingest' },

    identity: { name: 'Entropy / structure map / class + arch identity' },
    extraction: { name: 'Filesystem extraction (squashfs/jffs2/ubifs/cramfs/cpio)' },
    secrets: { name: 'Secret & credential scan (+ gitleaks deep scan)' },
    sbom: { name: 'SBOM + CVE (syft → OSV/NVD/grype)' },
    hardening: { name: 'Binary hardening (NX / canary / PIC / RELRO)' },
    decompile: { name: 'Ghidra / radare2 triage + taint scaffold' },
    fsaudit: { name: 'Init-script / config-security heuristics (firmwalker-style)' },
    certs: { name: 'Certificate / key artifact analysis' },
    compmap: { name: 'Component dependency map (bins/libs/scripts)' },
    uboot: { name: 'Bootloader / U-Boot env + default bootargs' },

    qemuUser: { name: 'User-mode QEMU (single binary)' },
    chroot: { name: 'Chroot service + libnvram shim' },
    fullSystem: { name: 'Full-system boot (firmadyne kernel)' },
    renode: { name: 'Renode (RTOS / Cortex-M)' },
    chipsec: { name: 'chipsec (UEFI/BIOS offline decode)' },
    servicemap: { name: 'Service enumeration (boot-time attack surface)' },
    presets: { name: 'Saved emulation presets' },
    interactiveShell: { name: 'Run-command-in-emulation / interactive shell' },

    fuzzing: { name: 'Coverage-guided fuzzing (AFL++ file/stdin/network)' },
    isolation: { name: 'Auto-run under OS-primitive isolation' },
    webprobe: { name: 'Drive the emulated service — command injection + path traversal' },
    webAuthBypass: { name: 'Web auth-bypass / default-creds / POST-body injection' },
    interactiveGdb: { name: 'Interactive GDB in emulation (breakpoints on unsafe fns)' },
    symreach: { name: 'Symbolic reachability of taint leads (angr)' },
    crossBinary: { name: 'Cross-binary dataflow / stack-global layout' },
    cmplog: { name: 'cmplog / compcov + auto harness generation' },

    treeDiff: { name: 'Firmware tree + binary diff across versions' },
    functionDiff: { name: 'Function-level decompilation diff (BinDiff-style)' },
    kernelModuleCve: { name: 'Kernel module (.ko) CVE surface correlation' },

    efiInventory: { name: 'Firmware-volume + EFI module inventory' },
    bootkitLead: { name: 'Embedded-application bootkit lead' },
    iocFeed: { name: 'IOC feed hook (FIRMLAB_UEFI_IOC)' },
    secureBoot: { name: 'Secure Boot / NVRAM posture + test-key detection' },
    fwhunt: { name: 'Threat-rule scanning (FwHunt code-pattern rules)' },
    logofail: { name: 'LogoFAIL parsers / SMM callout analysis' },

    mcuFingerprint: { name: 'MCU fingerprint + real-catalog platform select' },
    bootLiveness: { name: 'Boot liveness (UART decides success)' },
    vectorTable: { name: 'Vector-table / base-address / memory-map + RTOS-kernel detect' },
    mmioFuzzing: { name: 'Peripheral / MMIO fuzzing (Fuzzware / µEmu)' },

    htmlReport: { name: 'Self-contained HTML analysis report' },
    disclosureDraft: { name: 'Coordinated-disclosure Markdown draft' },
    intelBrief: { name: 'Cited external-intelligence brief (LLM)' },
    pdfExport: { name: 'PDF export' },

    uartBridge: { name: 'Live-device UART console bridge (host-side)' },
    jtag: { name: 'JTAG / SWD / SPI extraction · chip-off' },
    bleDfu: { name: 'BLE DFU reassembly (Nordic)' },
    zigbeeOta: { name: 'Zigbee OTA-cluster reassembly (0x0019)' },
    wifiSdr: { name: 'Wi-Fi / SDR capture' },
    sideChannel: { name: 'Side-channel / fault injection (glitching)' },
    weaponization: { name: 'Weaponized exploitation (ROP / shellcode / PoC)' },
  },

  /**
   * The notes that are sentences rather than pointers — the "why", the "what it would take", the phase a capture
   * leg landed in. A row whose note is a `providers/…` path is not here at all; it carries the path beside its
   * status instead. Where a note is prose wrapped around an identifier (`providers/chipsec (offline)`,
   * `integrate fwhunt-scan`) only the prose moves, and the identifier is reproduced exactly.
   */
  notes: {
    osint: 'research/ (allowlisted, cited)',
    upload: 'manual ingest',
    lanDiscovery: 'Phase 6.0 (capture/)',
    otaIntercept: 'Phase 6.1: proxy→score→carve→ingest (live capture on deploy)',
    interactiveShell: 'live introspection',
    webAuthBypass: 'webprobe follow-up',
    interactiveGdb: 'runtime gap',
    symreach: 'proves reachability',
    crossBinary: 'taint extension',
    cmplog: 'fuzzing depth',
    functionDiff: 'localize the patch',
    kernelModuleCve: 'beyond userland SBOM',
    bootkitLead: 'chipsec scan',
    iocFeed: 'operator-supplied GUID/name IOCs',
    secureBoot: 'providers/chipsec (offline)',
    fwhunt: 'integrate fwhunt-scan',
    logofail: 'efiXplorer-class',
    mmioFuzzing: 'exercise the HAL',
    pdfExport: 'convenience',
    uartBridge: 'Phase-6 transport',
    jtag: 'hardware lab',
    bleDfu: 'Phase 6.4: reassembly done; live sniff = nRF dongle',
    zigbeeOta: 'Phase 6.5: reassembly + unwrap done; live sniff = CC2531/ConBee',
    wifiSdr: 'Phase-6 dongle',
    sideChannel: 'lab hardware',
    weaponization: 'defensive by design',
  },
};
