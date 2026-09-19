/**
 * Curated Linux-kernel CVE triage with three-state subsystem gating.
 *
 * A version range is only a candidate generator: vendor backports and runtime reachability remain unknown. Required
 * subsystems are resolved from, in descending confidence, a shipped `.config`, module inventory, a structurally
 * complete kallsyms table, then distinctive kernel strings. Only an authoritative config, or complete kallsyms plus
 * complete module coverage, may turn absence into `off`; every other absence remains `unknown`.
 */
import type { EvidenceChannel, FindingSeverity, ProofState } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';
import { type DeviceContext, deviceContextTriage } from './cve-device-triage.js';
import type { DecodedKallsyms } from './kallsyms.js';
import type { KernelPostureResult } from './kernelposture.js';
import { LINUX_KERNEL_CNA_SOURCE, type NvdCandidate, type NvdComponentResult } from './nvd.js';

export type KernelOptionState = 'on' | 'off' | 'unknown';
export type KernelCveState = 'applicable' | 'ruled_out' | 'unknown';

export interface KernelOptionAssessment {
  option: string;
  state: KernelOptionState;
  evidence: string | null;
}

export interface KernelConfigEvidence {
  config: Readonly<Record<string, string>> | null;
  kallsyms: DecodedKallsyms | null;
  /** Basenames without `.ko`; positive evidence remains usable when `complete` is false. */
  modules: { names: ReadonlySet<string>; complete: boolean } | null;
  kernelStrings: string | null;
}

interface OptionKnowledge {
  option: string;
  symbols: readonly string[];
  modules: readonly string[];
  strings: readonly string[];
  builtinOnly: boolean;
}

export const KERNEL_OPTION_KNOWLEDGE: readonly OptionKnowledge[] = [
  {
    option: 'CONFIG_NETFILTER',
    symbols: ['nf_hook_slow', 'nf_register_net_hook', 'nf_register_hook'],
    modules: ['x_tables', 'nf_conntrack'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_NF_TABLES',
    symbols: ['nft_do_chain', 'nft_register_obj', 'nf_tables_api_init'],
    modules: ['nf_tables'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_BPF_SYSCALL',
    symbols: ['bpf_prog_load', 'bpf_check', '__sys_bpf'],
    modules: [],
    strings: [],
    builtinOnly: true,
  },
  { option: 'CONFIG_BPF_UNPRIV_DEFAULT_OFF', symbols: [], modules: [], strings: [], builtinOnly: false },
  {
    option: 'CONFIG_NET_CLS_ROUTE4',
    symbols: ['route4_classify'],
    modules: ['cls_route'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_NET_CLS_TCINDEX',
    symbols: ['tcindex_classify'],
    modules: ['cls_tcindex'],
    strings: [],
    builtinOnly: false,
  },
  { option: 'CONFIG_NET_CLS_U32', symbols: ['u32_classify'], modules: ['cls_u32'], strings: [], builtinOnly: false },
  {
    option: 'CONFIG_IO_URING',
    symbols: ['io_submit_sqes', 'io_uring_create', '__do_sys_io_uring_setup'],
    modules: [],
    strings: ['io_uring'],
    builtinOnly: true,
  },
  {
    option: 'CONFIG_UNIX',
    symbols: ['unix_create', 'unix_stream_connect', 'unix_dgram_recvmsg'],
    modules: ['unix'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_PACKET',
    symbols: ['packet_rcv', 'tpacket_rcv', 'packet_create'],
    modules: ['af_packet'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_USER_NS',
    symbols: ['create_user_ns', 'free_user_ns'],
    modules: [],
    strings: [],
    builtinOnly: true,
  },
  {
    option: 'CONFIG_CGROUPS',
    symbols: ['cgroup_attach_task', 'cgroup_mkdir', 'cgroup_procs_write'],
    modules: [],
    strings: [],
    builtinOnly: true,
  },
  {
    option: 'CONFIG_OVERLAY_FS',
    symbols: ['ovl_fill_super', 'ovl_lookup'],
    modules: ['overlay'],
    strings: ['overlayfs'],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_FUSE_FS',
    symbols: ['fuse_fill_super', 'fuse_dev_read', 'fuse_request_alloc'],
    modules: ['fuse'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_ANDROID_BINDER_IPC',
    symbols: ['binder_ioctl', 'binder_thread_read'],
    modules: ['binder', 'binder_linux'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_IP_DCCP',
    symbols: ['dccp_v4_init_sock', 'dccp_rcv_state_process'],
    modules: ['dccp', 'dccp_ipv4', 'dccp_ipv6'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_VSOCKETS',
    symbols: ['__vsock_create', 'vsock_bind'],
    modules: ['vsock'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_POSIX_MQUEUE',
    symbols: ['mqueue_get_inode', 'mqueue_evict_inode'],
    modules: [],
    strings: [],
    builtinOnly: true,
  },
  {
    option: 'CONFIG_INET_ESP',
    symbols: ['esp_init_state', 'esp6_init_state', 'esp_output'],
    modules: ['esp4', 'esp6'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_OPENVSWITCH',
    symbols: ['ovs_dp_process_packet', 'ovs_vport_receive'],
    modules: ['openvswitch'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_TIPC',
    symbols: ['tipc_sk_create', 'tipc_rcv'],
    modules: ['tipc'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_MAC80211',
    symbols: ['ieee80211_register_hw', 'ieee80211_rx_list'],
    modules: ['mac80211'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_BT',
    symbols: ['hci_register_dev', 'l2cap_recv_frame'],
    modules: ['bluetooth'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_QAT',
    symbols: ['adf_dev_init', 'qat_algs_register'],
    modules: ['intel_qat', 'qat_c62x', 'qat_4xxx', 'qat_dh895xcc'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_SCSI_ISCSI_ATTRS',
    symbols: ['iscsi_create_session', 'iscsi_add_session'],
    modules: ['scsi_transport_iscsi'],
    strings: [],
    builtinOnly: false,
  },
  { option: 'CONFIG_KEYS', symbols: ['key_alloc', 'keyring_alloc'], modules: [], strings: [], builtinOnly: true },
  {
    option: 'CONFIG_PERF_EVENTS',
    symbols: ['perf_event_alloc', 'perf_event_create_kernel_counter'],
    modules: [],
    strings: [],
    builtinOnly: true,
  },
  // ─── The subsystems the NVD prefix query is NOISIEST about, and that embedded images least often ship ───
  //
  // These are here for `subsystemGate` below rather than for any curated rule: a broad Linux-kernel CNA query
  // returns thousands of rows, a large share of them in GPU, sound and USB-gadget drivers that a router or an
  // IP camera does not build. Each option is resolved by the SAME three-state `inferKernelOption` as the rest,
  // so an absent symbol table still yields `unknown` and rules nothing out.
  {
    option: 'CONFIG_DRM',
    symbols: ['drm_dev_register', 'drm_dev_alloc', 'drm_open', 'drm_ioctl'],
    modules: ['drm', 'drm_kms_helper'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_FB',
    symbols: ['register_framebuffer', 'unregister_framebuffer', 'fb_set_var'],
    modules: ['fb', 'fbcon'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_SOUND',
    symbols: ['snd_card_new', 'snd_pcm_new', 'snd_ctl_add'],
    modules: ['snd', 'snd_pcm', 'soundcore'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_USB_GADGET',
    symbols: ['usb_gadget_probe_driver', 'usb_add_gadget_udc', 'usb_ep_queue'],
    modules: ['libcomposite', 'usb_f_fs', 'g_ether'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_INFINIBAND',
    symbols: ['ib_register_device', 'ib_create_cq'],
    modules: ['ib_core', 'ib_uverbs'],
    strings: [],
    builtinOnly: false,
  },
  {
    option: 'CONFIG_KVM',
    symbols: ['kvm_vcpu_ioctl', 'kvm_dev_ioctl_create_vm'],
    modules: ['kvm'],
    strings: [],
    builtinOnly: false,
  },
];

/**
 * Subsystem prefixes as the Linux CNA writes them, mapped to the option that has to be built for the flaw to
 * exist on this device.
 *
 * The Linux kernel CNA quotes the fixing commit's subject verbatim, and kernel commit subjects carry a
 * `subsystem: summary` prefix by long convention — `drm/amdgpu: fix use-after-free`, `usb: gadget: f_fs: ...`,
 * `ALSA: usb-audio: ...`. That prefix is a much stronger signal than the word appearing anywhere in the text,
 * which is why `subsystemGate` anchors on it and does not grep: an advisory that merely MENTIONS drm while
 * fixing something in the scheduler must not be ruled out because this image has no GPU.
 *
 * Ordered longest-first so `usb: gadget:` is tested before a bare `usb:` would be, if one is ever added.
 */
const SUBSYSTEM_MARKERS: readonly { prefix: string; option: string }[] = [
  { prefix: 'usb: gadget:', option: 'CONFIG_USB_GADGET' },
  { prefix: 'usb: f_fs:', option: 'CONFIG_USB_GADGET' },
  { prefix: 'drm/', option: 'CONFIG_DRM' },
  { prefix: 'drm:', option: 'CONFIG_DRM' },
  { prefix: 'fbdev:', option: 'CONFIG_FB' },
  { prefix: 'fbcon:', option: 'CONFIG_FB' },
  { prefix: 'video: fbdev:', option: 'CONFIG_FB' },
  { prefix: 'ALSA:', option: 'CONFIG_SOUND' },
  { prefix: 'ASoC:', option: 'CONFIG_SOUND' },
  { prefix: 'sound:', option: 'CONFIG_SOUND' },
  { prefix: 'Bluetooth:', option: 'CONFIG_BT' },
  { prefix: 'RDMA/', option: 'CONFIG_INFINIBAND' },
  { prefix: 'IB/', option: 'CONFIG_INFINIBAND' },
  { prefix: 'KVM:', option: 'CONFIG_KVM' },
  { prefix: 'KVM/', option: 'CONFIG_KVM' },
];

/** The boilerplate the Linux CNA puts in front of every advisory before the commit subject. */
const CNA_PREAMBLE = /^\s*In the Linux kernel,?\s*the following vulnerability has been resolved:\s*/i;

export interface SubsystemGate {
  option: string;
  state: KernelOptionState;
  evidence: string | null;
  /** The commit-subject prefix that identified the subsystem — quoted so the reader can check the inference. */
  marker: string;
}

/**
 * Pure: which kernel subsystem an advisory is about, and whether this image builds it.
 *
 * Returns null when the summary carries no recognised subsystem prefix, which is the majority of advisories and
 * the correct answer for them: no gate, no pruning, the row stands. **The only outcome that removes anything is
 * `off`**, and `inferKernelOption` reaches `off` only from an authoritative config or from complete kallsyms
 * plus complete module coverage — so an image whose evidence is thin prunes nothing at all.
 */
export function subsystemGate(
  summary: string | null | undefined,
  options: readonly KernelOptionAssessment[],
): SubsystemGate | null {
  if (!summary) return null;
  const body = summary.replace(CNA_PREAMBLE, '').trimStart();
  const hit = SUBSYSTEM_MARKERS.find((m) => body.toLowerCase().startsWith(m.prefix.toLowerCase()));
  if (!hit) return null;
  const assessed = options.find((o) => o.option === hit.option);
  if (!assessed) return null;
  return { option: hit.option, state: assessed.state, evidence: assessed.evidence, marker: hit.prefix };
}

function normalizedModule(name: string): string {
  return name.replace(/\.ko$/, '').replaceAll('-', '_');
}

export function inferKernelOption(option: string, evidence: KernelConfigEvidence): KernelOptionAssessment {
  const known = KERNEL_OPTION_KNOWLEDGE.find((entry) => entry.option === option);
  if (!known) return { option, state: 'unknown', evidence: null };

  if (evidence.config) {
    const value = evidence.config[option];
    return value === 'y' || value === 'm'
      ? { option, state: 'on', evidence: `kernel-config:${value}` }
      : { option, state: 'off', evidence: 'kernel-config:not-enabled' };
  }

  if (evidence.modules) {
    const names = new Set([...evidence.modules.names].map(normalizedModule));
    const hit = known.modules.find((name) => names.has(normalizedModule(name)));
    if (hit) return { option, state: 'on', evidence: `module:${hit}.ko` };
  }

  const symbol = known.symbols.find((name) => evidence.kallsyms?.names.has(name));
  if (symbol) return { option, state: 'on', evidence: `kallsyms:${symbol}` };

  const string = known.strings.find((marker) => evidence.kernelStrings?.includes(marker));
  if (string) return { option, state: 'on', evidence: `kernel-string:${string}` };

  if (evidence.kallsyms?.complete && known.symbols.length > 0) {
    if (known.builtinOnly) return { option, state: 'off', evidence: 'complete-kallsyms:no-builtin-symbol' };
    if (evidence.modules?.complete) {
      return { option, state: 'off', evidence: 'complete-kallsyms+complete-module-inventory:no-match' };
    }
  }
  return { option, state: 'unknown', evidence: null };
}

export interface KernelCveRule {
  id: string;
  introduced?: string;
  fixed?: string;
  impact: 'LPE' | 'RCE' | 'DoS';
  requires: readonly string[];
  mitigatedBy: readonly string[];
  note: string;
}

type RuleTuple = readonly [string, string, string, 'LPE' | 'RCE' | 'DoS', readonly string[], readonly string[], string];
const R = (row: RuleTuple): KernelCveRule => ({
  id: row[0],
  ...(row[1] ? { introduced: row[1] } : {}),
  ...(row[2] ? { fixed: row[2] } : {}),
  impact: row[3],
  requires: row[4],
  mitigatedBy: row[5],
  note: row[6],
});

export const KERNEL_CVE_RULES: readonly KernelCveRule[] = [
  R(['CVE-2016-5195', '2.6.22', '4.8.3', 'LPE', [], [], 'Dirty COW: core-mm COW race; public exploits.']),
  R(['CVE-2022-0847', '5.8', '5.16.11', 'LPE', [], [], 'Dirty Pipe: pipe page-cache overwrite.']),
  R(['CVE-2021-33909', '', '5.13.4', 'LPE', [], [], 'Sequoia: seq_file size underflow.']),
  R(['CVE-2019-13272', '', '5.1.17', 'LPE', [], [], 'ptrace parent credential handling.']),
  R(['CVE-2018-14634', '', '4.18.9', 'LPE', [], [], 'create_elf_tables integer overflow.']),
  R(['CVE-2023-3269', '6.1', '6.4.1', 'LPE', [], [], 'StackRot maple-tree use-after-free.']),
  R(['CVE-2016-0728', '', '4.4.1', 'LPE', ['CONFIG_KEYS'], [], 'Keyring reference-count overflow.']),
  R(['CVE-2014-3153', '', '3.15', 'LPE', [], [], 'Futex requeue flaw (TowelRoot).']),
  R(['CVE-2017-5123', '', '4.13.5', 'LPE', [], [], 'waitid missing access_ok.']),
  R(['CVE-2021-3347', '', '5.11', 'LPE', [], [], 'PI-futex use-after-free.']),
  R(['CVE-2013-2094', '', '3.8.9', 'LPE', ['CONFIG_PERF_EVENTS'], [], 'perf_event_open type confusion.']),
  R(['CVE-2017-1000112', '', '4.13', 'LPE', [], [], 'UDP fragmentation out-of-bounds write.']),
  R(['CVE-2021-22555', '2.6.19', '5.12', 'LPE', ['CONFIG_NETFILTER'], [], 'x_tables out-of-bounds write.']),
  R(['CVE-2023-32233', '', '6.4', 'LPE', ['CONFIG_NF_TABLES'], [], 'nf_tables anonymous-set use-after-free.']),
  R(['CVE-2022-32250', '', '5.18.1', 'LPE', ['CONFIG_NF_TABLES'], [], 'nf_tables set use-after-free.']),
  R(['CVE-2022-34918', '', '5.18.9', 'LPE', ['CONFIG_NF_TABLES'], [], 'nf_tables set-element type confusion.']),
  R(['CVE-2022-2586', '', '5.19', 'LPE', ['CONFIG_NF_TABLES'], [], 'nf_tables cross-table set use-after-free.']),
  R(['CVE-2023-35001', '', '6.4.3', 'LPE', ['CONFIG_NF_TABLES'], [], 'nft_byteorder out-of-bounds access.']),
  R(['CVE-2024-1086', '', '6.8', 'LPE', ['CONFIG_NF_TABLES'], [], 'nf_tables verdict double-free.']),
  R(['CVE-2022-1015', '5.5', '5.17', 'LPE', ['CONFIG_NF_TABLES'], [], 'nf_tables register out-of-bounds access.']),
  R(['CVE-2024-1085', '', '6.8', 'LPE', ['CONFIG_NF_TABLES'], [], 'nf_tables anonymous-set double-free.']),
  R(['CVE-2023-0179', '', '6.2', 'LPE', ['CONFIG_NF_TABLES'], [], 'nft_payload stack out-of-bounds leak.']),
  R([
    'CVE-2021-3490',
    '5.7',
    '5.13',
    'LPE',
    ['CONFIG_BPF_SYSCALL'],
    ['CONFIG_BPF_UNPRIV_DEFAULT_OFF'],
    'eBPF ALU32 bounds flaw.',
  ]),
  R([
    'CVE-2017-16995',
    '4.4',
    '4.14.8',
    'LPE',
    ['CONFIG_BPF_SYSCALL'],
    ['CONFIG_BPF_UNPRIV_DEFAULT_OFF'],
    'eBPF verifier sign-extension flaw.',
  ]),
  R([
    'CVE-2020-8835',
    '5.5',
    '5.6.1',
    'LPE',
    ['CONFIG_BPF_SYSCALL'],
    ['CONFIG_BPF_UNPRIV_DEFAULT_OFF'],
    'eBPF bounds tracking flaw.',
  ]),
  R(['CVE-2022-2588', '', '5.19', 'LPE', ['CONFIG_NET_CLS_ROUTE4'], [], 'cls_route filter use-after-free.']),
  R(['CVE-2023-1829', '', '6.3', 'LPE', ['CONFIG_NET_CLS_TCINDEX'], [], 'tcindex use-after-free.']),
  R(['CVE-2022-29581', '', '5.17', 'LPE', ['CONFIG_NET_CLS_U32'], [], 'cls_u32 reference-count use-after-free.']),
  R(['CVE-2021-41073', '5.11', '5.14.6', 'LPE', ['CONFIG_IO_URING'], [], 'io_uring loop_rw_iter type confusion.']),
  R(['CVE-2022-1786', '5.11', '5.18', 'LPE', ['CONFIG_IO_URING'], [], 'io_uring use-after-free.']),
  R(['CVE-2023-2598', '6.3', '6.4', 'LPE', ['CONFIG_IO_URING'], [], 'io_uring fixed-buffer out-of-bounds access.']),
  R([
    'CVE-2022-2602',
    '',
    '6.0',
    'LPE',
    ['CONFIG_IO_URING', 'CONFIG_UNIX'],
    [],
    'io_uring/AF_UNIX garbage-collector use-after-free.',
  ]),
  R(['CVE-2016-8655', '', '4.9', 'LPE', ['CONFIG_PACKET'], [], 'AF_PACKET TX_RING race.']),
  R(['CVE-2017-7308', '', '4.10.6', 'LPE', ['CONFIG_PACKET'], [], 'AF_PACKET ring-buffer out-of-bounds access.']),
  R(['CVE-2020-14386', '', '5.9', 'LPE', ['CONFIG_PACKET'], [], 'AF_PACKET tpacket_rcv out-of-bounds write.']),
  R(['CVE-2021-22600', '', '5.16', 'LPE', ['CONFIG_PACKET'], [], 'AF_PACKET packet_set_ring double-free.']),
  R([
    'CVE-2022-0185',
    '',
    '5.16.2',
    'LPE',
    ['CONFIG_USER_NS'],
    [],
    'fs_context heap overflow; container-escape primitive.',
  ]),
  R(['CVE-2021-4154', '', '5.16', 'LPE', ['CONFIG_CGROUPS'], [], 'cgroup-v1 fs_context use-after-free.']),
  R([
    'CVE-2023-0386',
    '',
    '6.2',
    'LPE',
    ['CONFIG_OVERLAY_FS', 'CONFIG_FUSE_FS'],
    [],
    'OverlayFS/FUSE setuid copy-up flaw.',
  ]),
  R(['CVE-2015-1328', '', '4.1', 'LPE', ['CONFIG_OVERLAY_FS'], [], 'OverlayFS permission bypass.']),
  R(['CVE-2019-2215', '', '5.0', 'LPE', ['CONFIG_ANDROID_BINDER_IPC'], [], 'Binder use-after-free.']),
  R(['CVE-2017-6074', '', '4.9.11', 'LPE', ['CONFIG_IP_DCCP'], [], 'DCCP double-free use-after-free.']),
  R(['CVE-2015-3636', '', '4.1', 'LPE', [], [], 'Ping-socket use-after-free.']),
  R(['CVE-2021-26708', '', '5.10.13', 'LPE', ['CONFIG_VSOCKETS'], [], 'AF_VSOCK multi-transport race.']),
  R(['CVE-2017-11176', '', '4.11.9', 'LPE', ['CONFIG_POSIX_MQUEUE'], [], 'mq_notify netlink use-after-free.']),
  R(['CVE-2022-27666', '', '5.17', 'LPE', ['CONFIG_INET_ESP'], [], 'ESP6 IPsec buffer overflow.']),
  R(['CVE-2022-2639', '', '6.0', 'LPE', ['CONFIG_OPENVSWITCH'], [], 'Open vSwitch out-of-bounds access.']),
  R(['CVE-2021-43267', '5.10', '5.15.1', 'RCE', ['CONFIG_TIPC'], [], 'TIPC MSG_CRYPTO heap overflow.']),
  R(['CVE-2022-0435', '', '5.17', 'RCE', ['CONFIG_TIPC'], [], 'TIPC monitoring stack overflow.']),
  R(['CVE-2019-11477', '', '4.19.42', 'DoS', [], [], 'SACK Panic remote denial of service.']),
  R(['CVE-2022-42719', '5.1', '6.1', 'RCE', ['CONFIG_MAC80211'], [], 'mac80211 MBSSID use-after-free.']),
  R(['CVE-2022-42720', '5.1', '6.1', 'RCE', ['CONFIG_MAC80211'], [], 'mac80211 BSS reference-count use-after-free.']),
  R(['CVE-2020-12351', '4.8', '5.10', 'RCE', ['CONFIG_BT'], [], 'Bluetooth L2CAP type confusion.']),
  R(['CVE-2024-24246', '', '6.7', 'LPE', ['CONFIG_QAT'], [], 'QAT driver use-after-free.']),
  R([
    'CVE-2021-27365',
    '',
    '5.11.4',
    'LPE',
    ['CONFIG_SCSI_ISCSI_ATTRS'],
    [],
    'iSCSI netlink heap out-of-bounds access.',
  ]),
  R(['CVE-2022-25636', '', '5.16.11', 'LPE', ['CONFIG_NETFILTER'], [], 'Netfilter flowtable out-of-bounds write.']),
];

function versionParts(value: string): readonly [number, number, number] | null {
  const match = /^(\d+)\.(\d+)(?:\.(\d+))?/.exec(value.trim());
  return match ? [Number(match[1]), Number(match[2]), Number(match[3] ?? 0)] : null;
}

function compareKernelVersions(a: string, b: string): number | null {
  const av = versionParts(a);
  const bv = versionParts(b);
  if (!av || !bv) return null;
  for (let i = 0; i < 3; i++) if (av[i] !== bv[i]) return (av[i] as number) < (bv[i] as number) ? -1 : 1;
  return 0;
}

export function kernelVersionAffected(version: string, rule: KernelCveRule): boolean {
  const introduced = rule.introduced ? compareKernelVersions(version, rule.introduced) : 0;
  const fixed = rule.fixed ? compareKernelVersions(version, rule.fixed) : -1;
  return introduced !== null && fixed !== null && introduced >= 0 && fixed < 0;
}

export interface KernelCveAssessment {
  id: string;
  impact: KernelCveRule['impact'];
  state: KernelCveState;
  reason: string;
  note: string;
  required: KernelOptionAssessment[];
  mitigations: KernelOptionAssessment[];
}

export function assessKernelCves(version: string, evidence: KernelConfigEvidence): KernelCveAssessment[] {
  return KERNEL_CVE_RULES.filter((rule) => kernelVersionAffected(version, rule)).map((rule) => {
    const required = rule.requires.map((option) => inferKernelOption(option, evidence));
    const mitigations = rule.mitigatedBy.map((option) => inferKernelOption(option, evidence));
    const missing = required.find((item) => item.state === 'off');
    if (missing) {
      return {
        id: rule.id,
        impact: rule.impact,
        state: 'ruled_out',
        reason: `requires ${missing.option}, ruled out by ${missing.evidence}`,
        note: rule.note,
        required,
        mitigations,
      };
    }
    const unknown = required.find((item) => item.state === 'unknown');
    if (unknown) {
      return {
        id: rule.id,
        impact: rule.impact,
        state: 'unknown',
        reason: `${unknown.option} is undetermined`,
        note: rule.note,
        required,
        mitigations,
      };
    }
    const mitigation = mitigations.find((item) => item.state === 'on');
    if (mitigation) {
      return {
        id: rule.id,
        impact: rule.impact,
        state: 'ruled_out',
        reason: `mitigated by ${mitigation.option} (${mitigation.evidence})`,
        note: rule.note,
        required,
        mitigations,
      };
    }
    return {
      id: rule.id,
      impact: rule.impact,
      state: 'applicable',
      reason:
        rule.requires.length > 0
          ? 'version is in range and every required subsystem is present'
          : 'version is in range; this core-kernel entry has no configurable subsystem gate',
      note: rule.note,
      required,
      mitigations,
    };
  });
}

function impactSeverity(impact: KernelCveRule['impact']): FindingSeverity {
  if (impact === 'RCE') return 'critical';
  if (impact === 'LPE') return 'high';
  return 'medium';
}

/**
 * `device` is optional and adjusts the severity of an APPLICABLE row only.
 *
 * The rule's `impact` is already the right axis for this — `LPE`/`RCE`/`DoS` are exactly what
 * `cve-device-triage.ts` reads — so the kernel lane needs no vector: it has the classification first-hand. What
 * it lacked was the device half, and `impactSeverity` mapping LPE→high on every image alike is the flat reading
 * the triage exists to replace.
 *
 * It is confined to `applicable` deliberately. A `ruled_out` row is already `false_positive` and a `unknown` row
 * is already `blocked_by_platform`; re-weighting either would be adjusting a severity nobody is going to act on,
 * and on the `unknown` row it would be worse than useless — that row's whole message is that the question could
 * not be answered, and a confident severity on it would argue the opposite.
 */
export function kernelCveFindings(
  version: string,
  assessments: readonly KernelCveAssessment[],
  device?: DeviceContext,
): FindingDraft[] {
  return assessments.map((assessment) => {
    const published = impactSeverity(assessment.impact);
    const triage =
      device && assessment.state === 'applicable' ? deviceContextTriage(assessment.impact, published, device) : null;
    return {
      kind: 'kernel-cve',
      title: `${assessment.id} (${assessment.impact}) — ${assessment.note}`,
      severity: triage ? triage.adjustedSeverity : published,
      proofState:
        assessment.state === 'applicable'
          ? 'needs_runtime_reproduction'
          : assessment.state === 'ruled_out'
            ? 'false_positive'
            : 'blocked_by_platform',
      evidence: {
        kernel: version,
        state: assessment.state,
        reason: assessment.reason,
        required: assessment.required,
        mitigations: assessment.mitigations,
        ...(triage
          ? { deviceTriage: triage.rule, deviceTriageKind: triage.kind, publishedSeverity: triage.baseSeverity }
          : {}),
      },
      rationale: [
        assessment.state === 'applicable'
          ? `Linux ${version} is inside the curated mainline range and its required subsystem evidence is present. This is a candidate only: vendor backports and runtime reachability were not established.`
          : assessment.state === 'ruled_out'
            ? `The version is in range, but a required condition was checked and dismissed: ${assessment.reason}.`
            : `The version is in range, but applicability could not be decided: ${assessment.reason}. Unknown is not absence and is not a clean result.`,
        triage?.note,
      ]
        .filter(Boolean)
        .join(' '),
    };
  });
}

// External-NVD compatibility: the research lane already uses these helpers to form its bounded online query. The
// local curated triage above complements that broad prefix; it does not silently replace or widen its egress.
export interface KernelCveSelection {
  candidate: NvdCandidate | null;
  detectedVersion: string | null;
  queryVersion: string | null;
  versionSource: KernelPostureResult['versionSource'];
  reason: string;
  /**
   * Every known option's three-state verdict for THIS image, carried through so `normalizeKernelCves` can gate
   * a returned advisory on the subsystem it is about. The posture run already computed it; recomputing it in
   * the research lane would be a second answer to a question already asked, and the two could disagree.
   */
  configOptions: readonly KernelOptionAssessment[];
}

export function selectKernelCveCandidate(posture: KernelPostureResult): KernelCveSelection {
  const base = {
    detectedVersion: posture.version,
    versionSource: posture.versionSource,
    configOptions: posture.configOptions ?? [],
  };
  if (!posture.located || !posture.version) {
    return { ...base, candidate: null, queryVersion: null, reason: 'No kernel version was established.' };
  }
  if (posture.versionConflicts.length > 0) {
    return {
      ...base,
      candidate: null,
      queryVersion: null,
      reason: `${posture.versionConflicts.length} kernel version source conflict(s) remain unresolved.`,
    };
  }
  const token = /^(\d+\.\d+(?:\.\d+)?)/.exec(posture.version.trim())?.[1] ?? null;
  if (!token) {
    return { ...base, candidate: null, queryVersion: null, reason: 'The detected version has no upstream token.' };
  }
  return {
    ...base,
    candidate: { name: 'linux-kernel', version: token },
    queryVersion: token,
    reason: `Linux ${posture.version} is queryable as upstream ${token} (source: ${posture.versionSource}).`,
  };
}

function advisorySeverity(raw: string | null): FindingSeverity {
  const severity = raw?.toLowerCase();
  return severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low'
    ? severity
    : 'info';
}

export function normalizeKernelCves(selection: KernelCveSelection, component: NvdComponentResult): FindingDraft[] {
  if (!selection.candidate || component.name !== 'linux-kernel') return [];
  const shown = component.advisories.length;
  const total = component.totalMatching;
  const prefix = total !== null && total > shown;
  return component.advisories.map((advisory) => {
    // Which subsystem the advisory is about, and whether this image builds it. Null for most advisories, and
    // `off` only where the posture run had authoritative evidence — see `subsystemGate`.
    const gate = subsystemGate(advisory.summary, selection.configOptions);
    const ruledOut = gate?.state === 'off';
    return {
      kind: 'kernel-cve-candidate',
      title: `${advisory.id} — Linux kernel ${selection.detectedVersion ?? component.version}`,
      severity: advisorySeverity(advisory.severity),
      // `false_positive` is "checked and dismissed", and that is exactly what happened: the advisory names its
      // subsystem and this image's own kernel config says the subsystem is not built. The row STAYS — the count
      // does not change — it just stops being presented as a lead nobody can act on.
      proofState: (ruledOut ? 'false_positive' : 'needs_runtime_reproduction') as ProofState,
      evidenceChannel: 'external_advisory' as EvidenceChannel,
      evidence: {
        id: advisory.id,
        ...(gate ? { subsystem: gate.option, subsystemState: gate.state, subsystemMarker: gate.marker } : {}),
        detectedVersion: selection.detectedVersion,
        queryVersion: selection.queryVersion,
        versionSource: selection.versionSource,
        matchedBy: component.matchedBy,
        cnaSourceIdentifier: LINUX_KERNEL_CNA_SOURCE,
        score: advisory.score,
        summary: advisory.summary,
        references: advisory.references,
        shown,
        totalMatching: total,
        truncated: prefix,
        freshness: component.freshness,
      },
      rationale: `NVD places upstream Linux ${selection.queryVersion} inside this advisory's affected CPE range, and the query is restricted to the Linux kernel CNA. The firmware's version was read from ${selection.versionSource}. This is a candidate, not a confirmed device vulnerability: vendor backports may keep the same banner${
        gate ? '' : ', the affected subsystem may be absent or disabled'
      }, and reachability has not been reproduced.${
        ruledOut
          ? ` Dismissed on this image: the advisory's commit subject begins "${gate?.marker}", which puts it in ${gate?.option}, and this kernel's own configuration says that option is not built (${gate?.evidence}). The flaw is real upstream; the code it is in is not here.`
          : gate?.state === 'on'
            ? ` The subsystem it is in (${gate.option}, from the "${gate.marker}" commit-subject prefix) IS built on this image (${gate.evidence}), so the usual "maybe the subsystem is absent" escape does not apply to this row.`
            : gate
              ? ` It is in ${gate.option} (from the "${gate.marker}" commit-subject prefix), and whether this kernel builds that option could not be determined — undetermined is not absent, so the row stands.`
              : ''
      }${
        prefix
          ? ` NVD reports ${total} matching kernel advisories; this run retained the first ${shown}, so the rows are a prefix rather than the complete set.`
          : ''
      }`,
    };
  });
}
