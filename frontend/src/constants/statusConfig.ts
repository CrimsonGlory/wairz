import {
  ShieldX,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  AlertCircle,
  Info,
  Package,
  Bot,
  User,
  Search,
  Bug,
  Shield,
  Smartphone,
  Code,
  Eye,
  FileSearch,
  Lock,
  Target,
  Network,
  Cpu,
  Terminal,
  CalendarClock,
  Link2,
  FilePlus,
  Clock,
  Skull,
  HardDrive,
  KeyRound,
} from 'lucide-react'
import type { Severity, FindingStatus, FindingSource, Confidence } from '@/types'

// ── Severity ──

export interface SeverityConfigEntry {
  icon: React.ElementType
  /** Text-only color class (e.g. "text-red-600") */
  className: string
  /** Background badge class (e.g. "bg-red-600 text-white") */
  bg: string
  label: string
  /** Sort order: 0 = most severe */
  order: number
}

export const SEVERITY_CONFIG: Record<Severity, SeverityConfigEntry> = {
  critical: { icon: ShieldX, className: 'text-red-600', bg: 'bg-red-600 text-white', label: 'Critical', order: 0 },
  high: { icon: ShieldAlert, className: 'text-orange-500', bg: 'bg-orange-500 text-white', label: 'High', order: 1 },
  medium: { icon: AlertTriangle, className: 'text-yellow-500', bg: 'bg-yellow-500 text-black', label: 'Medium', order: 2 },
  low: { icon: AlertCircle, className: 'text-blue-500', bg: 'bg-blue-500 text-white', label: 'Low', order: 3 },
  info: { icon: Info, className: 'text-gray-500', bg: 'bg-gray-500 text-white', label: 'Info', order: 4 },
}

// ── Finding status ──

export interface FindingStatusConfigEntry {
  label: string
  className: string
}

export const FINDING_STATUS_CONFIG: Record<FindingStatus, FindingStatusConfigEntry> = {
  open: { label: 'Open', className: 'border-yellow-500/50 text-yellow-600 dark:text-yellow-400' },
  confirmed: { label: 'Confirmed', className: 'border-red-500/50 text-red-600 dark:text-red-400' },
  false_positive: { label: 'False Positive', className: 'border-gray-500/50 text-gray-500' },
  fixed: { label: 'Fixed', className: 'border-green-500/50 text-green-600 dark:text-green-400' },
}

/** Array form of FINDING_STATUS_CONFIG for dropdown/selector use */
export const FINDING_STATUS_OPTIONS: { value: FindingStatus; label: string }[] = (
  Object.entries(FINDING_STATUS_CONFIG) as [FindingStatus, FindingStatusConfigEntry][]
).map(([value, { label }]) => ({ value, label }))

// ── Finding source ──

export interface FindingSourceConfigEntry {
  icon: React.ElementType
  label: string
  className: string
}

export const FINDING_SOURCE_CONFIG: Record<FindingSource, FindingSourceConfigEntry> = {
  manual: { icon: User, label: 'Manual', className: 'border-gray-500/50 text-gray-500' },
  ai_discovered: { icon: Bot, label: 'AI Discovered', className: 'border-purple-500/50 text-purple-600 dark:text-purple-400' },
  sbom_scan: { icon: Package, label: 'SBOM Scan', className: 'border-teal-500/50 text-teal-600 dark:text-teal-400' },
  fuzzing: { icon: Bug, label: 'Fuzzing', className: 'border-orange-500/50 text-orange-600 dark:text-orange-400' },
  security_review: { icon: Search, label: 'Security Review', className: 'border-blue-500/50 text-blue-600 dark:text-blue-400' },
  security_audit: { icon: Shield, label: 'Security Audit', className: 'border-red-500/50 text-red-600 dark:text-red-400' },
  yara_scan: { icon: Shield, label: 'YARA Scan', className: 'border-amber-500/50 text-amber-600 dark:text-amber-400' },
  abusech_scan: { icon: Shield, label: 'abuse.ch', className: 'border-rose-500/50 text-rose-600 dark:text-rose-400' },
  'apk-manifest-scan': { icon: Smartphone, label: 'APK Manifest', className: 'border-indigo-500/50 text-indigo-600 dark:text-indigo-400' },
  'apk-bytecode-scan': { icon: Code, label: 'APK Bytecode', className: 'border-violet-500/50 text-violet-600 dark:text-violet-400' },
  'apk-mobsfscan': { icon: FileSearch, label: 'APK SAST', className: 'border-fuchsia-500/50 text-fuchsia-600 dark:text-fuchsia-400' },
  unpack_audit: { icon: Lock, label: 'Unpack Audit', className: 'border-cyan-500/50 text-cyan-600 dark:text-cyan-400' },
  attack_surface: { icon: Target, label: 'Attack Surface', className: 'border-red-500/50 text-red-600 dark:text-red-400' },
  clamav_scan: { icon: Shield, label: 'ClamAV', className: 'border-blue-500/50 text-blue-600 dark:text-blue-400' },
  cwe_checker: { icon: AlertTriangle, label: 'CWE Checker', className: 'border-yellow-500/50 text-yellow-600 dark:text-yellow-400' },
  hardware_firmware_graph: { icon: Network, label: 'HW Graph', className: 'border-sky-500/50 text-sky-600 dark:text-sky-400' },
  uefi_scan: { icon: Cpu, label: 'UEFI', className: 'border-pink-500/50 text-pink-600 dark:text-pink-400' },
  vt_scan: { icon: Shield, label: 'VirusTotal', className: 'border-emerald-500/50 text-emerald-600 dark:text-emerald-400' },
  windows_authenticode: { icon: ShieldCheck, label: 'Authenticode', className: 'border-indigo-500/50 text-indigo-600 dark:text-indigo-400' },
  windows_dbx_revoked: { icon: ShieldX, label: 'DBX Revoked', className: 'border-red-500/50 text-red-600 dark:text-red-400' },
  windows_registry_persistence: { icon: Lock, label: 'Registry Persistence', className: 'border-orange-500/50 text-orange-600 dark:text-orange-400' },
  windows_inf: { icon: Cpu, label: 'INF', className: 'border-purple-500/50 text-purple-600 dark:text-purple-400' },
  windows_driver_imports: { icon: Network, label: 'Driver Imports', className: 'border-sky-500/50 text-sky-600 dark:text-sky-400' },
  windows_r2r_stomp: { icon: ShieldAlert, label: 'R2R Stomp', className: 'border-red-500/50 text-red-600 dark:text-red-400' },
  windows_il_capa: { icon: Code, label: 'IL Capa', className: 'border-fuchsia-500/50 text-fuchsia-600 dark:text-fuchsia-400' },
  windows_sysmon_proc_create: { icon: Eye, label: 'Sysmon Proc Create', className: 'border-amber-500/50 text-amber-600 dark:text-amber-400' },
  windows_logon_success: { icon: User, label: 'Logon Success', className: 'border-emerald-500/50 text-emerald-600 dark:text-emerald-400' },
  windows_logon_failure: { icon: ShieldX, label: 'Logon Failure', className: 'border-rose-500/50 text-rose-600 dark:text-rose-400' },
  windows_amcache_install: { icon: Package, label: 'AmCache Install', className: 'border-cyan-500/50 text-cyan-600 dark:text-cyan-400' },
  windows_prefetch_execution: { icon: Bot, label: 'Prefetch Execution', className: 'border-violet-500/50 text-violet-600 dark:text-violet-400' },
  windows_srum_network_activity: { icon: Network, label: 'SRUM Network', className: 'border-blue-500/50 text-blue-600 dark:text-blue-400' },
  windows_srum_application_runtime: { icon: Cpu, label: 'SRUM Runtime', className: 'border-orange-500/50 text-orange-600 dark:text-orange-400' },
  windows_powershell_script_block: { icon: Terminal, label: 'PowerShell Script', className: 'border-yellow-500/50 text-yellow-600 dark:text-yellow-400' },
  windows_scheduled_task_persistence: { icon: CalendarClock, label: 'Scheduled Task', className: 'border-amber-500/50 text-amber-600 dark:text-amber-400' },
  windows_lnk_abnormal_target: { icon: Link2, label: 'LNK Abnormal Target', className: 'border-rose-500/50 text-rose-600 dark:text-rose-400' },
  windows_mft_ads_hidden_content: { icon: FilePlus, label: 'MFT ADS Hidden', className: 'border-purple-500/50 text-purple-600 dark:text-purple-400' },
  windows_mft_timestomping: { icon: Clock, label: 'MFT Timestomp', className: 'border-red-500/50 text-red-600 dark:text-red-400' },
  windows_byovd_driver: { icon: Skull, label: 'BYOVD Driver', className: 'border-red-700/60 text-red-700 dark:text-red-300' },
  windows_bcd_suspicious_path: { icon: HardDrive, label: 'BCD Path', className: 'border-orange-500/50 text-orange-600 dark:text-orange-400' },
  windows_bcd_testsigning_enabled: { icon: KeyRound, label: 'BCD TestSigning', className: 'border-red-500/50 text-red-600 dark:text-red-400' },
}

// ── Finding confidence ──

export interface ConfidenceConfigEntry {
  label: string
  /** Full outline-badge class — border + text color. For `<Badge variant="outline">` use. */
  className: string
  /** Text-color-only class. For plain text suffix use (no border). */
  textClassName: string
}

/**
 * Visual config for `Finding.confidence`.  Hues kept distinct from
 * SEVERITY_CONFIG (filled) and FINDING_SOURCE_CONFIG (per-source hue) so
 * the three pieces of metadata don't visually merge in a tight header
 * row.  `null` confidence is rendered as nothing — call sites use
 * `?? CONFIDENCE_CONFIG.medium` only when a fallback is desired (per
 * CLAUDE.md Rule #9).
 */
export const CONFIDENCE_CONFIG: Record<Confidence, ConfidenceConfigEntry> = {
  high:   { label: 'High confidence',   className: 'border-emerald-500/50 text-emerald-600 dark:text-emerald-400', textClassName: 'text-emerald-600 dark:text-emerald-400' },
  medium: { label: 'Medium confidence', className: 'border-amber-500/50 text-amber-600 dark:text-amber-400',       textClassName: 'text-amber-600 dark:text-amber-400' },
  low:    { label: 'Low confidence',    className: 'border-slate-500/50 text-slate-600 dark:text-slate-400',       textClassName: 'text-slate-600 dark:text-slate-400' },
}

// ── Project status (Badge variant) ──

/**
 * Map of project `status` string to a shadcn Badge `variant`.  Values
 * NOT present here fall back to `'outline'` at the call site — the
 * lookup shape is intentionally looser (keyed by `string`, not a
 * Union) because the backend can produce new status strings faster
 * than the frontend enum evolves.  CLAUDE.md rule #9 applies: if a
 * backend status enum is introduced and this map becomes exhaustive,
 * tighten the key type.
 */
export const PROJECT_STATUS_VARIANT: Record<
  string,
  'default' | 'secondary' | 'destructive' | 'outline'
> = {
  ready: 'default',
  unpacking: 'secondary',
  error: 'destructive',
  created: 'outline',
}
