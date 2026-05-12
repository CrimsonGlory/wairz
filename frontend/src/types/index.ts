export interface Project {
  id: string
  name: string
  description: string | null
  status: string
  created_at: string
  updated_at: string
}

export interface ProjectDetail extends Project {
  firmware: FirmwareSummary[]
}

export interface FirmwareSummary {
  id: string
  original_filename: string | null
  sha256: string
  file_size: number | null
  architecture: string | null
  endianness: string | null
  os_info: string | null
  kernel_path: string | null
  version_label: string | null
  created_at: string
}

/**
 * Upload-stage state machine (Rule #29 + Rule #33). Mirrors the
 * Pydantic Literal in app/schemas/firmware.py:UploadStage and the DB
 * CHECK constraint ck_firmware_upload_stage (alembic d2e3f4a5b6c7).
 */
export type UploadStage =
  | 'uploading'
  | 'hashing'
  | 'detecting'
  | 'extracting'
  | 'analyzing'
  | 'ready'
  | 'failed'

export type ExtractionCapability = 'full' | 'partial' | 'none'

/**
 * Response from POST /firmware (the 202 ack) and GET /firmware/{id}/upload-status
 * (the 2 s polling endpoint). Frontend renders stage labels + format
 * banner directly from this shape.
 */
export interface FirmwareUploadStatus {
  id: string
  upload_stage: UploadStage
  upload_stage_error: string | null
  detected_format: string | null
  extraction_capability: ExtractionCapability | string | null
  capability_note: string | null
  extracted_path: string | null
  architecture: string | null
  os_info: string | null
  upload_stage_started_at: string | null
  upload_stage_finished_at: string | null
  sha256: string | null
  file_size: number | null
  original_filename: string | null
}

export interface ArchCandidate {
  architecture: string
  raw_name: string
  endianness: string | null
  confidence: string
}

export interface BinaryInfo {
  format: string | null
  architecture: string | null
  endianness: string | null
  bits: number | null
  is_static: boolean | null
  is_pie: boolean | null
  interpreter: string | null
  dependencies: string[]
  entry_point: number | null
  file_size: number | null
  extracted_filename: string | null
  arch_candidates?: ArchCandidate[]
  arch_detection_method?: string | null
}

export interface ExtractionDiagnostic {
  path: string
  size_bytes: number
  suffix: string
  magic_hex: string
  format?: string
  vendor?: string
  note?: string
}

export interface ExtractionDiagnostics {
  partial_extraction: boolean
  encrypted_archives: ExtractionDiagnostic[]
  unrecognised_archives: ExtractionDiagnostic[]
  summary: string
  /** Number of encrypted archives the vendor-AES auto-decrypt successfully resolved. Set by the post-decrypt recompute step. */
  decrypted_archives_count?: number
  /** Pre-decrypt list of encrypted archives, retained when all were resolved (encrypted_archives is then []). Used to surface the "this firmware was vendor-encrypted but auto-resolved" context in the UI. */
  originally_encrypted_archives?: ExtractionDiagnostic[]
}

export interface FirmwareDetail extends FirmwareSummary {
  project_id: string
  storage_path: string | null
  extracted_path: string | null
  extraction_dir: string | null
  version_label: string | null
  unpack_log: string | null
  unpack_stage: string | null
  unpack_progress: number | null
  binary_info: BinaryInfo | null
  device_metadata: {
    extraction_diagnostics?: ExtractionDiagnostics
    detection_roots?: string[]
    detection_audit?: Record<string, unknown>
    [key: string]: unknown
  } | null
}

export interface FileEntry {
  name: string
  type: 'file' | 'directory' | 'symlink' | 'other'
  size: number
  permissions: string
  symlink_target: string | null
}

export interface DirectoryListing {
  path: string
  entries: FileEntry[]
  truncated: boolean
}

export interface FileContent {
  content: string
  is_binary: boolean
  size: number
  truncated: boolean
  encoding?: string
}

export interface FileInfo {
  path: string
  type: string
  mime_type: string
  size: number
  permissions: string
  sha256: string | null
  elf_info: Record<string, unknown> | null
}

export interface SearchResult {
  pattern: string
  matches: string[]
  truncated: boolean
}

// ── Analysis types ──

export interface FunctionInfo {
  name: string
  offset: number
  size: number
}

export interface FunctionListResponse {
  binary_path: string
  functions: FunctionInfo[]
}

export interface ImportInfo {
  name: string
  libname: string | null
}

export interface ImportsResponse {
  binary_path: string
  imports: ImportInfo[]
}

export interface DisassemblyResponse {
  binary_path: string
  function: string
  disassembly: string
}

export interface DecompilationResponse {
  binary_path: string
  function: string
  decompiled_code: string
}

export interface CleanedCodeResponse {
  available: boolean
  cleaned_code: string | null
}

export interface BinaryProtections {
  nx: boolean
  relro: string
  canary: boolean
  pie: boolean
  fortify: boolean
  stripped: boolean
  error?: string
}

export interface BinaryInfoResponse {
  binary_path: string
  info: Record<string, unknown>
  protections: BinaryProtections
}

// ── Finding types ──

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Confidence = 'high' | 'medium' | 'low'
export type FindingStatus = 'open' | 'confirmed' | 'false_positive' | 'fixed'
export type FindingSource = 'manual' | 'ai_discovered' | 'sbom_scan' | 'fuzzing' | 'security_review' | 'security_audit' | 'yara_scan' | 'abusech_scan' | 'apk-manifest-scan' | 'apk-bytecode-scan' | 'apk-mobsfscan' | 'unpack_audit' | 'attack_surface' | 'clamav_scan' | 'cwe_checker' | 'hardware_firmware_graph' | 'uefi_scan' | 'vt_scan' | 'windows_authenticode' | 'windows_dbx_revoked' | 'windows_registry_persistence' | 'windows_inf' | 'windows_driver_imports' | 'windows_r2r_stomp' | 'windows_il_capa' | 'windows_sysmon_proc_create' | 'windows_logon_success' | 'windows_logon_failure' | 'windows_amcache_install' | 'windows_prefetch_execution' | 'windows_srum_network_activity' | 'windows_srum_application_runtime' | 'windows_powershell_script_block' | 'windows_scheduled_task_persistence' | 'windows_lnk_abnormal_target' | 'windows_mft_ads_hidden_content' | 'windows_mft_timestomping' | 'windows_byovd_driver' | 'windows_bcd_suspicious_path' | 'windows_bcd_testsigning_enabled' | 'windows_wmi_persistence' | 'windows_esp_unsigned' | 'windows_esp_dbx_revoked' | 'windows_mbr_bootkit' | 'windows_vbr_anomaly' | 'windows_sdb_inject_dll' | 'windows_sdb_redirect_exe' | 'windows_sdb_custom_shim' | 'linux_journald_priority_critical' | 'linux_journald_oom_killer' | 'linux_journald_suspicious_unit' | 'linux_journald_log_clear' | 'linux_journald_selinux_denied'

export interface Finding {
  id: string
  project_id: string
  firmware_id: string | null
  conversation_id: string | null
  title: string
  severity: Severity
  description: string | null
  evidence: string | null
  file_path: string | null
  line_number: number | null
  cve_ids: string[] | null
  cwe_ids: string[] | null
  confidence: Confidence | null
  status: FindingStatus
  source: FindingSource
  component_id: string | null
  created_at: string
  updated_at: string
}

export interface FindingCreate {
  title: string
  severity: Severity
  description?: string
  evidence?: string
  file_path?: string
  line_number?: number
  cve_ids?: string[]
  cwe_ids?: string[]
  confidence?: Confidence
  conversation_id?: string
  source?: FindingSource
}

export interface FindingUpdate {
  title?: string
  severity?: Severity
  description?: string
  evidence?: string
  file_path?: string
  line_number?: number
  cve_ids?: string[]
  cwe_ids?: string[]
  confidence?: Confidence
  status?: FindingStatus
  source?: FindingSource
}

// ── SBOM types ──

export type DetectionSource = 'package_manager' | 'binary_strings' | 'library_soname' | 'kernel_modules' | 'config_file'
export type DetectionConfidence = 'high' | 'medium' | 'low'

export type EnrichmentSource =
  | 'scanner'
  | 'exact_match'
  | 'local_fuzzy'
  | 'nvd_exact'
  | 'nvd_fuzzy'
  | 'inherited'
  | 'android_sdk'
  | 'none'

export interface SbomComponent {
  id: string
  firmware_id: string
  name: string
  version: string | null
  type: string
  cpe: string | null
  purl: string | null
  supplier: string | null
  detection_source: DetectionSource
  detection_confidence: DetectionConfidence
  file_paths: string[] | null
  metadata: Record<string, unknown>
  vulnerability_count: number
  created_at: string
  enrichment_source: EnrichmentSource | null
  cpe_confidence: number | null
}

export type VulnerabilityResolutionStatus = 'open' | 'resolved' | 'ignored' | 'false_positive'

export interface SbomVulnerability {
  id: string
  component_id: string
  cve_id: string
  cvss_score: number | null
  cvss_vector: string | null
  severity: Severity
  description: string | null
  published_date: string | null
  finding_id: string | null
  component_name: string | null
  component_version: string | null
  resolution_status: VulnerabilityResolutionStatus
  resolution_justification: string | null
  resolved_by: string | null
  resolved_at: string | null
  adjusted_cvss_score: number | null
  adjusted_severity: Severity | null
  adjustment_rationale: string | null
  effective_severity: Severity
  effective_cvss_score: number | null
}

export interface VulnerabilityUpdate {
  resolution_status?: VulnerabilityResolutionStatus
  resolution_justification?: string
}

export interface SbomGenerateResponse {
  components: SbomComponent[]
  total: number
  cached: boolean
}

export interface SbomSummary {
  total_components: number
  components_by_type: Record<string, number>
  components_with_vulns: number
  total_vulnerabilities: number
  vulns_by_severity: Record<string, number>
  scan_date: string | null
  open_count: number
  resolved_count: number
}

export interface VulnerabilityScanResult {
  status: string
  total_components_scanned: number
  total_vulnerabilities_found: number
  findings_created: number
  vulns_by_severity: Record<string, number>
}

// 202+polling response shape. Mirrors VulnerabilityScanStatusResponse in
// backend/app/schemas/sbom.py (Rule #33 (c): Pydantic Literal). The
// summary field is populated only when status === "completed".
export type VulnScanStatusValue =
  | 'idle'
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'

export interface VulnerabilityScanStatus {
  firmware_id: string
  status: VulnScanStatusValue
  started_at: string | null
  finished_at: string | null
  error: string | null
  summary: VulnerabilityScanResult | null
}

// ── Document types ──

export interface ProjectDocument {
  id: string
  project_id: string
  original_filename: string
  description: string | null
  content_type: string
  file_size: number
  sha256: string
  storage_path: string
  created_at: string
}

export interface DocumentContent {
  content: string
  content_type: string
  filename: string
  size: number
}

// ── Emulation types ──

export type EmulationMode = 'user' | 'system' | 'qiling'
// 202+polling statuses (pending, booting, ready) were added alongside
// the legacy synchronous values (created, starting, running). The new
// flow transitions pending → booting → ready; "running" is kept as the
// terminal-attachable alias for sessions started via the synchronous
// MCP path, and "ready" is the equivalent for the async REST path.
export type EmulationStatus =
  | 'created'
  | 'pending'
  | 'starting'
  | 'booting'
  | 'running'
  | 'ready'
  | 'stopping'
  | 'stopped'
  | 'error'

export interface PortForward {
  host: number
  guest: number
}

export interface FirmwareService {
  port: number
  protocol: string
  service: string
  host_port: number | null
  url: string | null
}

export type SystemEmulationStage =
  | 'extracting'
  | 'detecting_arch'
  | 'preparing_image'
  | 'booting'
  | 'checking'
  | 'running'

export interface EmulationSession {
  id: string
  project_id: string
  firmware_id: string
  mode: EmulationMode
  status: EmulationStatus
  architecture: string | null
  binary_path: string | null
  arguments: string | null
  port_forwards: PortForward[]
  error_message: string | null
  logs: string | null
  started_at: string | null
  stopped_at: string | null
  created_at: string
  // System emulation (FirmAE) fields
  discovered_services: FirmwareService[] | null
  system_emulation_stage: string | null
  kernel_used: string | null
  firmware_ip: string | null
}

export interface SystemEmulationStartRequest {
  brand?: string
  timeout?: number
}

export interface SystemCommandResponse {
  stdout: string
  stderr: string
  exit_code: number
}

export type StubProfile = 'none' | 'generic' | 'tenda'

export interface EmulationStartRequest {
  mode: EmulationMode
  binary_path?: string
  arguments?: string
  port_forwards?: PortForward[]
  kernel_name?: string
  init_path?: string
  pre_init_script?: string
  stub_profile?: StubProfile
}

export interface EmulationPreset {
  id: string
  project_id: string
  name: string
  description: string | null
  mode: EmulationMode
  binary_path: string | null
  arguments: string | null
  architecture: string | null
  port_forwards: PortForward[] | null
  kernel_name: string | null
  init_path: string | null
  pre_init_script: string | null
  stub_profile: StubProfile
  created_at: string
  updated_at: string
}

export interface EmulationPresetCreate {
  name: string
  description?: string
  mode: EmulationMode
  binary_path?: string
  arguments?: string
  architecture?: string
  port_forwards?: PortForward[]
  kernel_name?: string
  init_path?: string
  pre_init_script?: string
  stub_profile?: StubProfile
}

export interface EmulationPresetUpdate {
  name?: string
  description?: string
  mode?: EmulationMode
  binary_path?: string
  arguments?: string
  architecture?: string
  port_forwards?: PortForward[]
  kernel_name?: string
  init_path?: string
  pre_init_script?: string
  stub_profile?: StubProfile
}

// ── Kernel types ──

export interface KernelInfo {
  name: string
  architecture: string
  description: string
  file_size: number
  uploaded_at: string
}

export interface KernelListResponse {
  kernels: KernelInfo[]
  total: number
}

export interface EmulationExecResponse {
  stdout: string
  stderr: string
  exit_code: number
  timed_out: boolean
}

// ── Fuzzing types ──

export type FuzzingStatus = 'created' | 'queued' | 'running' | 'stopped' | 'completed' | 'error'
export type CrashExploitability = 'exploitable' | 'probably_exploitable' | 'probably_not' | 'unknown'

export interface FuzzingStats {
  execs_per_sec: number
  total_execs: number
  corpus_count: number
  saved_crashes: number
  saved_hangs: number
  stability: string | number
  bitmap_cvg: string | number
  last_find: number
  run_time: number
}

export interface FuzzingCampaign {
  id: string
  project_id: string
  firmware_id: string
  binary_path: string
  status: FuzzingStatus
  config: Record<string, unknown> | null
  stats: FuzzingStats | null
  crashes_count: number
  container_id: string | null
  error_message: string | null
  started_at: string | null
  stopped_at: string | null
  created_at: string
}

export interface FuzzingCrash {
  id: string
  campaign_id: string
  crash_filename: string
  crash_size: number | null
  signal: string | null
  stack_trace: string | null
  exploitability: CrashExploitability | null
  triage_output: string | null
  finding_id: string | null
  created_at: string
}

export interface FuzzingCrashDetail extends FuzzingCrash {
  crash_input_hex: string | null
}

export interface FuzzingTargetAnalysis {
  binary_path: string
  fuzzing_score: number
  input_sources: string[]
  dangerous_functions: string[]
  network_functions: string[]
  protections: Record<string, unknown>
  recommended_strategy: string
  function_count: number
  imports_of_interest: string[]
  file_size: number
  error?: string | null
}

export interface FuzzingCampaignCreateRequest {
  binary_path: string
  timeout_per_exec?: number
  memory_limit?: number
  dictionary?: string
  seed_corpus?: string[]
  arguments?: string
  environment?: Record<string, string>
  harness_script?: string
}

// ── Component Map types ──

export type ComponentNodeType = 'binary' | 'library' | 'script' | 'config' | 'init_script' | 'kernel_module'

export type ComponentEdgeType =
  | 'links_library'
  | 'imports_functions'
  | 'sources_script'
  | 'executes'
  | 'starts_service'
  | 'configures'

export interface ComponentNode {
  id: string
  label: string
  type: ComponentNodeType
  path: string
  size: number
  metadata: Record<string, unknown>
}

export interface ComponentEdge {
  source: string
  target: string
  type: ComponentEdgeType
  details: Record<string, unknown>
}

export interface ComponentGraph {
  nodes: ComponentNode[]
  edges: ComponentEdge[]
  node_count: number
  edge_count: number
  truncated: boolean
}

// ── Firmware Metadata types ──

export interface FirmwareSection {
  offset: number
  size: number | null
  type: string
  description: string
}

export interface UBootHeader {
  magic: string
  header_crc: string
  timestamp: number
  data_size: number
  load_address: string
  entry_point: string
  data_crc: string
  os_type: string
  architecture: string
  image_type: string
  compression: string
  name: string
}

export interface MTDPartition {
  name: string
  offset: number | null
  size: number
}

export interface FirmwareMetadata {
  file_size: number
  sections: FirmwareSection[]
  uboot_header: UBootHeader | null
  uboot_env: Record<string, string>
  mtd_partitions: MTDPartition[]
}

// ── Firmware Comparison types ──

export interface FileDiffEntry {
  path: string
  status: 'added' | 'removed' | 'modified' | 'permissions_changed'
  size_a: number | null
  size_b: number | null
  perms_a: string | null
  perms_b: string | null
  hash_a: string | null
  hash_b: string | null
}

export interface FirmwareDiff {
  added: FileDiffEntry[]
  removed: FileDiffEntry[]
  modified: FileDiffEntry[]
  permissions_changed: FileDiffEntry[]
  total_files_a: number
  total_files_b: number
  truncated: boolean
}

export interface FunctionDiffEntry {
  name: string
  status: 'added' | 'removed' | 'modified'
  size_a: number | null
  size_b: number | null
  hash_a?: string | null
  hash_b?: string | null
  addr_a?: number | null
  addr_b?: number | null
}

export interface SectionDiffEntry {
  name: string
  hash_a: string
  hash_b: string
  size_a: number
  size_b: number
  changed: boolean
}

export interface BasicBlockStats {
  blocks_a: number
  blocks_b: number
  common_count: number
  added_count: number
  removed_count: number
  unchanged_pct: number
}

export interface BinaryDiff {
  binary_path: string
  functions_added: FunctionDiffEntry[]
  functions_removed: FunctionDiffEntry[]
  functions_modified: FunctionDiffEntry[]
  info_a: Record<string, unknown>
  info_b: Record<string, unknown>
  sections_changed?: SectionDiffEntry[]
  imports_added?: string[]
  imports_removed?: string[]
  exports_added?: string[]
  exports_removed?: string[]
  basic_block_stats?: BasicBlockStats | null
}

export interface InstructionDiff {
  function_name: string
  arch: string
  diff_text: string
  lines_added: number
  lines_removed: number
  error: string | null
}

export interface TextDiff {
  path: string
  diff: string
  lines_added: number
  lines_removed: number
  truncated: boolean
  error: string | null
}

export interface DecompilationDiff {
  function_name: string
  binary_path: string
  source_a: string
  source_b: string
  diff_text: string
  lines_added: number
  lines_removed: number
  error: string | null
}

// ── APK Security Scan types ──

export type {
  FirmwareContextResponse,
  ManifestFindingResponse,
  ManifestScanSummary,
  ConfidenceSummary,
  ManifestScanResponse,
  BytecodeFindingLocation,
  BytecodeFindingResponse,
  BytecodeScanSummary,
  BytecodeScanResponse,
  SastFindingResponse,
  SastScanTimingResponse,
  SastScanSummary,
  SastScanResponse,
  ApkFullScanResult,
  ApkScanOptions,
  ApkScanSeverity,
  ApkScanConfidence,
} from './apkScan'
