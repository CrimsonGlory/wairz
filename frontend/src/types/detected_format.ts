// Rule #25 Shape-1 cross-stack alignment mirror for backend
// `app.schemas.file_format.DetectedFormat` Literal +
// `app.services.format_detection.DetectedFormat` Enum.
//
// Adding a new value here REQUIRES (Rule #48 5-part shape):
//   1. Update Pydantic Literal in backend/app/schemas/file_format.py
//   2. Update Python Enum in backend/app/services/format_detection.py
//   3. Add at least one shipping YAML manifest whose `pre_upload.detected_format`
//      uses the new value (under backend/app/services/file_format_catalog/data/file_formats/)
//   4. Update this file
//   5. The alignment test `backend/tests/test_file_format_detected_alignment.py`
//      catches any drift between the four surfaces.

/**
 * Pre-upload format classification — surfaced by
 * `GET /firmware/{id}/upload-status` and rendered in the upload-progress
 * banner. Mirrors backend `DetectedFormat` exactly.
 */
export type DetectedFormat =
  | 'linux_firmware_blob'
  | 'android_apk'
  | 'android_ota'
  | 'windows_installer_iso'
  | 'acronis_backup'
  | 'qnx_ifs'
  | 'pe_executable'
  | 'wim_archive'
  | 'iso_9660'
  | 'tar_archive'
  | 'zip_archive'
  | 'windows_cab'
  | 'windows_msi'
  | 'windows_msix'
  | 'windows_msu'
  | 'windows_psf'
  | 'windows_vhdx'
  | 'windows_driver_package'
  | 'unknown'

/**
 * Whether wairz has a working extractor for the format.
 *
 * - `full` — handler exists and is tested on real firmware
 * - `partial` — surface-level extraction works (listing / parts)
 * - `none` — informational only; user must extract externally
 */
export type ExtractionCapability = 'full' | 'partial' | 'none'

/**
 * Canonical list of all DetectedFormat values. Iterate this when you need
 * exhaustive coverage (e.g. building a Record<DetectedFormat, T> map).
 * Drift between this list and the union above is caught by tsc's
 * exhaustiveness check on the type.
 */
export const DETECTED_FORMAT_VALUES: readonly DetectedFormat[] = [
  'linux_firmware_blob',
  'android_apk',
  'android_ota',
  'windows_installer_iso',
  'acronis_backup',
  'qnx_ifs',
  'pe_executable',
  'wim_archive',
  'iso_9660',
  'tar_archive',
  'zip_archive',
  'windows_cab',
  'windows_msi',
  'windows_msix',
  'windows_msu',
  'windows_psf',
  'windows_vhdx',
  'windows_driver_package',
  'unknown',
]

export const EXTRACTION_CAPABILITY_VALUES: readonly ExtractionCapability[] = [
  'full',
  'partial',
  'none',
]
