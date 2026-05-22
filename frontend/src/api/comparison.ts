import apiClient from './client'
import type { BinaryDiff, DecompilationDiff, FirmwareDiff, InstructionDiff, TextDiff } from '@/types'
import { GHIDRA_PAIR_TIMEOUT } from './timeouts'

export async function diffFirmware(
  projectId: string,
  firmwareAId: string,
  firmwareBId: string,
): Promise<FirmwareDiff> {
  const { data } = await apiClient.post<FirmwareDiff>(
    `/projects/${projectId}/compare/firmware`,
    { firmware_a_id: firmwareAId, firmware_b_id: firmwareBId },
    { timeout: 300_000 },
  )
  return data
}

export async function diffBinary(
  projectId: string,
  firmwareAId: string,
  firmwareBId: string,
  binaryPath: string,
): Promise<BinaryDiff> {
  const { data } = await apiClient.post<BinaryDiff>(
    `/projects/${projectId}/compare/binary`,
    { firmware_a_id: firmwareAId, firmware_b_id: firmwareBId, binary_path: binaryPath },
    { timeout: 300_000 },
  )
  return data
}

export async function diffTextFile(
  projectId: string,
  firmwareAId: string,
  firmwareBId: string,
  filePath: string,
): Promise<TextDiff> {
  const { data } = await apiClient.post<TextDiff>(
    `/projects/${projectId}/compare/text`,
    { firmware_a_id: firmwareAId, firmware_b_id: firmwareBId, file_path: filePath },
    { timeout: 60_000 },
  )
  return data
}

export async function diffInstructions(
  projectId: string,
  firmwareAId: string,
  firmwareBId: string,
  binaryPath: string,
  functionName: string,
): Promise<InstructionDiff> {
  const { data } = await apiClient.post<InstructionDiff>(
    `/projects/${projectId}/compare/instructions`,
    { firmware_a_id: firmwareAId, firmware_b_id: firmwareBId, binary_path: binaryPath, function_name: functionName },
    { timeout: 30_000 },
  )
  return data
}

export async function diffDecompilation(
  projectId: string,
  firmwareAId: string,
  firmwareBId: string,
  binaryPath: string,
  functionName: string,
): Promise<DecompilationDiff> {
  const { data } = await apiClient.post<DecompilationDiff>(
    `/projects/${projectId}/compare/decompilation`,
    { firmware_a_id: firmwareAId, firmware_b_id: firmwareBId, binary_path: binaryPath, function_name: functionName },
    { timeout: GHIDRA_PAIR_TIMEOUT },
  )
  return data
}
