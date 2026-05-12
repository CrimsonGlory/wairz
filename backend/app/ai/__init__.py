from app.ai.tool_registry import ToolRegistry
from app.ai.tools.android import register_android_tools
from app.ai.tools.android_bytecode import register_android_bytecode_tools
from app.ai.tools.android_sast import register_android_sast_tools
from app.ai.tools.attack_surface import register_attack_surface_tools
from app.ai.tools.binary import register_binary_tools
from app.ai.tools.comparison import register_comparison_tools
from app.ai.tools.cwe_checker import register_cwe_checker_tools
from app.ai.tools.documents import register_document_tools
from app.ai.tools.emulation import register_emulation_tools
from app.ai.tools.filesystem import register_filesystem_tools
from app.ai.tools.fuzzing import register_fuzzing_tools
from app.ai.tools.hardware_firmware import register_hardware_firmware_tools
from app.ai.tools.linux_container import register_linux_container_tools
from app.ai.tools.linux_journald import register_linux_journald_tools
from app.ai.tools.linux_persistence import register_linux_persistence_tools
from app.ai.tools.linux_systemd import register_linux_systemd_tools
from app.ai.tools.network import register_network_tools
from app.ai.tools.reporting import register_reporting_tools
from app.ai.tools.sbom import register_sbom_tools
from app.ai.tools.security import register_security_tools
from app.ai.tools.strings import register_string_tools
from app.ai.tools.taint_llm import register_taint_llm_tools
from app.ai.tools.uart import register_uart_tools
from app.ai.tools.uefi import register_uefi_tools
from app.ai.tools.vulhunt import register_vulhunt_tools
from app.ai.tools.windows_appcompat import register_windows_appcompat_tools
from app.ai.tools.windows_archive import register_windows_archive_tools
from app.ai.tools.windows_bcd import register_windows_bcd_tools
from app.ai.tools.windows_dotnet import register_windows_dotnet_tools
from app.ai.tools.windows_driver import register_windows_driver_tools
from app.ai.tools.windows_efs import register_windows_efs_tools
from app.ai.tools.windows_esp import register_windows_esp_tools
from app.ai.tools.windows_etl import register_windows_etl_tools
from app.ai.tools.windows_event_log import register_windows_event_log_tools
from app.ai.tools.windows_lnk import register_windows_lnk_tools
from app.ai.tools.windows_mbr_vbr import register_windows_mbr_vbr_tools
from app.ai.tools.windows_mft import register_windows_mft_tools
from app.ai.tools.windows_pe_signature import register_windows_pe_signature_tools
from app.ai.tools.windows_prefetch import register_windows_prefetch_tools
from app.ai.tools.windows_registry import register_windows_registry_tools
from app.ai.tools.windows_scheduled_task import (
    register_windows_scheduled_task_tools,
)
from app.ai.tools.windows_sdb import register_windows_sdb_tools
from app.ai.tools.windows_srum import register_windows_srum_tools
from app.ai.tools.windows_storage import register_windows_storage_tools
from app.ai.tools.windows_update import register_windows_update_tools
from app.ai.tools.windows_wmi import register_windows_wmi_tools


def create_tool_registry() -> ToolRegistry:
    """Create a ToolRegistry with all available tools registered."""
    registry = ToolRegistry()
    register_filesystem_tools(registry)
    register_string_tools(registry)
    register_binary_tools(registry)
    register_security_tools(registry)
    register_reporting_tools(registry)
    register_document_tools(registry)
    register_sbom_tools(registry)
    register_android_tools(registry)
    register_android_bytecode_tools(registry)
    register_android_sast_tools(registry)
    register_hardware_firmware_tools(registry)
    register_emulation_tools(registry)
    register_fuzzing_tools(registry)
    register_comparison_tools(registry)
    register_network_tools(registry)
    register_uart_tools(registry)
    register_uefi_tools(registry)
    register_vulhunt_tools(registry)
    register_attack_surface_tools(registry)
    register_cwe_checker_tools(registry)
    register_taint_llm_tools(registry)
    register_windows_archive_tools(registry)
    register_windows_pe_signature_tools(registry)
    register_windows_registry_tools(registry)
    register_windows_driver_tools(registry)
    register_windows_update_tools(registry)
    register_windows_storage_tools(registry)
    register_windows_dotnet_tools(registry)
    register_windows_event_log_tools(registry)
    register_windows_prefetch_tools(registry)
    register_windows_srum_tools(registry)
    register_windows_scheduled_task_tools(registry)
    register_windows_lnk_tools(registry)
    register_windows_mft_tools(registry)
    register_windows_bcd_tools(registry)
    register_windows_wmi_tools(registry)
    register_windows_esp_tools(registry)
    register_windows_mbr_vbr_tools(registry)
    register_windows_sdb_tools(registry)
    register_linux_journald_tools(registry)
    register_linux_systemd_tools(registry)
    register_windows_etl_tools(registry)
    register_windows_efs_tools(registry)
    register_linux_container_tools(registry)
    register_windows_appcompat_tools(registry)
    register_linux_persistence_tools(registry)
    return registry
