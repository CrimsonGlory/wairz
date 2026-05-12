from app.models.analysis_cache import AnalysisCache
from app.models.attack_surface import AttackSurfaceEntry
from app.models.conversation import Conversation
from app.models.cra_compliance import CraAssessment, CraRequirementResult
from app.models.device_dump import DeviceDumpSession
from app.models.document import Document
from app.models.emulation_preset import EmulationPreset
from app.models.emulation_session import EmulationSession
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.fuzzing import FuzzingCampaign, FuzzingCrash
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.linux_journald_entry import LinuxJournaldEntry
from app.models.linux_systemd_units import LinuxSystemdUnit
from app.models.project import Project
from app.models.sbom import SbomComponent, SbomVulnerability
from app.models.security_review import ReviewAgent, SecurityReview  # kept for DB/relationship integrity
from app.models.uart_session import UARTSession
from app.models.windows_bcd_entry import WindowsBcdEntry
from app.models.windows_driver import WindowsDriver
from app.models.windows_esp_entry import WindowsEspEntry
from app.models.windows_etl_events import WindowsEtlEvent
from app.models.windows_event_record import WindowsEventRecord
from app.models.windows_lnk_record import WindowsLnkRecord
from app.models.windows_mbr_vbr_sector import WindowsMbrVbrSector
from app.models.windows_mft_record import WindowsMftRecord
from app.models.windows_pe_signature import WindowsPESignature
from app.models.windows_prefetch_record import WindowsPrefetchRecord
from app.models.windows_registry_extract import WindowsRegistryExtract
from app.models.windows_scheduled_task import WindowsScheduledTask
from app.models.windows_sdb_entry import WindowsSdbEntry
from app.models.windows_srum_record import WindowsSrumRecord
from app.models.windows_update_dll_diff import WindowsUpdateDllDiff
from app.models.windows_update_package import WindowsUpdatePackage
from app.models.windows_wmi_event import WindowsWmiEvent

__all__ = [
    "Project", "Firmware", "Conversation", "AnalysisCache",
    "Finding", "Document", "SecurityReview", "ReviewAgent",
    "SbomComponent", "SbomVulnerability", "EmulationSession",
    "EmulationPreset", "FuzzingCampaign", "FuzzingCrash",
    "AttackSurfaceEntry", "UARTSession",
    "CraAssessment", "CraRequirementResult", "HardwareFirmwareBlob",
    "DeviceDumpSession", "LinuxJournaldEntry", "LinuxSystemdUnit",
    "WindowsPESignature", "WindowsRegistryExtract",
    "WindowsDriver", "WindowsUpdatePackage", "WindowsUpdateDllDiff",
    "WindowsBcdEntry", "WindowsEspEntry", "WindowsEtlEvent", "WindowsEventRecord", "WindowsLnkRecord", "WindowsMbrVbrSector", "WindowsMftRecord",
    "WindowsPrefetchRecord", "WindowsScheduledTask", "WindowsSdbEntry",
    "WindowsSrumRecord", "WindowsWmiEvent",
]
