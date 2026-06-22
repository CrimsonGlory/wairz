import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel

ALLOWED_EXTENSIONS = {".gzf", ".py", ".java", ".jy"}

# .gzf archives can be large Ghidra project exports
MAX_GZF_SIZE_MB = 500
# Scripts are text files
MAX_SCRIPT_SIZE_MB = 50

BINARY_EXTENSIONS = {".gzf"}
TEXT_EXTENSIONS = {".py", ".java", ".jy"}

FILE_CATEGORY_MAP = {
    ".gzf": "ghidra_archive",
    ".py": "python_script",
    ".java": "java_script",
    ".jy": "java_script",
}

IMPORT_STATUS_VALUES = ("idle", "queued", "running", "completed", "failed")


class GhidraResearchFileResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    original_filename: str
    file_category: str
    description: str | None
    content_type: str
    file_size: int
    sha256: str
    created_at: datetime
    import_status: str
    import_result: dict[str, Any] | None
    import_error: str | None


class GhidraResearchFileUpdate(BaseModel):
    description: str | None = None


class GhidraResearchScriptUpdate(BaseModel):
    content: str
