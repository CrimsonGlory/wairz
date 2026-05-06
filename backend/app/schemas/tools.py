"""Pydantic request/response schemas for the MCP-to-REST tool bridge."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ToolRunRequest(BaseModel):
    tool_name: str = Field(..., description="Name of the MCP tool to execute")
    input: dict[str, Any] = Field(
        default_factory=dict,
        description="Tool input parameters (same schema as MCP tool input)",
    )


class ToolRunResponse(BaseModel):
    tool: str
    output: str
    success: bool


class ToolInfo(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any]


class ToolListResponse(BaseModel):
    tools: list[ToolInfo]
    count: int
