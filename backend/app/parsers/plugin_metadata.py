from pydantic import BaseModel, Field
from typing import List

class PluginMetadata(BaseModel):
    name: str = Field(..., description="Unique name of the parser plugin")
    version: str = Field(..., description="Version of the plugin")
    description: str = Field(..., description="Description of the parser")
    vendor: str = Field(..., description="Vendor or author of the plugin")
    supported_formats: List[str] = Field(..., description="List of formats or systems supported")
    priority: int = Field(..., description="Execution priority (lower is higher priority)")
    enabled: bool = Field(default=True, description="Whether the plugin is enabled by default")
