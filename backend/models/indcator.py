from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, List
import ipaddress

class ProcessedIndicator(BaseModel):
    """Unified Schema for all Threat Intelligence Indicators."""
    value: str = Field(..., description="The indicator itself (IP, Domain, Hash)")
    type: str = Field(..., description="IPv4, IPv6, Domain, URL, or FileHash")
    source: str = Field(..., description="The feed source name (e.g., alienvault_otx)")
    severity: str = Field(default="medium", description="Low, Medium, High, Critical")
    confidence: int = Field(default=50, ge=0, le=100)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = []

    @field_validator('value')
    @classmethod
    def validate_indicator_value(cls, v, info):
        """Basic validation to ensure IP values are structurally correct."""
        ind_type = info.data.get('type')
        if ind_type in ['IPv4', 'IPv6']:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f"Invalid IP address format for {v}")
        return v