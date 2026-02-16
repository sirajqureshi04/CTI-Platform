from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, List
import ipaddress

class ProcessedIndicator(BaseModel):
    """Unified Schema for all Threat Intelligence Indicators."""
    
    value: str = Field(..., description="The indicator itself (IP, Domain, Hash)")
    type: str = Field(..., description="IPv4, IPv6, Domain, URL, or FileHash")
    
    # Changed from 'source: str' to 'sources: List[str]'
    sources: List[str] = Field(
        default_factory=list, 
        description="List of feed source names (e.g., ['Malpedia', 'Ransomware.live'])"
    )
    
    severity: str = Field(default="medium", description="Low, Medium, High, Critical")
    confidence: int = Field(default=50, ge=0, le=100)
    
    # Use 'last_seen' to align with the deduplicator logic
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    
    tags: List[str] = Field(default_factory=list)
    
    # Optional: Track how many times this has been seen across all feeds
    hit_count: int = Field(default=1, description="Number of times this IOC was merged")

    @field_validator('value')
    @classmethod
    def validate_indicator_value(cls, v: str, info) -> str:
        """Basic validation to ensure IP values are structurally correct."""
        # Accessing other fields in Pydantic V2 is done via the 'info' object
        ind_type = info.data.get('type')
        if ind_type in ['IPv4', 'IPv6']:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f"Invalid IP address format for {v}")
        return v

    def add_source(self, new_source: str):
        """Helper to add a unique source and increment hit count."""
        if new_source not in self.sources:
            self.sources.append(new_source)
        self.hit_count = len(self.sources)