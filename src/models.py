"""
NetLens-Recon Data Models
Structured Pydantic definitions for targets, probe results, scan results, and clusters.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class Target(BaseModel):
    """Represents a target to scan."""
    raw_input: str
    host: str
    port: int
    scheme: str = "http"
    path: str = ""

    @property
    def url(self) -> str:
        standard_ports = {"http": 80, "https": 443}
        port_part = f":{self.port}" if standard_ports.get(self.scheme) != self.port else ""
        p = self.path
        if p and not p.startswith("/"):
            p = f"/{p}"
        return f"{self.scheme}://{self.host}{port_part}{p}"


class ProbeResult(BaseModel):
    """Result of initial network probing (DNS & TCP connect)."""
    target: Target
    is_open: bool
    resolved_ip: Optional[str] = None
    banner: Optional[str] = None
    error: Optional[str] = None
    latency_ms: float = 0.0


class ScanResult(BaseModel):
    """Full reconnaissance capture result for a single endpoint."""
    url: str
    target_host: str
    target_port: int
    scheme: str
    resolved_ip: Optional[str] = None
    status_code: Optional[int] = None
    status_text: Optional[str] = None
    final_url: Optional[str] = None
    redirect_chain: List[str] = Field(default_factory=list)
    page_title: Optional[str] = None
    meta_description: Optional[str] = None
    meta_generator: Optional[str] = None
    screenshot_file: Optional[str] = None
    screenshot_path: Optional[str] = None
    dhash: Optional[str] = None
    cluster_id: Optional[int] = None
    is_cluster_rep: bool = True
    cluster_size: int = 1
    response_headers: Dict[str, str] = Field(default_factory=dict)
    technologies: List[str] = Field(default_factory=list)
    hvt_flags: List[str] = Field(default_factory=list)
    is_hvt: bool = False
    has_login_form: bool = False
    has_password_input: bool = False
    response_time_ms: float = 0.0
    error: Optional[str] = None


class ClusterGroup(BaseModel):
    """Group of visually identical or near-identical endpoints."""
    cluster_id: int
    representative_hash: str
    representative_url: str
    representative_screenshot: Optional[str] = None
    representative_title: Optional[str] = None
    members: List[ScanResult] = Field(default_factory=list)


class ScanSummary(BaseModel):
    """High-level summary of completed recon job."""
    total_targets_supplied: int = 0
    endpoints_probed: int = 0
    endpoints_open: int = 0
    endpoints_scanned: int = 0
    total_successful: int = 0
    total_failed: int = 0
    high_value_targets_count: int = 0
    unique_visual_clusters: int = 0
    status_distribution: Dict[str, int] = Field(default_factory=dict)
    tech_distribution: Dict[str, int] = Field(default_factory=dict)
    duration_seconds: float = 0.0
    scan_timestamp: str = ""
