"""
Signatures Processing Model - Complete representation of signatures, ttps, malscore, malstatus
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ============================================================
# Helper Models
# ============================================================

class SignatureCall(BaseModel):
    """Individual API call from signature data."""
    type: Optional[str] = None
    pid: Optional[int] = None
    cid: Optional[int] = None


class SignatureSection(BaseModel):
    """PE section information from signature."""
    name: Optional[str] = None
    raw_address: Optional[str] = None
    virtual_address: Optional[str] = None
    virtual_size: Optional[str] = None
    size_of_data: Optional[str] = None
    characteristics: Optional[str] = None
    characteristics_raw: Optional[str] = None
    entropy: Optional[float] = None


class SignatureDataEntry(BaseModel):
    """Complete signature data entry - keep everything."""
    # Call-related
    type: Optional[str] = None
    pid: Optional[int] = None
    cid: Optional[int] = None
    
    # Network-related (KEEP - important)
    domain: Optional[str] = None
    IP: Optional[str] = None
    
    # Command-related (KEEP - important)
    command: Optional[str] = None
    self_read: Optional[str] = None
    
    # File-related
    file: Optional[str] = None
    value: Optional[str] = None
    
    # Section-related (for packer detection)
    section: Optional[SignatureSection] = None
    
    # Anomaly description
    anomaly: Optional[str] = None
    
    # Process info
    process: Optional[str] = None
    thread_resumed: Optional[str] = None
    
    class Config:
        extra = "allow"


class NewDataProcess(BaseModel):
    """Process information in new_data."""
    process_name: Optional[str] = None
    process_id: Optional[int] = None


class NewDataSign(BaseModel):
    """Sign information in new_data."""
    type: Optional[str] = None
    value: Optional[str] = None


class NewDataEntry(BaseModel):
    """Complete new_data entry - keep what matters."""
    process: Optional[NewDataProcess] = None
    signs: Optional[List[NewDataSign]] = None


class Signature(BaseModel):
    """Complete signature - ALL fields preserved."""
    name: str
    description: Optional[str] = None
    categories: List[str] = Field(default_factory=list)
    severity: Optional[int] = None
    weight: Optional[int] = None
    confidence: Optional[int] = None
    references: List[str] = Field(default_factory=list)
    data: List[SignatureDataEntry] = Field(default_factory=list)
    new_data: List[NewDataEntry] = Field(default_factory=list)
    families: List[str] = Field(default_factory=list)
    alert: Optional[bool] = False
    
    class Config:
        extra = "allow"


class TTPSMapping(BaseModel):
    """Complete TTP mapping."""
    signature: str
    ttps: List[str] = Field(default_factory=list)
    mbcs: List[str] = Field(default_factory=list)


# ============================================================
# Top-Level Models
# ============================================================

class SignaturesData(BaseModel):
    """Complete signatures section data."""
    signatures: List[Signature] = Field(default_factory=list)


class TTPSData(BaseModel):
    """Complete ttps section data."""
    mappings: List[TTPSMapping] = Field(default_factory=list)


class SignaturesProcessingResult(BaseModel):
    """
    Complete result for signatures, ttps, malscore, malstatus.
    Output: { "full": {...}, "ai_summary": {...} }
    """
    signatures: SignaturesData = Field(default_factory=SignaturesData)
    ttps: TTPSData = Field(default_factory=TTPSData)
    malscore: float = 0.0
    malstatus: str = ""
    
    class Config:
        extra = "allow"


# ============================================================
# AI Summary Model (Compact for LLM - What we actually send)
# ============================================================

class SignaturesAISummary(BaseModel):
    """
    Compact summary for AI consumption.
    Contains extracted indicators from the full data.
    """
    
    # === Overall Assessment ===
    malscore: float = 0.0
    malstatus: str = ""
    
    # === Signature Statistics ===
    total_signatures: int = 0
    critical_signatures: int = 0  # severity >= 3
    suspicious_signatures: int = 0  # severity == 2
    low_severity_signatures: int = 0  # severity == 1

    # === Signature Details (for AI) ===
    high_severity_signatures: List[Dict[str, Any]] = Field(default_factory=list)
    medium_severity_signatures: List[Dict[str, Any]] = Field(default_factory=list)
    
    # === Extracted IOCs (KEEP FULL) ===
    domains: List[str] = Field(default_factory=list)  # All domains from signatures
    ips: List[str] = Field(default_factory=list)      # All IPs from signatures
    commands: List[str] = Field(default_factory=list)  # All commands (limited length)
    
    # === Malware Capabilities (Key Findings) ===
    has_anti_debug: bool = False
    has_anti_vm: bool = False
    has_persistence: bool = False
    has_injection: bool = False
    has_info_stealer: bool = False
    has_packing: bool = False
    has_network_activity: bool = False
    
    # === Affected Processes ===
    affected_pids: List[int] = Field(default_factory=list)  # Unique PIDs
    
    # === MITRE ATT&CK ===
    detected_ttps: List[str] = Field(default_factory=list)  # Top TTPs
    
    # === Categorization ===
    top_categories: Dict[str, int] = Field(default_factory=dict)  # Category counts
    
    # === Quick Assessment ===
    quick_summary: str = ""
    
    def generate_summary(self):
        """Generate quick summary string."""
        parts = []
        
        if self.malstatus:
            parts.append(f"Status: {self.malstatus}")
        
        if self.malscore > 0:
            parts.append(f"Score: {self.malscore}")
        
        if self.critical_signatures > 0:
            parts.append(f"Critical: {self.critical_signatures}")
        
        if self.domains:
            parts.append(f"Domains: {len(self.domains)}")
        
        if self.ips:
            parts.append(f"IPs: {len(self.ips)}")
        
        if self.commands:
            parts.append(f"Commands: {len(self.commands)}")
        
        if self.has_persistence:
            parts.append("Persistence")
        if self.has_injection:
            parts.append("Injection")
        if self.has_anti_vm:
            parts.append("Anti-VM")
        if self.has_info_stealer:
            parts.append("InfoStealer")
        
        if self.detected_ttps:
            parts.append(f"TTPs: {', '.join(self.detected_ttps[:3])}")
        
        self.quick_summary = " | ".join(parts) if parts else "No signatures"
    
    class Config:
        json_schema_extra = {
            "example": {
                "malscore": 10.0,
                "malstatus": "Malicious",
                "total_signatures": 45,
                "critical_signatures": 12,
                "suspicious_signatures": 8,
                "domains": ["www.msftconnecttest.com", "88j.co.com"],
                "ips": ["104.21.87.11", "172.67.139.34"],
                "commands": [
                    "powershell Add-MpPreference -ExclusionPath",
                    "schtasks /create /sc onlogon"
                ],
                "has_anti_debug": True,
                "has_anti_vm": True,
                "has_persistence": True,
                "has_injection": True,
                "has_info_stealer": True,
                "has_packing": True,
                "has_network_activity": True,
                "affected_pids": [1764, 1304, 4328],
                "detected_ttps": ["T1055", "T1547", "T1082", "T1027"],
                "top_categories": {"persistence": 5, "injection": 3, "anti-vm": 4},
                "quick_summary": "Status: Malicious | Score: 10.0 | Critical: 12 | Domains: 2 | IPs: 2 | Persistence | Injection | Anti-VM | TTPs: T1055, T1547, T1082"
            }
        }