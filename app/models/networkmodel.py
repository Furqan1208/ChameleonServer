"""
Network Processing Model - Complete representation of Network section data
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, model_validator


# ============================================================
# Helper Models
# ============================================================

class HostInfo(BaseModel):
    """Information about a contacted host/IP."""
    
    ip: str
    country_name: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    hostname: Optional[str] = None
    inaddrarpa: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    
    class Config:
        extra = "allow"


class DomainInfo(BaseModel):
    """Information about a domain lookup."""
    
    domain: str
    ip: Optional[str] = None
    
    class Config:
        extra = "allow"


class TCPConnection(BaseModel):
    """TCP network connection details."""
    
    src: str
    sport: int
    dst: str
    dport: int
    offset: int
    time: float
    
    class Config:
        extra = "allow"


class UDPConnection(BaseModel):
    """UDP network connection details."""
    
    src: str
    sport: int
    dst: str
    dport: int
    offset: int
    time: float
    
    class Config:
        extra = "allow"


class ICMPConnection(BaseModel):
    """ICMP network connection details."""
    
    src: Optional[str] = None
    dst: Optional[str] = None
    type: Optional[int] = None
    code: Optional[int] = None
    
    class Config:
        extra = "allow"


class HTTPRequest(BaseModel):
    """HTTP request details captured during analysis."""
    
    count: int
    host: str
    port: int
    data: str
    uri: str
    body: Optional[str] = ""
    path: str
    user_agent: str = Field(..., alias="user-agent")
    version: str
    method: str
    first_seen: float
    
    class Config:
        extra = "allow"
        populate_by_name = True


class DNSAnswer(BaseModel):
    """DNS answer record."""
    
    type: str
    data: str
    ttl: Optional[int] = None
    
    class Config:
        extra = "allow"


class DNSRequest(BaseModel):
    """DNS query details."""
    
    request: str
    type: str
    answers: List[DNSAnswer] = Field(default_factory=list)
    first_seen: float
    
    class Config:
        extra = "allow"


class DeadHost(BaseModel):
    """Host that was unreachable/not responding."""
    
    ip: str
    port: int
    
    class Config:
        extra = "allow"


class SortedConnections(BaseModel):
    """Sorted network connections structure."""
    
    tcp: List[TCPConnection] = Field(default_factory=list)
    udp: List[UDPConnection] = Field(default_factory=list)
    
    class Config:
        extra = "allow"


class PCAPNGInfo(BaseModel):
    """Information about the PCAPNG file."""
    
    sha256: str
    
    class Config:
        extra = "allow"


# ============================================================
# Main Network Model
# ============================================================

class NetworkModel(BaseModel):
    """
    Comprehensive network analysis results from CAPE/Cuckoo.
    Contains all network-related data collected during analysis.
    """
    
    # PCAP file information
    pcap_sha256: Optional[str] = Field(None, description="SHA256 of the raw PCAP file")
    sorted_pcap_sha256: Optional[str] = Field(None, description="SHA256 of the sorted PCAP file")
    
    # Network entities
    hosts: List[HostInfo] = Field(default_factory=list, description="IP addresses contacted")
    domains: List[DomainInfo] = Field(default_factory=list, description="Domains resolved")
    
    # Protocol-specific connections
    tcp: List[TCPConnection] = Field(default_factory=list, description="TCP connections")
    udp: List[UDPConnection] = Field(default_factory=list, description="UDP connections")
    icmp: List[ICMPConnection] = Field(default_factory=list, description="ICMP connections")
    
    # Application layer traffic
    http: List[HTTPRequest] = Field(default_factory=list, description="HTTP requests")
    dns: List[DNSRequest] = Field(default_factory=list, description="DNS queries")
    smtp: List[Any] = Field(default_factory=list, description="SMTP traffic")
    irc: List[Any] = Field(default_factory=list, description="IRC traffic")
    
    # Additional network information
    dead_hosts: List[DeadHost] = Field(default_factory=list, description="Unreachable hosts")
    
    # Sorted packet data (with different timestamps)
    sorted: Optional[SortedConnections] = Field(None, description="Sorted packet connections")
    
    # PCAPNG file information
    pcapng: Optional[PCAPNGInfo] = Field(None, description="PCAPNG file information")
    
    # Allow any additional fields
    additional: Dict[str, Any] = Field(default_factory=dict)
    
    @model_validator(mode='before')
    @classmethod
    def preprocess_dead_hosts(cls, values):
        """Convert dead_hosts list-of-lists to list-of-dicts before validation."""
        if isinstance(values, dict) and "dead_hosts" in values:
            raw = values["dead_hosts"]
            if isinstance(raw, list):
                converted = []
                for item in raw:
                    if isinstance(item, (list, tuple)) and len(item) == 2:
                        converted.append({"ip": item[0], "port": item[1]})
                    else:
                        converted.append(item)
                values = {**values, "dead_hosts": converted}
        return values

    class Config:
        extra = "allow"
        populate_by_name = True


class NetworkTopLevel(BaseModel):
    """
    Top-level network structure as it appears in the CAPE report.
    """
    
    network: NetworkModel = Field(..., description="Network analysis results")
    
    class Config:
        extra = "allow"


# ============================================================
# AI Summary Model (Compact for LLM)
# ============================================================

class NetworkAISummary(BaseModel):
    """
    Compact summary of network data for AI consumption.
    Contains key indicators extracted from the full data.
    """
    
    # === Overview ===
    has_network_activity: bool = False
    
    # === Domains (Critical IOCs - KEEP ALL) ===
    domains: List[str] = Field(default_factory=list, description="All domains contacted")
    
    # === IPs (Critical IOCs - KEEP ALL) ===
    ips: List[str] = Field(default_factory=list, description="All IPs contacted")
    
    # === DNS Queries ===
    dns_queries: List[Dict[str, Any]] = Field(default_factory=list, description="DNS requests and answers")
    
    # === HTTP Requests ===
    http_requests: List[Dict[str, Any]] = Field(default_factory=list, description="HTTP requests (summary)")
    
    # === Dead Hosts ===
    dead_hosts: List[Dict[str, int]] = Field(default_factory=list, description="Unreachable hosts")
    
    # === Statistics ===
    total_tcp_connections: int = 0
    total_udp_connections: int = 0
    total_dns_queries: int = 0
    total_http_requests: int = 0
    
    # === Suspicious Indicators ===
    has_suspicious_domains: bool = False
    suspicious_domain_keywords: List[str] = Field(default_factory=list)
    has_https_traffic: bool = False
    has_dns_traffic: bool = False
    
    # === Country Distribution ===
    contacted_countries: List[str] = Field(default_factory=list)
    
    # === Quick Assessment ===
    quick_summary: str = ""
    
    def generate_summary(self):
        """Generate quick summary string."""
        parts = []
        
        if self.domains:
            parts.append(f"Domains: {len(self.domains)}")
            if self.domains:
                parts.append(f"Top domain: {self.domains[0][:50]}")
        
        if self.ips:
            parts.append(f"IPs: {len(self.ips)}")
        
        if self.http_requests:
            parts.append(f"HTTP: {len(self.http_requests)}")
        
        if self.dns_queries:
            parts.append(f"DNS: {len(self.dns_queries)}")
        
        if self.dead_hosts:
            parts.append(f"Dead hosts: {len(self.dead_hosts)}")
        
        if self.contacted_countries:
            parts.append(f"Countries: {', '.join(self.contacted_countries[:3])}")
        
        if self.has_suspicious_domains:
            parts.append("Suspicious domains detected")
        
        self.quick_summary = " | ".join(parts) if parts else "No network activity"
    
    class Config:
        json_schema_extra = {
            "example": {
                "has_network_activity": True,
                "domains": ["www.msftconnecttest.com", "kalyanonlinematkaapp.in.net", "api.kalyanonlinematkaapp.in.net"],
                "ips": ["108.162.193.193", "104.21.87.11"],
                "dns_queries": [
                    {"request": "www.msftconnecttest.com", "type": "A", "answers": []},
                    {"request": "kalyanonlinematkaapp.in.net", "type": "A", "answers": []}
                ],
                "http_requests": [],
                "dead_hosts": [{"ip": "104.21.87.11", "port": 443}],
                "total_tcp_connections": 45,
                "total_udp_connections": 12,
                "total_dns_queries": 4,
                "total_http_requests": 0,
                "has_suspicious_domains": True,
                "suspicious_domain_keywords": ["kalyan", "matka"],
                "has_https_traffic": True,
                "has_dns_traffic": True,
                "contacted_countries": ["unknown"],
                "quick_summary": "Domains: 3 | Top domain: kalyanonlinematkaapp.in.net | IPs: 2 | DNS: 4 | Dead hosts: 1 | Suspicious domains detected"
            }
        }