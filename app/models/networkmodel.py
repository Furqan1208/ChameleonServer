from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, model_validator


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
    ip: Optional[str] = None  # IP resolved for the domain
    
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
    
    # Define fields if needed, currently empty in example
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
    
    def __init__(self, **data):
        # Handle case where dead_hosts are provided as list of [ip, port]
        if isinstance(data.get('data'), (list, tuple)) and len(data['data']) == 2:
            super().__init__(ip=data['data'][0], port=data['data'][1])
        else:
            super().__init__(**data)


class SortedConnections(BaseModel):
    """Sorted network connections structure."""
    
    tcp: List[TCPConnection] = Field(default_factory=list)
    # Add other protocol types if they appear in sorted data
    
    class Config:
        extra = "allow"


class PCAPNGInfo(BaseModel):
    """Information about the PCAPNG file."""
    
    sha256: str
    
    class Config:
        extra = "allow"


class NetworkModel(BaseModel):
    """
    Comprehensive network analysis results from CAPE/Cuckoo.
    
    Contains all network-related data collected during analysis including
    PCAP hashes, hosts contacted, domains resolved, protocol-specific
    connections, HTTP traffic, DNS queries, and sorted packet data.
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
    
    # Sorted packet data (often with different timestamps)
    sorted: Optional[SortedConnections] = Field(None, description="Sorted packet connections")
    
    # PCAPNG file information (if available)
    pcapng: Optional[PCAPNGInfo] = Field(None, description="PCAPNG file information")
    
    # Allow any additional fields that might appear in different report versions
    additional: Dict[str, Any] = Field(default_factory=dict)
    
    @model_validator(mode='before')
    @classmethod
    def preprocess_dead_hosts(cls, values):
        """Convert dead_hosts list-of-lists to list-of-dicts before Pydantic validates them."""
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
    
    def model_post_init(self, __context):
        """Post-initialization processing to handle special cases."""
        # Convert dead_hosts if they're provided as list of lists
        if hasattr(self, 'dead_hosts') and self.dead_hosts:
            processed = []
            for item in self.dead_hosts:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    processed.append(DeadHost(ip=item[0], port=item[1]))
                elif isinstance(item, dict):
                    processed.append(DeadHost(**item))
                else:
                    processed.append(item)
            self.dead_hosts = processed
        return super().model_post_init(__context)


class NetworkTopLevel(BaseModel):
    """
    Top-level network structure as it appears in the CAPE report.
    This matches the exact structure shown in the example data.
    """
    
    network: NetworkModel = Field(..., description="Network analysis results")
    
    class Config:
        extra = "allow"