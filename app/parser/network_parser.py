"""
Network Parser - Parses network section from CAPE report.
Output: { "full": {...}, "ai_summary": {...} }
"""

import json
import sys
import ipaddress
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from collections import Counter

from app.models.networkmodel import (
    DNSAnswer,
    DNSRequest,
    DeadHost,
    DomainInfo,
    HostInfo,
    HTTPRequest,
    ICMPConnection,
    NetworkAISummary,
    NetworkModel,
    NetworkTopLevel,
    PCAPNGInfo,
    SortedConnections,
    TCPConnection,
    UDPConnection,
)
from app.utils.logger import get_logger

_logger = get_logger("app.parser.network")

# Limits for AI summary
_MAX_DOMAINS = 30
_MAX_PUBLIC_IPS = 30
_MAX_DNS_QUERIES = 20
_MAX_HTTP_REQUESTS = 15
_MAX_DEAD_HOSTS = 10
_MAX_UNIQUE_PORTS = 15
_MAX_SUSPICIOUS_DOMAINS_TO_SHOW = 10

# RFC1918 private IP ranges (not important for LLM)
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
]

# Suspicious domain patterns (for AI highlighting)
SUSPICIOUS_DOMAIN_PATTERNS = [
    r"\.tk$", r"\.ml$", r"\.ga$", r"\.cf$", r"\.gq$",
    r"\.xyz$", r"\.club$", r"\.online$", r"\.top$", r"\.site$",
    r"ddns", r"no-ip", r"duckdns", r"dyndns", r"dynamic-dns",
    r"free", r"bit\.ly", r"tinyurl", r"pastebin",
    r"c2", r"command", r"server", r"api\.", r"cdn-",
    r"update", r"download", r"cloudflare",
]

# Suspicious ports
SUSPICIOUS_PORTS = {22, 23, 445, 1433, 3306, 3389, 5900, 8080, 8443, 1337, 4444, 6667}


class NetworkParser:
    """Parser for network section - produces full model + AI summary."""
    
    @staticmethod
    def parse(report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse network section from report.
        Returns: { "full": {...}, "ai_summary": {...} }
        """
        try:
            raw_network = NetworkParser._extract_raw_network(report_path)
            if not raw_network:
                return None
            
            full_result = NetworkParser._parse_full_model(raw_network)
            ai_summary = NetworkParser._generate_ai_summary(full_result)
            
            return {
                "full": full_result.model_dump(exclude_none=True),
                "ai_summary": ai_summary.model_dump(exclude_none=True)
            }
            
        except Exception as e:
            _logger.exception(f"Error parsing network section: {e}")
            return None
    
    @staticmethod
    def _extract_raw_network(report_path: Path) -> Optional[Dict[str, Any]]:
        """Extract raw network section from CAPE report."""
        try:
            with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            if isinstance(data, dict):
                return data.get("network", {})
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "network" in item:
                        return item["network"]
            return None
        except Exception as e:
            _logger.error(f"Error extracting network data: {e}")
            return None
    
    @staticmethod
    def _parse_full_model(raw_network: Dict[str, Any]) -> NetworkModel:
        """Parse raw network data into complete model."""
        
        # Parse hosts (keep all - they're already summarized)
        hosts = []
        for host in raw_network.get("hosts", []):
            if isinstance(host, dict):
                hosts.append(HostInfo(
                    ip=host.get("ip", ""),
                    country_name=host.get("country_name"),
                    asn=host.get("asn"),
                    asn_name=host.get("asn_name"),
                    hostname=host.get("hostname"),
                    inaddrarpa=host.get("inaddrarpa"),
                    ports=host.get("ports", []),
                ))
        
        # Parse domains
        domains = []
        for domain in raw_network.get("domains", []):
            if isinstance(domain, dict):
                domains.append(DomainInfo(
                    domain=domain.get("domain", ""),
                    ip=domain.get("ip"),
                ))
        
        # Parse TCP connections - keep only first 200 for full model
        tcp_connections = []
        for conn in raw_network.get("tcp", [])[:200]:
            if isinstance(conn, dict):
                tcp_connections.append(TCPConnection(
                    src=conn.get("src", ""),
                    sport=conn.get("sport", 0),
                    dst=conn.get("dst", ""),
                    dport=conn.get("dport", 0),
                    offset=conn.get("offset", 0),
                    time=conn.get("time", 0.0),
                ))
        
        # Parse UDP connections - keep only first 200 for full model
        udp_connections = []
        for conn in raw_network.get("udp", [])[:200]:
            if isinstance(conn, dict):
                udp_connections.append(UDPConnection(
                    src=conn.get("src", ""),
                    sport=conn.get("sport", 0),
                    dst=conn.get("dst", ""),
                    dport=conn.get("dport", 0),
                    offset=conn.get("offset", 0),
                    time=conn.get("time", 0.0),
                ))
        
        # Parse ICMP
        icmp = []
        for icmp_item in raw_network.get("icmp", []):
            if isinstance(icmp_item, dict):
                icmp.append(ICMPConnection(
                    src=icmp_item.get("src"),
                    dst=icmp_item.get("dst"),
                    type=icmp_item.get("type"),
                    code=icmp_item.get("code"),
                ))
        
        # Parse HTTP
        http_requests = []
        for req in raw_network.get("http", [])[:100]:
            if isinstance(req, dict):
                try:
                    http_requests.append(HTTPRequest(
                        count=req.get("count", 0),
                        host=req.get("host", ""),
                        port=req.get("port", 0),
                        data=req.get("data", ""),
                        uri=req.get("uri", ""),
                        body=req.get("body", ""),
                        path=req.get("path", ""),
                        user_agent=req.get("user-agent", ""),
                        version=req.get("version", ""),
                        method=req.get("method", ""),
                        first_seen=req.get("first_seen", 0.0),
                    ))
                except Exception as e:
                    _logger.warning(f"Failed to parse HTTP request: {e}")
                    continue
        
        # Parse DNS
        dns_queries = []
        for dns in raw_network.get("dns", []):
            if isinstance(dns, dict):
                answers = []
                for ans in dns.get("answers", []):
                    if isinstance(ans, dict):
                        answers.append(DNSAnswer(
                            type=ans.get("type", ""),
                            data=ans.get("data", ""),
                            ttl=ans.get("ttl"),
                        ))
                dns_queries.append(DNSRequest(
                    request=dns.get("request", ""),
                    type=dns.get("type", ""),
                    answers=answers,
                    first_seen=dns.get("first_seen", 0.0),
                ))
        
        # Parse dead hosts
        dead_hosts = []
        raw_dead_hosts = raw_network.get("dead_hosts", [])
        for item in raw_dead_hosts:
            if isinstance(item, list) and len(item) == 2:
                dead_hosts.append(DeadHost(ip=item[0], port=item[1]))
            elif isinstance(item, dict):
                dead_hosts.append(DeadHost(ip=item.get("ip", ""), port=item.get("port", 0)))
        
        # Parse sorted connections (limit)
        sorted_data = raw_network.get("sorted", {})
        sorted_connections = None
        if sorted_data:
            sorted_tcp = []
            for conn in sorted_data.get("tcp", [])[:100]:
                if isinstance(conn, dict):
                    sorted_tcp.append(TCPConnection(
                        src=conn.get("src", ""),
                        sport=conn.get("sport", 0),
                        dst=conn.get("dst", ""),
                        dport=conn.get("dport", 0),
                        offset=conn.get("offset", 0),
                        time=conn.get("time", 0.0),
                    ))
            
            sorted_udp = []
            for conn in sorted_data.get("udp", [])[:100]:
                if isinstance(conn, dict):
                    sorted_udp.append(UDPConnection(
                        src=conn.get("src", ""),
                        sport=conn.get("sport", 0),
                        dst=conn.get("dst", ""),
                        dport=conn.get("dport", 0),
                        offset=conn.get("offset", 0),
                        time=conn.get("time", 0.0),
                    ))
            
            sorted_connections = SortedConnections(
                tcp=sorted_tcp,
                udp=sorted_udp,
            )
        
        # Parse PCAPNG info
        pcapng = None
        if raw_network.get("pcapng"):
            pcapng = PCAPNGInfo(sha256=raw_network["pcapng"].get("sha256", ""))
        
        return NetworkModel(
            pcap_sha256=raw_network.get("pcap_sha256"),
            sorted_pcap_sha256=raw_network.get("sorted_pcap_sha256"),
            hosts=hosts,
            domains=domains,
            tcp=tcp_connections,
            udp=udp_connections,
            icmp=icmp,
            http=http_requests,
            dns=dns_queries,
            smtp=raw_network.get("smtp", []),
            irc=raw_network.get("irc", []),
            dead_hosts=dead_hosts,
            sorted=None,
            pcapng=pcapng,
        )
    
    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Check if an IP address is private (RFC1918)."""
        if not ip_str:
            return True
        try:
            ip = ipaddress.ip_address(ip_str)
            for private_range in PRIVATE_IP_RANGES:
                if ip in private_range:
                    return True
            return False
        except ValueError:
            # Not a valid IP (might be hostname or empty)
            return True
    
    @staticmethod
    def _is_public_ip(ip_str: str) -> bool:
        """Check if an IP address is public (not private)."""
        return not NetworkParser._is_private_ip(ip_str)
    
    @staticmethod
    def _extract_public_ips_from_connections(connections: List[Union[TCPConnection, UDPConnection]]) -> Set[str]:
        """Extract unique public IPs from connection list."""
        public_ips = set()
        for conn in connections:
            if conn.dst and NetworkParser._is_public_ip(conn.dst):
                public_ips.add(conn.dst)
            if conn.src and NetworkParser._is_public_ip(conn.src):
                public_ips.add(conn.src)
        return public_ips
    
    @staticmethod
    def _get_connection_stats(connections: List[Union[TCPConnection, UDPConnection]]) -> Dict[str, Any]:
        """Get statistics about connections (counts, unique ports, unique destinations)."""
        if not connections:
            return {
                "total": 0,
                "unique_ports": [],
                "unique_destinations": [],
                "port_counts": {},
                "suspicious_ports": [],
            }
        
        ports = []
        destinations = []
        for conn in connections:
            ports.append(conn.dport)
            destinations.append(conn.dst)
        
        port_counter = Counter(ports)
        dest_counter = Counter(destinations)
        
        # Get suspicious ports found
        suspicious_ports_found = [p for p in set(ports) if p in SUSPICIOUS_PORTS]
        
        return {
            "total": len(connections),
            "unique_ports": sorted(set(ports))[:_MAX_UNIQUE_PORTS],
            "unique_destinations": list(dest_counter.keys())[:_MAX_UNIQUE_PORTS],
            "port_counts": dict(port_counter.most_common(_MAX_UNIQUE_PORTS)),
            "suspicious_ports": suspicious_ports_found,
        }
    
    @staticmethod
    def _is_suspicious_domain(domain: str) -> Tuple[bool, List[str]]:
        """Check if a domain looks suspicious and return matching patterns."""
        if not domain:
            return False, []
        
        domain_lower = domain.lower()
        matched_patterns = []
        
        for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
            if re.search(pattern, domain_lower, re.IGNORECASE):
                matched_patterns.append(pattern)
        
        return len(matched_patterns) > 0, matched_patterns
    
    @staticmethod
    def _generate_ai_summary(full: NetworkModel) -> NetworkAISummary:
        """Generate compact AI summary from full model."""
        summary = NetworkAISummary()
        
        # === Domains (KEEP ALL - critical IOCs) ===
        all_domains = []
        suspicious_domains = []
        suspicious_keywords = set()
        
        for domain_info in full.domains:
            domain = domain_info.domain
            if domain:
                all_domains.append(domain)
                is_suspicious, patterns = NetworkParser._is_suspicious_domain(domain)
                if is_suspicious:
                    suspicious_domains.append(domain)
                    for pattern in patterns:
                        # Extract keyword from pattern (remove regex special chars)
                        keyword = pattern.replace(r"\.", "").replace(r"\$", "").replace(r"\^", "")
                        suspicious_keywords.add(keyword)
        
        summary.domains = all_domains[:_MAX_DOMAINS]
        summary.has_suspicious_domains = len(suspicious_domains) > 0
        summary.suspicious_domain_keywords = list(suspicious_keywords)[:_MAX_SUSPICIOUS_DOMAINS_TO_SHOW]
        
        # === IPs (Keep only public IPs) ===
        # Extract from hosts
        public_ips_from_hosts = set()
        for host in full.hosts:
            if host.ip and NetworkParser._is_public_ip(host.ip):
                public_ips_from_hosts.add(host.ip)
        
        # Extract from DNS answers
        public_ips_from_dns = set()
        for dns in full.dns:
            for answer in dns.answers:
                if answer.data and NetworkParser._is_public_ip(answer.data):
                    public_ips_from_dns.add(answer.data)
        
        # Extract from TCP/UDP connections
        public_ips_from_tcp = NetworkParser._extract_public_ips_from_connections(full.tcp)
        public_ips_from_udp = NetworkParser._extract_public_ips_from_connections(full.udp)
        
        all_public_ips = public_ips_from_hosts | public_ips_from_dns | public_ips_from_tcp | public_ips_from_udp
        summary.ips = sorted(list(all_public_ips))[:_MAX_PUBLIC_IPS]
        
        # === DNS Queries (Keep with answers) ===
        dns_summaries = []
        for dns in full.dns[:_MAX_DNS_QUERIES]:
            dns_summary = {
                "request": dns.request,
                "type": dns.type,
            }
            if dns.answers:
                dns_summary["answers"] = [{"type": a.type, "data": a.data} for a in dns.answers[:3]]
            dns_summaries.append(dns_summary)
        summary.dns_queries = dns_summaries
        summary.total_dns_queries = len(full.dns)
        summary.has_dns_traffic = len(full.dns) > 0
        
        # === HTTP Requests (Keep summary) ===
        http_summaries = []
        for http in full.http[:_MAX_HTTP_REQUESTS]:
            http_summary = {
                "method": http.method,
                "host": http.host,
                "path": http.path[:100] if http.path else "",
                "port": http.port,
                "user_agent": http.user_agent[:80] if http.user_agent else "",
            }
            # Only include body if present and not too large
            if http.body and len(http.body) < 500:
                http_summary["body"] = http.body[:200]
            http_summaries.append(http_summary)
        summary.http_requests = http_summaries
        summary.total_http_requests = len(full.http)
        summary.has_https_traffic = any("https" in str(req.host).lower() or req.port == 443 for req in full.http)
        
        # === Dead Hosts ===
        dead_hosts_summary = []
        for dead in full.dead_hosts[:_MAX_DEAD_HOSTS]:
            dead_hosts_summary.append({"ip": dead.ip, "port": dead.port})
        summary.dead_hosts = dead_hosts_summary
        
        # === TCP Statistics ===
        tcp_stats = NetworkParser._get_connection_stats(full.tcp)
        summary.total_tcp_connections = tcp_stats["total"]
        
        # === UDP Statistics ===
        udp_stats = NetworkParser._get_connection_stats(full.udp)
        summary.total_udp_connections = udp_stats["total"]
        
        # === Country Distribution ===
        countries = set()
        for host in full.hosts:
            if host.country_name and host.country_name != "unknown":
                countries.add(host.country_name)
        summary.contacted_countries = sorted(list(countries))[:5]
        
        # === Overall network activity flag ===
        summary.has_network_activity = (
            len(full.domains) > 0 or
            len(all_public_ips) > 0 or
            len(full.dns) > 0 or
            len(full.http) > 0 or
            tcp_stats["total"] > 0 or
            udp_stats["total"] > 0
        )
        
        # === Generate quick summary ===
        summary.generate_summary()
        
        return summary


# ============================================================
# Legacy/Compatibility Functions
# ============================================================

def parse_network_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """Main entry point - returns {full, ai_summary}."""
    return NetworkParser.parse(report_path)


def process_network_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """Legacy alias."""
    return parse_network_section(report_path)


# ============================================================
# Self-Execution
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        _logger.info("Usage: python network_parser.py <cape_report.json>")
        sys.exit(1)
    
    report_file = Path(sys.argv[1])
    result = parse_network_section(report_file)
    
    if result:
        print("\n" + "=" * 60)
        print("AI SUMMARY (What goes to LLM)")
        print("=" * 60)
        print(json.dumps(result.get("ai_summary", {}), indent=2))
        
        print("\n" + "=" * 60)
        print("FULL MODEL STATISTICS")
        print("=" * 60)
        full = result.get("full", {})
        
        print(f"Domains: {len(full.get('domains', []))}")
        print(f"Hosts: {len(full.get('hosts', []))}")
        print(f"TCP connections (full): {len(full.get('tcp', []))}")
        print(f"UDP connections (full): {len(full.get('udp', []))}")
        print(f"DNS queries: {len(full.get('dns', []))}")
        print(f"HTTP requests: {len(full.get('http', []))}")
        print(f"Dead hosts: {len(full.get('dead_hosts', []))}")
        
        ai_summary = result.get("ai_summary", {})
        print(f"\nPublic IPs: {len(ai_summary.get('ips', []))}")
        print(f"Domains (AI): {len(ai_summary.get('domains', []))}")
        print(f"DNS queries (AI): {len(ai_summary.get('dns_queries', []))}")
        print(f"\nQuick Summary: {ai_summary.get('quick_summary', 'N/A')}")
    else:
        _logger.error("Failed to parse network section")
        sys.exit(1)