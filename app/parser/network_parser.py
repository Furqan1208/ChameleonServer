# app/parsers/network_parser.py

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from app.models.networkmodel import NetworkModel, NetworkTopLevel


# Configuration for what to keep/exclude
HIGH_VALUE_DOMAINS_EXTENSIONS = {'.exe', '.dll', '.zip', '.rar', '.7z', '.ps1', '.vbs', '.js'}
SUSPICIOUS_PORTS = {445, 139, 3389, 22, 23, 21, 1433, 3306, 5900, 5800}
SUSPICIOUS_USER_AGENTS = {'powershell', 'curl', 'wget', 'ncsi', 'winhttp'}

EXCLUDE_HTTP_FIELDS = {'data', 'body', 'version'}
EXCLUDE_DNS_FIELDS = {'first_seen'}
EXCLUDE_CONNECTION_FIELDS = {'offset', 'time'}


def extract_network_data(file_path: Path) -> Optional[Dict[str, Any]]:
    """
    Extract the network section from a CAPE/Cuckoo report JSON file.
    
    Args:
        file_path: Path to the report JSON file
        
    Returns:
        Dictionary containing network data or None if not found
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            report_data = json.load(file)

        # Handle different report structures
        if isinstance(report_data, list):
            for item in report_data:
                if "network" in item:
                    return item["network"]
            return None
        elif isinstance(report_data, dict):
            # Try direct network key
            network = report_data.get("network")
            if network:
                return network
            
            # Try behavior.network (some reports nest it)
            behavior = report_data.get("behavior", {})
            if isinstance(behavior, dict):
                return behavior.get("network")
            
            return None
        else:
            return None

    except Exception as error:
        print(f"Error reading report file: {error}")
        return None


def filter_hosts(hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter hosts to keep only those with suspicious characteristics.
    
    Args:
        hosts: List of host dictionaries
        
    Returns:
        Filtered list of hosts
    """
    if not hosts:
        return []
    
    filtered = []
    for host in hosts:
        # Keep hosts with open ports or external IPs
        ip = host.get("ip", "")
        ports = host.get("ports", [])
        
        # Skip local/private IPs unless they have unusual ports
        if ip.startswith(("192.168.", "10.", "172.16.", "127.0.0.")):
            if not any(p in SUSPICIOUS_PORTS for p in ports):
                continue
        
        # Create filtered host entry
        filtered_host = {
            "ip": ip,
            "ports": ports[:5],  # Limit to first 5 ports
        }
        
        # Add ASN info if available (valuable for threat intel)
        if host.get("asn") and host.get("asn") != "":
            filtered_host["asn"] = host.get("asn")
        if host.get("country_name") and host.get("country_name") != "unknown":
            filtered_host["country"] = host.get("country_name")
            
        filtered.append(filtered_host)
    
    return filtered


def filter_domains(domains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter domains to identify potentially malicious ones.
    
    Args:
        domains: List of domain dictionaries
        
    Returns:
        Filtered list of domains
    """
    if not domains:
        return []
    
    # Group domains by domain name to identify unique ones
    domain_dict = {}
    for domain in domains:
        name = domain.get("domain", "")
        if not name:
            continue
            
        # Skip common benign domains
        if name in ("www.msftconnecttest.com", "ctldl.windowsupdate.com", 
                   "www.msftncsi.com", "dns.msftncsi.com"):
            continue
            
        # Track unique domains with their IPs
        if name not in domain_dict:
            domain_dict[name] = {
                "domain": name,
                "ip": domain.get("ip", ""),
                "tld": name.split('.')[-1] if '.' in name else "",
            }
            
            # Check for suspicious TLDs
            suspicious_tlds = {'.ru', '.cn', '.tk', '.xyz', '.top', '.club', '.work'}
            if domain_dict[name]["tld"] in suspicious_tlds:
                domain_dict[name]["suspicious_tld"] = True
    
    return list(domain_dict.values())[:20]  # Limit to top 20 domains


def filter_http_traffic(http_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract important HTTP traffic indicators.
    
    Args:
        http_list: List of HTTP request dictionaries
        
    Returns:
        Filtered list of important HTTP requests
    """
    if not http_list:
        return []
    
    filtered = []
    for http in http_list:
        # Skip if missing key data
        if not http.get("host") or not http.get("uri"):
            continue
            
        # Check for suspicious indicators
        uri = http.get("uri", "").lower()
        host = http.get("host", "").lower()
        user_agent = http.get("user-agent", "").lower()
        method = http.get("method", "")
        
        # Skip common Microsoft connectivity tests
        if "msftconnecttest.com" in host or "msftncsi.com" in host:
            continue
            
        # Create filtered entry with key indicators
        filtered_entry = {
            "method": method,
            "host": host,
            "path": http.get("path", ""),
            "user_agent": user_agent[:100] if user_agent else "",  # Truncate long UAs
            "count": http.get("count", 1),
        }
        
        # Flag suspicious patterns
        suspicious = False
        
        # Check for file downloads
        if any(ext in uri for ext in HIGH_VALUE_DOMAINS_EXTENSIONS):
            filtered_entry["file_download"] = True
            suspicious = True
            
        # Check for suspicious user agents
        if any(agent in user_agent for agent in SUSPICIOUS_USER_AGENTS):
            filtered_entry["suspicious_ua"] = True
            suspicious = True
            
        # Check for POST to non-standard paths
        if method == "POST" and http.get("path") in ["/", ""]:
            filtered_entry["post_to_root"] = True
            suspicious = True
            
        if suspicious or filtered_entry.get("count", 0) > 5:
            filtered_entry["flagged"] = True

        # Include all non-Microsoft HTTP traffic (not just flagged)
        filtered.append(filtered_entry)
    
    return filtered[:30]  # Limit to top 30 requests


def filter_dns_queries(dns_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract important DNS queries and responses.
    
    Args:
        dns_list: List of DNS query dictionaries
        
    Returns:
        Filtered list of important DNS queries
    """
    if not dns_list:
        return []
    
    # Track unique queries with their answers
    query_dict = {}
    
    for dns in dns_list:
        request = dns.get("request", "")
        if not request:
            continue
            
        # Skip common benign queries
        if request in ("www.msftconnecttest.com", "ctldl.windowsupdate.com", 
                      "www.msftncsi.com", "dns.msftncsi.com", "time.windows.com"):
            continue
            
        # Get answers
        answers = dns.get("answers", [])
        answer_data = []
        
        for ans in answers:
            if ans.get("type") == "A" and ans.get("data"):
                answer_data.append(ans.get("data"))
        
        # Create key for this query
        if request not in query_dict:
            query_dict[request] = {
                "query": request,
                "answers": answer_data[:3],  # Limit to first 3 answers
                "type": dns.get("type", "A"),
            }
            
            # Flag if no answers (NXDOMAIN can be suspicious)
            if not answer_data:
                query_dict[request]["no_answer"] = True
    
    return list(query_dict.values())[:30]  # Limit to 30 unique queries


def filter_connections(
    connections: List[Dict[str, Any]], 
    protocol: str
) -> List[Dict[str, Any]]:
    """
    Filter network connections to keep important ones.
    
    Args:
        connections: List of connection dictionaries
        protocol: Protocol name (tcp/udp)
        
    Returns:
        Filtered list of important connections
    """
    if not connections:
        return []
    
    # Track unique connections (src:dst:port)
    unique_conns = {}
    
    for conn in connections:
        dst = conn.get("dst", "")
        dport = conn.get("dport", 0)
        src = conn.get("src", "")
        
        # Skip local traffic unless to unusual ports
        if dst.startswith(("192.168.", "10.", "172.16.")):
            if dport not in SUSPICIOUS_PORTS:
                continue
        
        # Create key for unique connection
        conn_key = f"{src}:{dst}:{dport}"
        
        if conn_key not in unique_conns:
            unique_conns[conn_key] = {
                "dst": dst,
                "dport": dport,
                "protocol": protocol.upper(),
            }
            
            # Add source if not local
            if not src.startswith(("192.168.", "10.", "172.16.")):
                unique_conns[conn_key]["src"] = src
    
    return list(unique_conns.values())[:50]  # Limit to 50 unique connections


def filter_dead_hosts(dead_hosts: List[Any]) -> List[Dict[str, Any]]:
    """
    Extract dead hosts (failed connection attempts).
    
    Args:
        dead_hosts: List of dead host entries
        
    Returns:
        Filtered list of dead hosts
    """
    if not dead_hosts:
        return []
    
    filtered = []
    for item in dead_hosts:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            filtered.append({
                "ip": item[0],
                "port": item[1],
                "failed": True
            })
        elif isinstance(item, dict):
            filtered.append({
                "ip": item.get("ip", ""),
                "port": item.get("port", 0),
                "failed": True
            })
    
    return filtered[:20]  # Limit to 20 dead hosts


def prepare_cleaned_network(raw_network: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Clean and filter network data to extract only important fields for AI analysis.
    
    Args:
        raw_network: Raw network dictionary from report
        
    Returns:
        Cleaned and filtered network dictionary
    """
    if not raw_network:
        return None

    try:
        # Validate with Pydantic model
        validated_network = NetworkModel(**raw_network)
        
        # Build cleaned network data structure
        cleaned_data = {
            "network_summary": {
                "total_hosts": len(validated_network.hosts),
                "total_domains": len(validated_network.domains),
                "total_http_requests": len(validated_network.http),
                "total_dns_queries": len(validated_network.dns),
                "has_pcap": bool(validated_network.pcap_sha256),
            }
        }
        
        # Add filtered hosts
        if validated_network.hosts:
            filtered_hosts = filter_hosts([h.model_dump() for h in validated_network.hosts])
            if filtered_hosts:
                cleaned_data["hosts"] = filtered_hosts
        
        # Add filtered domains
        if validated_network.domains:
            filtered_domains = filter_domains([d.model_dump() for d in validated_network.domains])
            if filtered_domains:
                cleaned_data["domains"] = filtered_domains
        
        # Add filtered HTTP traffic
        if validated_network.http:
            filtered_http = filter_http_traffic([h.model_dump() for h in validated_network.http])
            if filtered_http:
                cleaned_data["http_requests"] = filtered_http
        
        # Add filtered DNS queries
        if validated_network.dns:
            filtered_dns = filter_dns_queries([d.model_dump() for d in validated_network.dns])
            if filtered_dns:
                cleaned_data["dns_queries"] = filtered_dns
        
        # Add filtered connections
        tcp_conns = []
        if validated_network.tcp:
            tcp_conns = filter_connections([t.model_dump() for t in validated_network.tcp], "tcp")
        
        udp_conns = []
        if validated_network.udp:
            udp_conns = filter_connections([u.model_dump() for u in validated_network.udp], "udp")
        
        all_conns = tcp_conns + udp_conns
        if all_conns:
            cleaned_data["connections"] = all_conns
        
        # Add dead hosts (failed connection attempts)
        if validated_network.dead_hosts:
            dead_dicts = [
                h.model_dump() if hasattr(h, 'model_dump') else h
                for h in validated_network.dead_hosts
            ]
            filtered_dead = filter_dead_hosts(dead_dicts)
            if filtered_dead:
                cleaned_data["failed_connections"] = filtered_dead
        
        # Extract IOC summary
        ioc_summary = {
            "suspicious_domains": [
                d["domain"] for d in cleaned_data.get("domains", []) 
                if d.get("suspicious_tld") or not d.get("ip")
            ],
            "suspicious_ips": [
                h["ip"] for h in cleaned_data.get("hosts", [])
                if h.get("ports") and any(p in SUSPICIOUS_PORTS for p in h["ports"])
            ],
            "file_downloads": [
                f"{h['host']}{h['path']}" for h in cleaned_data.get("http_requests", [])
                if h.get("file_download")
            ],
        }
        cleaned_data["ioc_summary"] = ioc_summary
        
        return cleaned_data

    except Exception as error:
        print(f"Error processing network data: {error}")
        return None


def parse_network_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """
    Main function to parse and filter network section from report.
    
    Args:
        report_path: Path to the report JSON file
        
    Returns:
        Cleaned network data dictionary or None if error
    """
    raw_network = extract_network_data(report_path)
    return prepare_cleaned_network(raw_network)


def process_network_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """
    Alias for parse_network_section for consistency with other parsers.
    
    Args:
        report_path: Path to the report JSON file
        
    Returns:
        Cleaned network data dictionary or None if error
    """
    return parse_network_section(report_path)


def get_network_iocs(report_path: Path) -> Dict[str, List[str]]:
    """
    Extract only IOCs (Indicators of Compromise) from network data.
    
    Args:
        report_path: Path to the report JSON file
        
    Returns:
        Dictionary with lists of IPs, domains, and URLs
    """
    cleaned = parse_network_section(report_path)
    
    iocs = {
        "ips": [],
        "domains": [],
        "urls": [],
        "suspicious_ports": [],
    }
    
    if not cleaned:
        return iocs
    
    # Extract IPs from hosts
    for host in cleaned.get("hosts", []):
        if host.get("ip"):
            iocs["ips"].append(host["ip"])
        if host.get("ports"):
            iocs["suspicious_ports"].extend([str(p) for p in host["ports"]])
    
    # Extract domains
    for domain in cleaned.get("domains", []):
        if domain.get("domain"):
            iocs["domains"].append(domain["domain"])
    
    # Extract URLs from HTTP requests
    for http in cleaned.get("http_requests", []):
        host = http.get("host", "")
        path = http.get("path", "")
        if host and path:
            iocs["urls"].append(f"http://{host}{path}")
    
    # Remove duplicates
    for key in iocs:
        iocs[key] = list(set(iocs[key]))[:50]  # Limit to 50 per category
    
    return iocs


if __name__ == "__main__":
    import sys
    from pprint import pprint
    
    if len(sys.argv) < 2:
        print("Usage: python network_parser.py <report.json>")
        sys.exit(1)
    
    report_file = Path(sys.argv[1])
    output_file = report_file.parent / f"{report_file.stem}_network_parsed.json"
    
    # Parse network section
    cleaned_network = parse_network_section(report_file)
    
    if cleaned_network:
        # Save cleaned data
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(cleaned_network, f, indent=2)
        print(f"✅ Cleaned network data saved to: {output_file}")
        
        # Print summary
        print("\n📊 NETWORK ANALYSIS SUMMARY")
        print("=" * 50)
        print(json.dumps(cleaned_network.get("network_summary", {}), indent=2))
        
        # Print IOCs
        print("\n🔍 EXTRACTED IOCs")
        print("=" * 50)
        iocs = get_network_iocs(report_file)
        pprint(iocs)
    else:
        print("❌ Failed to parse network section")