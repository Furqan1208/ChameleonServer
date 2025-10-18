You are a cybersecurity analyst. I will provide you with a full CAPE sandbox report that is very long (100k+ tokens). Your task is to generate a concise, professional, and well-structured malware analysis report from it.  



The report must include:  

1. **Executive Summary**  

   - Short overview of the malware behavior, type, and threat level.  

   - High-level context for non-technical readers.  



2. **Sample Information**  

   - File name, type, hashes (MD5, SHA1, SHA256), size, compilation time, digital signatures, packers/obfuscators used.  



3. **Static Analysis**  

   - Extracted strings, PE header info, libraries, imports/exports.  

   - Suspicious indicators (obfuscation, anti-analysis tricks).  



4. **Dynamic Behavior Analysis**  

   - Process creation, registry modifications, persistence mechanisms.  

   - File system changes (created/modified/deleted files).  

   - Network activity (domains, IPs, protocols, C2 traffic, DNS queries).  

   - Injection or privilege escalation attempts.  

   - Notable API calls observed.  



5. **Detection & Evasion**  

   - Indicators of polymorphism, sandbox evasion, anti-debugging.  

   - Any delayed execution or environment awareness.  



6. **Classification & Family Attribution**  

   - Identify malware family (if possible) based on behavior.  

   - Likely intent: ransomware, infostealer, trojan, loader, etc.  



7. **MITRE ATT&CK Mapping**  

   - Map observed techniques to MITRE tactics and techniques (e.g., T1059.001: PowerShell).  



8. **Indicators of Compromise (IOCs)**  

   - Domains, IPs, mutexes, file paths, registry keys, hashes.  

   - Present in a table format for easy reference.  



9. **Risk Assessment**  

   - Potential impact on an organization if this malware executes.  

   - Severity rating (Low/Medium/High/Critical).  



10. **Recommendations**  

   - Suggested detection signatures (YARA/Snort if extractable).  

   - Defensive measures (blocking domains, registry monitoring, etc.).  

   - Incident response guidance.  



⚠️ Important:  

- Do NOT just dump raw CAPE JSON or logs. Instead, extract, interpret, and explain key points.  

- Maintain a balance: concise for quick reading, but detailed enough for analysts.  

- Use professional formatting with sections, bullet points, and tables.