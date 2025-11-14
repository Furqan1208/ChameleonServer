import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple


@dataclass
class WhitelistResults:
    clean_strings: List[str]
    garbage_removed: int
    total_processed: int
    categories: Dict[str, List[str]]


class WhitelistFilter:
    ENGLISH_PATTERNS = [
        r"\b(?:the|and|for|are|but|not|you|all|any|can|her|was|one|our|out|has|had|him|his|how|man|new|now|old|see|two|way|who|boy|did|its|let|put|say|she|too|use)\b",
        r"\b(?:that|with|have|this|will|your|from|they|know|want|been|good|much|some|time|very|when|come|here|just|like|long|make|many|more|only|over|such|take|than|them|well|were)\b",
        r"\b(?:what|which|about|before|could|first|great|other|right|should|these|thing|think|three|after|again|being|called|does|every|found|given|going|house|little|might|never|often|order|place|point|small|sound|still|study|their|there|those|under|until|where|while|world|would|write|years)\b",
        r"\b(?:error|warning|success|failed|completed|loading|starting|stopping|initializing|connecting|disconnected|permission|access|denied|allowed|restricted)\b",
        r"\b(?:file|folder|directory|path|not|found|exists|missing|invalid|valid|correct|incorrect|true|false|yes|no|ok|cancel)\b",
        r"\b(?:please|wait|processing|working|ready|finished|done|complete|successful|unsuccessful|aborted|cancelled)\b",
        r"\b(?:button|menu|window|dialog|form|panel|tab|page|screen|display|show|hide|open|close|minimize|maximize|restore)\b",
        r"\b(?:settings|options|preferences|configuration|properties|attributes|parameters|values|default|custom)\b",
    ]

    FILE_SYSTEM_PATTERNS = [
        r'[A-Za-z]:\\(?:[^<>:"|?*\\]+\\)*[^<>:"|?*\\]*\.(exe|dll|sys|bat|cmd|ps1|vbs|js|txt|log|ini|cfg|config|xml|json|doc|xls|pdf|zip|rar|7z)',
        r'\\\\[^<>:"|?*\\]+(?:\\[^<>:"|?*\\]+)*',
        r'/(?:usr|var|etc|home|tmp|opt|bin|sbin|dev|lib|mnt|root)(?:/[^<>:"|?*\\]+)*\.[a-z0-9]+',
        r'/home/[^/]+/[^<>:"|?*\\]*',
        r'/tmp/[^<>:"|?*\\]*',
        r"\b(?:Windows|System32|SysWOW64|Program Files|ProgramData|AppData|Local|Roaming|Temp|Temporary|Documents|Downloads|Desktop)\b",
        r"\b(?:Users|Public|Administrator|Default|All Users)\b",
    ]

    DLL_PATTERNS = [
        r"\b(?:kernel32|user32|advapi32|ntdll|ws2_32|wininet|urlmon|ole32|oleaut32|comctl32|shell32|gdi32|gdiplus)\b\.dll",
        r"\b(?:msvcrt|msvcp|vcruntime|ucrtbase)\b\.dll",
        r"\b(?:crypt32|cryptui|bcrypt|ncrypt)\b\.dll",
        r"\b(?:iphlpapi|netapi32|wtsapi32)\b\.dll",
        r"\b(?:mscorlib|System|System\.Core|System\.Data|System\.Xml|System\.Windows\.Forms)\b",
        r"\b(?:PresentationCore|PresentationFramework|WindowsBase)\b",
        r"\b(?:python\d+\.dll|v8\.dll|node\.dll|jvm\.dll)\b",
    ]

    URL_PATTERNS = [
        r'https?://[^\s<>"\']+',
        r"www\.[a-z0-9.-]+\.[a-z]{2,}",
        r'ftp://[^\s<>"\']+',
        r'[a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s<>"\']*)?',
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        r"\\\\[^\\]+\\[^\\]+",
    ]

    API_PATTERNS = [
        r"\b(?:CreateProcess|CreateThread|CreateRemoteThread|VirtualAlloc|VirtualProtect|WriteProcessMemory|ReadProcessMemory|OpenProcess|OpenThread|GetProcAddress|LoadLibrary|GetModuleHandle)\b",
        r"\b(?:RegOpenKey|RegCreateKey|RegSetValue|RegQueryValue|RegDeleteKey|RegEnumKey|RegEnumValue)\b",
        r"\b(?:CreateFile|ReadFile|WriteFile|CloseHandle|DeleteFile|MoveFile|CopyFile|FindFirstFile|FindNextFile)\b",
        r"\b(?:GetSystemDirectory|GetWindowsDirectory|GetTempPath|GetCurrentProcess|GetCurrentThread|GetLastError)\b",
        r"\b(?:cmd\.exe|powershell\.exe|pwsh\.exe|wscript\.exe|cscript\.exe|rundll32\.exe|regsvr32\.exe|mshta\.exe)\b",
        r"\b(?:schtasks\.exe|sc\.exe|net\.exe|taskkill\.exe|tasklist\.exe|systeminfo\.exe|ipconfig\.exe)\b",
        r"\b(?:Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod|Start-Process|Get-Content|Set-Content|Out-File|New-Object|Add-Type)\b",
    ]

    REGISTRY_PATTERNS = [
        r'HKEY_[A-Z_]+(?:\\[^<>:"|?*\\]+)+',
        r'Software\\Microsoft\\[^<>:"|?*\\]+',
        r'Software\\Classes\\[^<>:"|?*\\]+',
        r'System\\CurrentControlSet\\[^<>:"|?*\\]+',
        r"Run|RunOnce|RunServices|RunServicesOnce|Policies|Explorer|Windows|CurrentVersion",
        r"\b(?:username|password|token|key|secret|api[_-]?key|auth|login|credential|account)\b",
        r"\b(?:host|port|server|client|endpoint|url|uri|address|proxy|useragent)\b",
        r"\b(?:config|setting|option|parameter|value|default|enable|disable|true|false)\b",
    ]

    SECURITY_PATTERNS = [
        r"\b(?:malware|trojan|virus|worm|ransomware|backdoor|keylogger|rootkit|botnet|payload|dropper|loader)\b",
        r"\b(?:inject|injection|hook|hooking|bypass|evasion|persistence|elevation|escalation|privilege)\b",
        r"\b(?:exploit|vulnerability|shellcode|payload|stager|beacon|command|control|c2|callback)\b",
        r"\b(?:firewall|antivirus|defender|security|protection|scan|detect|block|allow|whitelist|blacklist)\b",
        r"\b(?:encrypt|decrypt|crypt|encode|decode|obfuscate|pack|unpack|compress|decompress)\b",
        r"\b(?:bitcoin|btc|ethereum|eth|monero|xmr|wallet|miner|mining|crypto|blockchain)\b",
    ]

    CODE_PATTERNS = [
        r"\b(?:function|method|class|object|variable|parameter|argument|return|import|export|include|define)\b",
        r"\b(?:string|integer|boolean|array|list|dictionary|hash|map|pointer|reference|instance|static)\b",
        r"\b(?:json|xml|html|yaml|csv|ini|cfg|config|properties|settings|log|txt)\b",
        r"\b(?:temp|tmp|buffer|data|info|result|status|flag|count|size|length|index|offset)\b",
    ]

    def __init__(self):
        self.english_regex = [
            re.compile(p, re.IGNORECASE) for p in self.ENGLISH_PATTERNS
        ]
        self.filesystem_regex = [
            re.compile(p, re.IGNORECASE) for p in self.FILE_SYSTEM_PATTERNS
        ]
        self.dll_regex = [re.compile(p, re.IGNORECASE) for p in self.DLL_PATTERNS]
        self.url_regex = [re.compile(p, re.IGNORECASE) for p in self.URL_PATTERNS]
        self.api_regex = [re.compile(p, re.IGNORECASE) for p in self.API_PATTERNS]
        self.registry_regex = [
            re.compile(p, re.IGNORECASE) for p in self.REGISTRY_PATTERNS
        ]
        self.security_regex = [
            re.compile(p, re.IGNORECASE) for p in self.SECURITY_PATTERNS
        ]
        self.code_regex = [re.compile(p, re.IGNORECASE) for p in self.CODE_PATTERNS]

        self.all_whitelist_patterns = (
            self.english_regex
            + self.filesystem_regex
            + self.dll_regex
            + self.url_regex
            + self.api_regex
            + self.registry_regex
            + self.security_regex
            + self.code_regex
        )

    def is_whitelisted(self, string: str) -> Tuple[bool, str]:
        cleaned_string = string.strip()

        if len(cleaned_string) < 3 or len(cleaned_string) > 1000:
            return False, "bad_length"

        category_checks = [
            (self.english_regex, "english_text"),
            (self.filesystem_regex, "file_system"),
            (self.dll_regex, "dll_libraries"),
            (self.url_regex, "urls_network"),
            (self.api_regex, "windows_api"),
            (self.registry_regex, "registry_config"),
            (self.security_regex, "security_malware"),
            (self.code_regex, "programming_code"),
        ]

        for patterns, category in category_checks:
            for pattern in patterns:
                if pattern.search(cleaned_string):
                    return True, category

        return False, "garbage"


def extract_all_strings(data: Any) -> List[str]:
    strings = set()

    def extract_recursive(obj):
        if isinstance(obj, str):
            cleaned = obj.strip()
            if cleaned:
                strings.add(cleaned)
        elif isinstance(obj, dict):
            for value in obj.values():
                extract_recursive(value)
        elif isinstance(obj, list):
            for item in obj:
                extract_recursive(item)

    extract_recursive(data)
    return list(strings)


def extract_section_strings(data: Any, section_keywords: List[str]) -> List[str]:
    section_strings = set()

    def extract_from_section(obj, path=""):
        if isinstance(obj, str):
            section_strings.add(obj.strip())
        elif isinstance(obj, dict):
            for key, value in obj.items():
                key_lower = key.lower()
                if any(keyword in key_lower for keyword in section_keywords):
                    if isinstance(value, str):
                        section_strings.add(value.strip())
                extract_from_section(value, f"{path}.{key}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                extract_from_section(item, f"{path}[{i}]")

    if isinstance(data, dict):
        for key in data:
            if any(keyword in key.lower() for keyword in section_keywords):
                extract_from_section(data[key])

    return list(section_strings)


def extract_target_strings(data: Any) -> List[str]:
    return extract_section_strings(data, ["target", "file", "path", "name", "string"])


def extract_dropped_strings(data: Any) -> List[str]:
    return extract_section_strings(data, ["dropped", "file", "path", "name", "string"])


def process_whitelist_filtering(report_path: Path) -> WhitelistResults:
    print(f"Processing with whitelist: {report_path.name}")

    try:
        with open(report_path, "r", encoding="utf-8", errors="ignore") as file:
            data = json.load(file)
    except Exception as error:
        print(f"Error loading JSON: {error}")
        sys.exit(1)

    print("Extracting strings from sections...")
    all_strings = extract_all_strings(data)
    target_strings = extract_target_strings(data)
    dropped_strings = extract_dropped_strings(data)

    combined_strings = list(set(all_strings + target_strings + dropped_strings))

    print(f"    - Total unique strings: {len(combined_strings)}")
    print(f"    - Target section strings: {len(target_strings)}")
    print(f"    - Dropped section strings: {len(dropped_strings)}")

    print("Applying whitelist filtering...")
    filter_engine = WhitelistFilter()
    clean_strings = []
    garbage_count = 0

    categories = {
        "english_text": [],
        "file_system": [],
        "dll_libraries": [],
        "urls_network": [],
        "windows_api": [],
        "registry_config": [],
        "security_malware": [],
        "programming_code": [],
    }

    for string in combined_strings:
        is_whitelisted, category = filter_engine.is_whitelisted(string)

        if is_whitelisted:
            clean_strings.append(string)
            categories[category].append(string)
        else:
            garbage_count += 1

    categories = {k: v for k, v in categories.items() if v}

    total_processed = len(combined_strings)
    clean_count = len(clean_strings)

    print("Whitelist filtering complete:")
    print(f"    - Total processed: {total_processed:,}")
    print(
        f"    - Whitelisted (clean): {clean_count:,} ({clean_count / total_processed * 100:.1f}%)"
    )
    print(
        f"    - Garbage removed: {garbage_count:,} ({garbage_count / total_processed * 100:.1f}%)"
    )
    print(f"    - Categories found: {len(categories)}")

    for category, strings in categories.items():
        print(f"        {category}: {len(strings)} strings")

    return WhitelistResults(
        clean_strings=sorted(clean_strings),
        garbage_removed=garbage_count,
        total_processed=total_processed,
        categories=categories,
    )


def save_results(results: WhitelistResults, output_path: Path):
    output_data = {
        "metadata": {
            "strategy": "whitelist_only",
            "total_strings_processed": results.total_processed,
            "whitelisted_strings": len(results.clean_strings),
            "garbage_removed": results.garbage_removed,
            "reduction_percentage": f"{(results.garbage_removed / results.total_processed) * 100:.1f}%",
            "whitelist_categories_used": list(results.categories.keys()),
        },
        "categories": results.categories,
        "all_clean_strings": results.clean_strings,
    }

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(output_data, file, indent=2, ensure_ascii=False)

    print(f"Whitelist results saved to: {output_path}")


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python strings_model_whitelist.py <cape_report.json> [output.json]"
        )
        sys.exit(1)

    report_path = Path(sys.argv[1])
    output_path = (
        Path(sys.argv[2])
        if len(sys.argv) > 2
        else report_path.with_name(report_path.stem + "_whitelist_clean.json")
    )

    if not report_path.exists():
        print(f"File not found: {report_path}")
        sys.exit(1)

    results = process_whitelist_filtering(report_path)
    save_results(results, output_path)

    print("\nSample whitelisted strings by category:")
    for category, strings in results.categories.items():
        print(f"\n  {category.upper()}:")
        for i, string in enumerate(strings[:3]):
            display = string if len(string) <= 60 else string[:57] + "..."
            print(f"    {i + 1}. {display}")


if __name__ == "__main__":
    main()
