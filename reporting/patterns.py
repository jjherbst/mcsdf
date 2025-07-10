# patterns.py
"""
Malware Analysis Pattern Definitions - Comprehensive collection of 
suspicious keywords, domain patterns, filename indicators, and regex 
patterns for static malware analysis and threat detection systems, 
designed for educational cybersecurity research and detection testing.

Limitation: If the string is not in the list specified below, the custom 
malware report will fail to include it. This must be externalized in a 
database or configuration file for better flexibility.
"""

"""
description: List of suspicious keywords commonly found in malware for threat classification and detection
parameters: None (constant list)
returns: List of strings containing malware-related terminology for pattern matching analysis
"""
SUSPICIOUS_KEYWORDS = [
    "ransomware", "keylogger", "backdoor", "shellcode", "exploit", "virus",
    "trojan", "worm", "malware", "spyware", "adware", "phishing", "botnet",
    "exploit kit", "rootkit", "DDoS attack", "SQL injection", "XSS attack",
    "command injection", "buffer overflow"
]

"""
description: Regex patterns for detecting suspicious domain names and C2 communication endpoints in malware
parameters: None (constant list)
returns: List of regex patterns for identifying malicious domains and command-and-control infrastructure
"""
SUSPICIOUS_DOMAINS = [
    r"fake\\.hacker\\.com", r"haxor\\-c2\\.example\\.net", r"evil\\.malicious\\.com",
    r"malicious\\.anonymous\\.com", r"c2\\..*\\.com",
    r"evil\\.[a-zA-Z0-9\\-]+\\.(com|net|org)",
    r"malicious\\.[a-zA-Z0-9\\-]+\\.(com|net|org)",
    r"hacker\\.[a-zA-Z0-9\\-]+\\.(com|net|org)",
    r"backdoor\\.[a-zA-Z0-9\\-]+\\.(com|net|org)",
    r"trojan\\.[a-zA-Z0-9\\-]+\\.(com|net|org)",
    r"botnet\\.[a-zA-Z0-9\\-]+\\.(com|net|org)"
]

"""
description: List of suspicious filename patterns commonly associated with malware families and threats
parameters: None (constant list)
returns: List of strings containing known malicious filenames for threat identification and analysis
"""
SUSPICIOUS_FILENAMES = [
    "wannacry.exe", "evil.dll", "payload.bin", "exploit.sys",
    "iloveyou", "stuxnet", "zues"
]

"""
description: Regex pattern for detecting IPv4 addresses in malware strings for network indicator analysis
parameters: None (constant string)
returns: String containing regex pattern to match IPv4 address format in text analysis
"""
IP_REGEX = r"(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"

"""
description: Regex pattern for detecting PowerShell commands with encoding parameters indicating obfuscation
parameters: None (constant string)
returns: String containing regex pattern to identify potentially malicious PowerShell command usage
"""
POWERSHELL_REGEX = r"powershell.+?(?:\\-enc|\\-encodedcommand)"

"""
description: Regex pattern for detecting Windows registry autorun key modifications for persistence mechanisms
parameters: None (constant string)
returns: String containing regex pattern to identify registry persistence indicator locations
"""
REGISTRY_PATH_REGEX = r"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"

"""
description: Regex pattern for detecting YARA rule syntax and structure in malware analysis contexts
parameters: None (constant string)
returns: String containing regex pattern to identify YARA rule definitions and signatures
"""
YARA_RULE_REGEX = r"rule\\s+\\w+\\s*\\{[^}]+\\}"

"""
description: EICAR antivirus test signature for validating malware detection systems and scanner functionality
parameters: None (constant bytes)
returns: Bytes containing the standard EICAR test file signature for antivirus validation testing
"""
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

"""
description: Shannon entropy threshold value for detecting encrypted or compressed data sections in binaries
parameters: None (constant float)
returns: Float representing entropy threshold above which data is considered potentially obfuscated or encrypted
"""
HIGH_ENTROPY_THRESHOLD = 4.5
