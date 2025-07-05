# patterns.py
"""
Constants and regex patterns for malware analysis.
Limtation: If the string is not in the list specified below, the custom malware report will fail to include it.
This must be externalised in a database or configuration file for better flexibility.
"""

SUSPICIOUS_KEYWORDS = [
    "ransomware", "keylogger", "backdoor", "shellcode", "exploit", "virus",
    "trojan", "worm", "malware", "spyware", "adware", "phishing", "botnet",
    "exploit kit", "rootkit", "DDoS attack", "SQL injection", "XSS attack",
    "command injection", "buffer overflow"
]

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

SUSPICIOUS_FILENAMES = [
    "wannacry.exe", "evil.dll", "payload.bin", "exploit.sys",
    "iloveyou", "stuxnet", "zues"
]

IP_REGEX = r"(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"
POWERSHELL_REGEX = r"powershell.+?(?:\\-enc|\\-encodedcommand)"
REGISTRY_PATH_REGEX = r"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
YARA_RULE_REGEX = r"rule\\s+\\w+\\s*\\{[^}]+\\}"
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
HIGH_ENTROPY_THRESHOLD = 4.5
