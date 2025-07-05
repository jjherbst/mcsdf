import hashlib
from pathlib import Path
from typing import Dict, Optional
import vt

class VirusTotalAnalyzer:
    @staticmethod
    def extract_mitre_attack(vt_attrs: dict) -> list:
        """Extract MITRE ATT&CK techniques from VirusTotal attributes."""
        if not vt_attrs or not isinstance(vt_attrs, dict):
            return []
        mitre = vt_attrs.get("crowdsourced_attack_techniques", [])
        result = []
        if isinstance(mitre, list):
            for entry in mitre:
                if not isinstance(entry, dict):
                    continue
                tid = entry.get("technique_id", "?")
                tname = entry.get("technique", "?")
                tactic = entry.get("tactic", "?")
                framework = entry.get("framework", "MITRE ATT&CK")
                desc = entry.get("description", None)
                result.append({
                    "technique_id": tid,
                    "technique": tname,
                    "tactic": tactic,
                    "framework": framework,
                    "description": desc
                })
        return result

    @staticmethod
    def extract_summary_attributes(vt_attrs: dict) -> dict:
        """Extract key VirusTotal v3 attributes for summary reporting."""
        if not vt_attrs or not isinstance(vt_attrs, dict):
            return {}
        def safe_join(val, limit=5):
            if isinstance(val, list):
                return ', '.join(val[:limit]) + ("..." if len(val) > limit else "")
            return val
        def safe_get_dict(d, key, subkey):
            val = d.get(key)
            if isinstance(val, dict):
                return val.get(subkey)
            return None
        def safe_get_list_of_dicts(d, key, subkey):
            val = d.get(key)
            if isinstance(val, list) and val and isinstance(val[0], dict):
                return val[0].get(subkey)
            return None
        return {
            "SHA256": vt_attrs.get("sha256"),
            "SHA1": vt_attrs.get("sha1"),
            "MD5": vt_attrs.get("md5"),
            "Authentihash": vt_attrs.get("authentihash"),
            "TLSH": vt_attrs.get("tlsh"),
            "vHash": vt_attrs.get("vhash"),
            "Tags": safe_join(vt_attrs.get("tags", [])),
            "Names": safe_join(vt_attrs.get("names", [])),
            "Type Description": vt_attrs.get("type_description"),
            "File Size": vt_attrs.get("size"),
            "First Submission": vt_attrs.get("first_submission_date"),
            "Last Submission": vt_attrs.get("last_submission_date"),
            "Meaningful Name": vt_attrs.get("meaningful_name"),
            "DetectItEasy": safe_get_dict(vt_attrs, "detectiteasy", "values"),
            "Magika": safe_get_dict(vt_attrs, "magika", "description"),
            "TrID": safe_get_list_of_dicts(vt_attrs, "trid", "file_type"),
            "FileCondis": vt_attrs.get("filecondis"),
            "Total Votes": vt_attrs.get("total_votes"),
        }
    """VirusTotal analyzer using the official vt-py library."""
    def __init__(self, api_key: str):
        self.api_key = api_key

    def _validate_api_key(self, api_key: str) -> bool:
        """Validate VirusTotal API key format."""
        if not api_key:
            return False
        # VirusTotal API keys are typically 64 hexadecimal characters
        if len(api_key) != 64:
            print(f" Invalid API key length: {len(api_key)} characters (expected: 64)")
            return False
        if not all(c in '0123456789abcdefABCDEF' for c in api_key):
            print(f" Invalid API key format: must contain only hexadecimal characters")
            return False
        return True

    async def analyze_file(self, file_path: Path) -> Optional[Dict]:
        """Analyze a file with VirusTotal using the official library."""
        try:
            print(f" Connecting to VirusTotal...")
            async with vt.Client(self.api_key) as client:
                file_hash = self._calculate_sha256(file_path)
                print(f" File SHA-256: {file_hash}")
                # Try to get existing analysis first
                try:
                    print(f" Checking for existing analysis...")
                    file_obj = await client.get_object_async(f"/files/{file_hash}")
                    print(f"Found existing analysis")
                    return self._convert_vt_object_to_dict(file_obj)
                except vt.APIError as e:
                    if e.code == "NotFoundError":
                        print(f" File not found in database, uploading...")
                    elif e.code == "WrongCredentialsError" or "Wrong API key" in str(e):
                        print(f" Invalid VirusTotal API key")
                        print(f" Please verify your API key is correct and active")
                        print(f" You can get a free API key from: https://www.virustotal.com/gui/join-us")
                        return None
                    else:
                        print(f" Error checking existing analysis: {e}")
                        return None
                # Upload file for analysis
                print(f" Uploading file: {file_path.name}")
                with open(file_path, "rb") as f:
                    analysis = await client.scan_file_async(f, wait_for_completion=True)
                print(f"Analysis completed!")
                # Get the detailed file report
                file_obj = await client.get_object_async(f"/files/{file_hash}")
                return self._convert_vt_object_to_dict(file_obj)
        except vt.APIError as e:
            if "Invalid API key" in str(e) or "WrongCredentialsError" in str(e) or "Wrong API key" in str(e):
                print(f" Invalid VirusTotal API key")
                print(f" Please verify your API key is correct and active")
                print(f" API key format should be: 64 hexadecimal characters")
                print(f" You can get a free API key from: https://www.virustotal.com/gui/join-us")
            elif "Quota exceeded" in str(e):
                print(f" API quota exceeded")
                print(f" Please wait or upgrade your VirusTotal plan")
            else:
                print(f" VirusTotal API error: {e}")
            return None
        except Exception as e:
            print(f" Unexpected error: {e}")
            return None

    def _calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def _convert_vt_object_to_dict(self, vt_obj) -> Dict:
        """Convert VirusTotal object to dictionary format."""
        result = {
            "data": {
                "id": vt_obj.id,
                "type": vt_obj.type,
                "attributes": {}
            }
        }
        # Copy all attributes from the VT object
        for attr_name in dir(vt_obj):
            if not attr_name.startswith('_') and hasattr(vt_obj, attr_name):
                try:
                    attr_value = getattr(vt_obj, attr_name)
                    if not callable(attr_value) and attr_name not in ['id', 'type']:
                        result["data"]["attributes"][attr_name] = attr_value
                except:
                    continue
        return result