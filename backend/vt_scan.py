import os
import hashlib
import httpx
import logging

logger = logging.getLogger(__name__)

async def get_virustotal_report(file_path: str) -> dict:
    """
    Computes SHA256 of the APK and queries the free VirusTotal API.
    Returns the VT scan report summary if found.
    """
    vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not vt_api_key:
        logger.warning("VIRUSTOTAL_API_KEY not set. Skipping VT integration.")
        return {"status": "skipped", "reason": "No API key"}

    # Compute SHA256 hash
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Failed to hash {file_path}: {e}")
        return {"status": "error", "reason": "Hashing failed"}

    # Query VT v3 API
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": vt_api_key}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=10.0)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                undetected = stats.get("undetected", 0)
                
                logger.info(f"VT Result for {file_hash}: {malicious} malicious detections.")
                return {
                    "status": "success", 
                    "malicious": malicious, 
                    "undetected": undetected,
                    "total": malicious + undetected,
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
                }
            elif response.status_code == 404:
                return {"status": "not_found", "reason": "File not previously scanned by VT"}
            elif response.status_code == 401:
                return {"status": "auth_error", "reason": "Invalid VT API key"}
            elif response.status_code == 429:
                return {"status": "rate_limited", "reason": "VT Free Tier rate limit exceeded"}
            else:
                return {"status": "error", "reason": f"HTTP {response.status_code}"}
    except Exception as e:
        logger.error(f"VT API request failed: {e}")
        return {"status": "error", "reason": str(e)}
