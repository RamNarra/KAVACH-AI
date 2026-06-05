import os
import hashlib
import httpx
import logging

logger = logging.getLogger(__name__)

import asyncio

async def get_virustotal_report(file_path: str) -> dict:
    """
    Computes SHA256 of the APK and queries the free VirusTotal API.
    If the hash is not found (404), uploads the physical APK file to VirusTotal
    and polls for the analysis status.
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
                logger.info(f"File {file_hash} not found in VirusTotal. Initializing upload flow...")
                
                # Check file size; get large file upload URL if > 32MB
                upload_url = "https://www.virustotal.com/api/v3/files"
                try:
                    file_size = os.path.getsize(file_path)
                    if file_size > 32 * 1024 * 1024:
                        url_res = await client.get("https://www.virustotal.com/api/v3/files/upload_url", headers=headers, timeout=10.0)
                        if url_res.status_code == 200:
                            upload_url = url_res.json().get("data", upload_url)
                except Exception as e:
                    logger.warning(f"Failed to get custom VT upload URL: {e}")

                try:
                    with open(file_path, "rb") as f:
                        files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
                        upload_res = await client.post(upload_url, headers=headers, files=files, timeout=60.0)
                    
                    if upload_res.status_code == 200:
                        analysis_data = upload_res.json()
                        analysis_id = analysis_data.get("data", {}).get("id")
                        if analysis_id:
                            # Poll analysis endpoint up to 3 times (10s intervals)
                            poll_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                            for _ in range(3):
                                await asyncio.sleep(10)
                                poll_res = await client.get(poll_url, headers=headers, timeout=10.0)
                                if poll_res.status_code == 200:
                                    status = poll_res.json().get("data", {}).get("attributes", {}).get("status")
                                    if status == "completed":
                                        # Retrieve final report
                                        final_res = await client.get(url, headers=headers, timeout=10.0)
                                        if final_res.status_code == 200:
                                            data = final_res.json()
                                            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                                            malicious = stats.get("malicious", 0)
                                            undetected = stats.get("undetected", 0)
                                            return {
                                                "status": "success",
                                                "malicious": malicious,
                                                "undetected": undetected,
                                                "total": malicious + undetected,
                                                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
                                            }
                                        break
                        
                        return {
                            "status": "processing",
                            "reason": "File uploaded to VirusTotal. Analysis in progress.",
                            "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
                        }
                    else:
                        logger.warning(f"VirusTotal file upload failed with status: {upload_res.status_code}")
                        return {"status": "not_found", "reason": f"File upload failed (HTTP {upload_res.status_code})"}
                except Exception as upload_exc:
                    logger.error(f"VirusTotal file upload crashed: {upload_exc}")
                    return {"status": "not_found", "reason": f"File upload crashed: {str(upload_exc)}"}

            elif response.status_code == 401:
                return {"status": "auth_error", "reason": "Invalid VT API key"}
            elif response.status_code == 429:
                return {"status": "rate_limited", "reason": "VT Free Tier rate limit exceeded"}
            else:
                return {"status": "error", "reason": f"HTTP {response.status_code}"}
    except Exception as e:
        logger.error(f"VT API request failed: {e}")
        return {"status": "error", "reason": str(e)}
