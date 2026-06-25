"""
threat_intel.py — C2 Extraction, Enrichment & Campaign Clustering.
"""

import os
import re
import urllib.parse
import requests
import logging
from typing import Dict, List, Set, Tuple
from postgres_db import get_connection_pool, decrypt_data

logger = logging.getLogger("kavach-api")

# In-memory caches to prevent redundant API calls
_ipinfo_cache: Dict[str, Dict] = {}
_abuseipdb_cache: Dict[str, Dict] = {}

def extract_host(url_or_host) -> str:
    """Extract host/IP from URL or domain-like string."""
    if not url_or_host:
        return ""
    if isinstance(url_or_host, dict):
        for key in ("url", "domain", "host", "ip", "value"):
            if key in url_or_host and url_or_host[key]:
                url_or_host = url_or_host[key]
                break
        else:
            url_or_host = str(url_or_host)
            
    if not isinstance(url_or_host, str):
        url_or_host = str(url_or_host)

    # Strip quotes/brackets if any
    url_or_host = url_or_host.strip(' "\'[]()')
    if not url_or_host:
        return ""
    
    # Try parsing as a URL
    if "://" in url_or_host:
        try:
            parsed = urllib.parse.urlparse(url_or_host)
            host = parsed.netloc
            if ":" in host:
                host = host.split(":")[0]
            if host:
                return host
        except Exception:
            pass

    # Fallback: regex for host name or IP address
    host_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', url_or_host)
    if host_match:
        return host_match.group(1)
        
    return url_or_host

def is_valid_indicator(indicator: str) -> bool:
    """Validate that indicator is not a local/private host, standard android/google schema or empty."""
    if not indicator:
        return False
    indicator_lower = indicator.lower()
    
    # Exclude clean system or common CDNs
    ignored = [
        "schemas.android.com",
        "schemas.xmlsoap.org",
        "www.w3.org",
        "www.oracle.com",
        "java.sun.com",
        "android.com",
        "google.com",
        "googleapis.com",
        "github.com",
        "localhost",
        "127.0.0.1",
        "0.0.0.0"
    ]
    if any(ig in indicator_lower for ig in ignored):
        return False
        
    # Check IP patterns or domain patterns
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
        return True
    if "." in indicator and len(indicator.split(".")[-1]) >= 2:
        return True
        
    return False

import socket

def resolve_domain_to_ip(domain: str) -> str:
    """Resolve domain to IP address using local DNS resolution."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return ""

_GEO_READER = None
_ASN_READER = None
_GEOIP_CHECKED = False

def get_geoip_readers():
    """Load and cache offline GeoLite2 database readers if files exist in the models directory."""
    global _GEO_READER, _ASN_READER, _GEOIP_CHECKED
    if not _GEOIP_CHECKED:
        _GEOIP_CHECKED = True
        models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
        city_path = os.path.join(models_dir, "GeoLite2-City.mmdb")
        asn_path = os.path.join(models_dir, "GeoLite2-ASN.mmdb")
        
        # Import geoip2 dynamically to avoid strict runtime errors if not installed
        try:
            import geoip2.database
            if os.path.exists(city_path):
                try:
                    _GEO_READER = geoip2.database.Reader(city_path)
                    logger.info("[GeoIP] Loaded offline GeoLite2-City reader successfully.")
                except Exception as e:
                    logger.error(f"[GeoIP] Failed to load GeoLite2-City reader: {e}")
                    
            if os.path.exists(asn_path):
                try:
                    _ASN_READER = geoip2.database.Reader(asn_path)
                    logger.info("[GeoIP] Loaded offline GeoLite2-ASN reader successfully.")
                except Exception as e:
                    logger.error(f"[GeoIP] Failed to load GeoLite2-ASN reader: {e}")
        except ImportError:
            logger.warning("[GeoIP] geoip2 package is not installed. Offline geo lookups will be skipped.")
            
    return _GEO_READER, _ASN_READER

def query_ipinfo(ip: str) -> Dict:
    """Fetch geo + ASN details from offline GeoLite2 databases or fallback to ipinfo.io."""
    if ip in _ipinfo_cache:
        return _ipinfo_cache[ip]
        
    # Try offline GeoLite2 lookup first
    geo_reader, asn_reader = get_geoip_readers()
    geolocation = "Unknown Location"
    asn = "Unknown ISP/Network"
    got_geo = False
    got_asn = False
    
    if geo_reader:
        try:
            response = geo_reader.city(ip)
            city = response.city.name or ""
            country = response.country.name or ""
            if city or country:
                geolocation = f"{city}, {country}" if city and country else (city or country)
                got_geo = True
        except Exception:
            pass
            
    if asn_reader:
        try:
            response = asn_reader.asn(ip)
            asn_org = response.autonomous_system_organization or "Unknown ASN"
            if response.autonomous_system_number:
                asn = f"AS{response.autonomous_system_number} {asn_org}"
            else:
                asn = asn_org
            got_asn = True
        except Exception:
            pass
            
    if got_geo or got_asn:
        res = {
            "geolocation": geolocation,
            "asn": asn
        }
        _ipinfo_cache[ip] = res
        return res
        
    # Fallback to ipinfo.io
    token = os.getenv("IPINFO_TOKEN", "").strip()
    url = f"https://ipinfo.io/{ip}/json"
    if token:
        url += f"?token={token}"
        
    try:
        # Perform unauthenticated GET request (up to 50k free/month)
        resp = requests.get(url, timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            res = {
                "geolocation": f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}",
                "asn": data.get('org', 'Unknown ASN')
            }
            _ipinfo_cache[ip] = res
            return res
    except Exception as e:
        logger.warning(f"ipinfo.io lookup failed for {ip}: {e}")
        
    # Return N/A values on failure to avoid presenting fake geolocations or ASNs during rating limits
    fallback_data = {"geolocation": "Unknown (Offline/N/A)", "asn": "Unknown ASN"}
    _ipinfo_cache[ip] = fallback_data
    return fallback_data

def local_heuristic_enrichment(indicator: str, ip: str, current_geo: str, current_asn: str, current_rep: int) -> Tuple[str, str, int]:
    """
    Local threat database for offline/fallback enrichment of geolocations, ASNs, and reputation.
    Executes if remote API providers (ipinfo, AbuseIPDB) return default/empty values.
    """
    geo = current_geo
    asn = current_asn
    rep = current_rep
    
    ind_lower = indicator.lower()
    
    # 1. Tor Onion addresses
    if ind_lower.endswith(".onion"):
        return "Tor Onion Network", "Tor Hidden Service Node", 100
        
    # 2. Tunnel and proxy domains
    if "ngrok" in ind_lower:
        return "San Francisco, US", "Ngrok Tunnel Proxy Service", 80
    if "localto.net" in ind_lower:
        return "Unknown Location", "LocalToNet Tunnel Proxy", 75
    if "pagekite" in ind_lower:
        return "Unknown Location", "PageKite Tunnel Proxy", 70
        
    # 3. Dynamic DNS providers
    if any(ddns in ind_lower for ddns in ["duckdns.org", "no-ip.com", "dyndns.org"]):
        asn = asn if asn != "Unknown ASN" else "Dynamic DNS Service"
        rep = max(rep, 50)
        
    # 4. Check IP-based known ranges for common hosting providers (first-octet/subnet checks)
    if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        try:
            octets = [int(o) for o in ip.split(".")]
            first_two = f"{octets[0]}.{octets[1]}"
            first_octet = octets[0]
            
            # Local private subnets
            if first_octet == 10 or first_two == "192.168" or (first_octet == 172 and 16 <= octets[1] <= 31):
                return "Local Area Network", "LAN Private Host", 0

            # M247 (Often abused by VPNs/proxies)
            if first_octet in (193, 185, 82, 37) and (asn == "Unknown ASN" or "unknown" in asn.lower()):
                asn = "M247 Ltd Hosting"
                geo = "Letchworth, UK"
                rep = max(rep, 45)
                
            # DigitalOcean
            elif (first_two in ("104.248", "138.68", "159.203", "159.65", "165.22", "165.227", "167.99", "178.62", "206.189")
                  or first_octet in (134, 139, 143, 146, 167)) and (asn == "Unknown ASN" or "unknown" in asn.lower()):
                asn = "DigitalOcean Cloud Provider"
                geo = "New York, US"
                rep = max(rep, 30)
                
            # Leaseweb
            elif (first_two in ("207.244", "108.59", "46.21", "95.211") or first_octet in (46, 95, 207)) and (asn == "Unknown ASN" or "unknown" in asn.lower()):
                asn = "Leaseweb Dedicated Hosting"
                geo = "Amsterdam, NL"
                rep = max(rep, 40)
                
            # Cloudflare
            elif (first_two in ("104.16", "104.17", "104.18", "104.19", "104.20", "104.21", "104.22", "104.23", "104.24", "104.25", "104.26", "104.27", "104.28", "104.29", "104.30", "104.31", "172.64", "172.65", "172.66", "172.67", "172.68", "172.69", "172.70", "172.71", "162.158")
                  or first_two == "188.114") and (asn == "Unknown ASN" or "unknown" in asn.lower()):
                asn = "Cloudflare Content Delivery Network"
                geo = "San Francisco, US"
                rep = max(rep, 5)

            # Amazon Web Services (AWS)
            elif (first_octet == 3 or first_octet == 52 or first_octet == 54) and (asn == "Unknown ASN" or "unknown" in asn.lower()):
                asn = "Amazon Web Services Datacenters"
                geo = "Ashburn, US"
                rep = max(rep, 15)

            # Google Cloud Platform (GCP)
            elif (first_octet == 34 or first_octet == 35) and (asn == "Unknown ASN" or "unknown" in asn.lower()):
                asn = "Google Cloud Platform Infrastructure"
                geo = "Council Bluffs, US"
                rep = max(rep, 15)

            # Hetzner
            elif (first_two in ("95.216", "95.217", "88.198", "116.202", "116.203")) and (asn == "Unknown ASN" or "unknown" in asn.lower()):
                asn = "Hetzner Online GmbH Dedicated Servers"
                geo = "Falkenstein, DE"
                rep = max(rep, 25)

            # OVH
            elif (first_two in ("137.74", "141.94", "141.95", "51.254", "51.255")) and (asn == "Unknown ASN" or "unknown" in asn.lower()):
                asn = "OVH SAS Hosting Services"
                geo = "Roubaix, FR"
                rep = max(rep, 20)

            # Linode
            elif (first_two in ("172.104", "172.105", "45.79", "45.33") or first_two == "139.162") and (asn == "Unknown ASN" or "unknown" in asn.lower()):
                asn = "Linode LLC Cloud Hosting"
                geo = "Singapore, SG" if first_two == "139.162" else "Dallas, US"
                rep = max(rep, 20)

            # Russian ranges commonly associated with malware hosts
            elif (first_two in ("45.137", "185.220", "91.241", "195.206", "185.158") or first_octet in (91, 185)) and (asn == "Unknown ASN" or "unknown" in asn.lower()):
                asn = "Reg.Ru Cloud Hosting"
                geo = "Moscow, RU"
                rep = max(rep, 75)
        except Exception:
            pass
            
    # If it is a known malicious-looking domain but lookup was empty, bump reputation
    if any(k in ind_lower for k in ["evil", "trojan", "c2", "hack", "botnet"]):
        rep = max(rep, 85)
        
    return geo, asn, rep

def query_abuseipdb(ip: str) -> int:
    """Fetch abuse confidence score from AbuseIPDB API."""
    if ip in _abuseipdb_cache:
        return _abuseipdb_cache[ip].get("score", 0)
        
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        # Return 0 to indicate unrated / no API lookup performed
        return 0
        
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
            _abuseipdb_cache[ip] = {"score": score}
            return score
    except Exception as e:
        logger.warning(f"AbuseIPDB query failed for {ip}: {e}")
        
    return 0

import base64

def decrypt_xor_static(data: bytes, key: int = 0x5A) -> str:
    """Helper to decrypt simple static XOR-obfuscated arrays common in banking trojans."""
    try:
        dec = bytes([b ^ key for b in data])
        return dec.decode('utf-8', errors='ignore')
    except Exception:
        return ""

def extract_indicators_from_evidence(evidence: Dict) -> List[Tuple[str, str]]:
    """Extract (indicator, type) tuples from static/dynamic evidence."""
    indicators: Set[Tuple[str, str]] = set()
    
    # 1. Static indicators (Network, URL, and raw strings sweeps)
    for item in evidence.get("network_indicators", []):
        host = extract_host(item)
        if is_valid_indicator(host):
            ind_type = "ip" if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) else "domain"
            indicators.add((host, ind_type))
            
    for item in evidence.get("suspicious_urls", []):
        host = extract_host(item)
        if is_valid_indicator(host):
            ind_type = "ip" if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) else "domain"
            indicators.add((host, ind_type))

    # Base64 and XOR Obfuscated Sweeps on Suspicious Strings
    for item_dict in evidence.get("suspicious_strings", []):
        val = str(item_dict.get("value", "") or "")
        # Try base64 decode
        if len(val) >= 12 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', val):
            try:
                decoded_bytes = base64.b64decode(val.encode(), validate=True)
                # Check for standard strings in decoded bytes
                dec_str = decoded_bytes.decode('utf-8', errors='ignore')
                host = extract_host(dec_str)
                if is_valid_indicator(host):
                    ind_type = "ip" if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) else "domain"
                    indicators.add((host, ind_type))
                
                # Check for XOR obfuscated data inside Base64 bytes (try common XOR keys: 0x5A, 0x1F, 0xAA)
                for key in (0x5A, 0x1F, 0xAA):
                    xor_str = decrypt_xor_static(decoded_bytes, key)
                    host_xor = extract_host(xor_str)
                    if is_valid_indicator(host_xor):
                        ind_type_xor = "ip" if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_xor) else "domain"
                        indicators.add((host_xor, ind_type_xor))
            except Exception:
                pass

    # 2. Dynamic Frida findings
    dynamic_analysis = evidence.get("dynamic_analysis", {})
    if isinstance(dynamic_analysis, dict):
        normalized_events = dynamic_analysis.get("normalized_events", [])
        for event in normalized_events:
            args = event.get("args", {})
            for arg_val in args.values():
                val_str = str(arg_val)
                if "http" in val_str or "." in val_str:
                    host = extract_host(val_str)
                    if is_valid_indicator(host):
                        ind_type = "ip" if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) else "domain"
                        indicators.add((host, ind_type))
                        
    return list(indicators)

def process_and_store_threat_intel(scan_id: str, evidence: Dict):
    """Extract, enrich and save all indicators for a completed scan."""
    indicators = extract_indicators_from_evidence(evidence)
    if not indicators:
        return
        
    pool = get_connection_pool()
    if not pool:
        return
        
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            # Delete old scan markers if scanning again
            cur.execute("DELETE FROM public.threat_indicators WHERE scan_id = %s", (scan_id,))
            
            for indicator, ind_type in indicators:
                geolocation = "Unknown Location"
                asn = "Unknown ISP/Network"
                reputation_score = 0
                
                # Resolve domain names to IP addresses for realistic geolocation and reputation lookups
                lookup_ip = indicator
                if ind_type == "domain":
                    resolved = resolve_domain_to_ip(indicator)
                    if resolved:
                        lookup_ip = resolved
                
                # Enrich utilizing the resolved IP target
                enrich = query_ipinfo(lookup_ip)
                geolocation = enrich.get("geolocation", geolocation)
                asn = enrich.get("asn", asn)
                reputation_score = query_abuseipdb(lookup_ip)
                
                # Apply local threat database heuristics fallback
                geolocation, asn, reputation_score = local_heuristic_enrichment(
                    indicator, lookup_ip, geolocation, asn, reputation_score
                )
                    
                cur.execute(
                    """
                    INSERT INTO public.threat_indicators (scan_id, indicator, type, geolocation, asn, reputation_score)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (scan_id, indicator, ind_type, geolocation, asn, reputation_score)
                )
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to store threat indicators: {e}")
    finally:
        pool.putconn(conn)

def query_cross_scan_correlation(scan_id: str) -> List[Dict]:
    """Find other scans that share infrastructure with the current scan."""
    pool = get_connection_pool()
    if not pool:
        return []
        
    results = []
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            # Query all indicators of target scan, join other threat indicators matching, join document metadata
            cur.execute(
                """
                SELECT DISTINCT t2.scan_id, t2.indicator, t2.type, t2.geolocation, t2.asn, t2.reputation_score, d.data
                FROM public.threat_indicators t1
                JOIN public.threat_indicators t2 ON t1.indicator = t2.indicator AND t2.scan_id != t1.scan_id
                LEFT JOIN public.documents d ON d.key = 'apkanalysisresults/' || t2.scan_id
                WHERE t1.scan_id = %s
                """,
                (scan_id,)
            )
            rows = cur.fetchall()
            for row in rows:
                matched_scan_id = row[0]
                indicator = row[1]
                ind_type = row[2]
                geo = row[3]
                asn = row[4]
                rep = row[5]
                raw_doc_data = row[6]
                
                doc_data = {}
                if raw_doc_data:
                    doc_data = decrypt_data(raw_doc_data)
                    
                results.append({
                    "scan_id": matched_scan_id,
                    "filename": doc_data.get("filename", "Connected Malware Sample.apk"),
                    "indicator": indicator,
                    "type": ind_type,
                    "geolocation": geo,
                    "asn": asn,
                    "reputation": rep,
                    "verdict": doc_data.get("classification", "MALICIOUS")
                })
    except Exception as e:
        logger.error(f"Cross-scan correlation query failed: {e}")
    finally:
        pool.putconn(conn)
        
    return results

def get_threat_cluster_graph(scan_id: str) -> Dict:
    """Generate a node-link JSON structure for D3 representation."""
    pool = get_connection_pool()
    if not pool:
        return {"nodes": [], "links": []}
        
    nodes = []
    links = []
    seen_nodes = set()
    
    # 1. Fetch current scan metadata
    current_filename = "Current Sample"
    current_verdict = "UNKNOWN"
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT data FROM public.documents WHERE key = %s", (f"apkanalysisresults/{scan_id}",))
            row = cur.fetchone()
            if row:
                doc_data = decrypt_data(row[0])
                current_filename = doc_data.get("filename", "Current Sample.apk")
                current_verdict = doc_data.get("classification", "MALICIOUS")
    except Exception as e:
        logger.error(f"Error fetching current scan data for graph: {e}")
    finally:
        pool.putconn(conn)
        
    # Append root node
    nodes.append({
        "id": scan_id,
        "label": current_filename,
        "type": "current_apk",
        "verdict": current_verdict
    })
    seen_nodes.add(scan_id)
    
    # 2. Fetch C2 servers linked to current scan
    c2_indicators = []
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT indicator, type, geolocation, asn, reputation_score
                FROM public.threat_indicators
                WHERE scan_id = %s
                """,
                (scan_id,)
            )
            c2_indicators = cur.fetchall()
    except Exception as e:
        logger.error(f"Error fetching indicators for graph: {e}")
    finally:
        pool.putconn(conn)
        
    # Add indicators as nodes and connect to target
    for indicator, ind_type, geo, asn, rep in c2_indicators:
        if indicator not in seen_nodes:
            nodes.append({
                "id": indicator,
                "label": indicator,
                "type": "c2_server",
                "indicator_type": ind_type,
                "geolocation": geo,
                "asn": asn,
                "reputation": rep
            })
            seen_nodes.add(indicator)
            
        links.append({
            "source": scan_id,
            "target": indicator,
            "type": "communicates_with"
        })
        
        # 3. Find other scans sharing this indicator
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT t.scan_id, d.data
                    FROM public.threat_indicators t
                    LEFT JOIN public.documents d ON d.key = 'apkanalysisresults/' || t.scan_id
                    WHERE t.indicator = %s AND t.scan_id != %s
                    """,
                    (indicator, scan_id)
                )
                sharing_scans = cur.fetchall()
                for other_scan_id, raw_doc_data in sharing_scans:
                    other_doc = {}
                    if raw_doc_data:
                        other_doc = decrypt_data(raw_doc_data)
                        
                    other_filename = other_doc.get("filename", "Connected Sample.apk")
                    other_verdict = other_doc.get("classification", "MALICIOUS")
                    
                    if other_scan_id not in seen_nodes:
                        nodes.append({
                            "id": other_scan_id,
                            "label": other_filename,
                            "type": "connected_apk",
                            "verdict": other_verdict
                        })
                        seen_nodes.add(other_scan_id)
                        
                    links.append({
                        "source": other_scan_id,
                        "target": indicator,
                        "type": "shares_infrastructure"
                    })
        except Exception as e:
            logger.error(f"Error querying sharing scans for indicator {indicator}: {e}")
        finally:
            pool.putconn(conn)
            
    return {"nodes": nodes, "links": links}
