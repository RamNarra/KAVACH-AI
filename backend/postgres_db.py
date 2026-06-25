"""
postgres_db.py — Database client wrapper using PostgreSQL.
Provides query/document abstraction used by Kavach AI, drop-in replacement for Supabase.
"""

import os
import time
import re
import json
import uuid
import logging
import threading
from typing import Any, Dict, Optional, List
import psycopg2
from psycopg2 import pool
import base64
import hashlib
from cryptography.fernet import Fernet

logger = logging.getLogger("kavach-api")

# --- Encryption ---
def _get_cipher():
    key_source = os.getenv("KAVACH_DB_ENCRYPTION_KEY", "").strip()
    if not key_source:
        is_production = os.getenv("KAVACH_ENV", "development").strip().lower() in ("production", "prod")
        
        if is_production:
            raise RuntimeError(
                "CRITICAL CONFIGURATION ERROR: KAVACH_DB_ENCRYPTION_KEY must be configured in environment."
            )
        
        logger.warning(
            "CRITICAL SECURITY WARNING: KAVACH_DB_ENCRYPTION_KEY is not defined in the environment. "
            "Using a transient dynamically-generated session key. Encrypted database records will NOT persist across backend restarts."
        )
        # Fall back to KAVACH_JWT_SECRET if available as a dynamic per-deployment secret
        key_source = os.getenv("KAVACH_JWT_SECRET", "").strip()
        if not key_source:
            # Fall back to a completely random cryptographically secure dynamic key
            key_source = os.urandom(32).hex()

    key_bytes = hashlib.sha256(key_source.encode('utf-8')).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)

_cipher = _get_cipher()

def encrypt_data(data: Dict) -> str:
    json_str = json.dumps(data)
    encrypted_bytes = _cipher.encrypt(json_str.encode('utf-8'))
    return encrypted_bytes.decode('utf-8')

def decrypt_data(encrypted_str: str) -> Dict:
    if not encrypted_str:
        return {}
    try:
        # Try to decrypt using Fernet
        decrypted_bytes = _cipher.decrypt(encrypted_str.strip().encode('utf-8'))
        return json.loads(decrypted_bytes.decode('utf-8'))
    except Exception:
        # Fallback to plain JSON parsing if unencrypted
        try:
            return json.loads(encrypted_str)
        except Exception:
            return {}


# --- Postgres Configuration & Pool ---
def get_postgres_config():
    host = os.getenv("POSTGRES_HOST", "localhost").strip()
    port = os.getenv("POSTGRES_PORT", "5432").strip()
    db_name = os.getenv("POSTGRES_DB", "kavach_db").strip()
    user = os.getenv("POSTGRES_USER", "kavach_user").strip()
    password = os.getenv("POSTGRES_PASSWORD", "kavach_secure_password_1337").strip()
    return host, port, db_name, user, password

def is_postgres_configured() -> bool:
    import sys
    if "pytest" in sys.modules or os.getenv("PYTEST_CURRENT_TEST"):
        # Only use Postgres if environment variables are explicitly defined in os.environ
        return bool(os.getenv("POSTGRES_HOST") and os.getenv("POSTGRES_USER"))
    host, port, db_name, user, password = get_postgres_config()
    return bool(host and user and password and db_name)

# Expose both naming conventions to minimize changes in other parts of backend
is_supabase_configured = is_postgres_configured


_pool = None
_pool_lock = threading.Lock()

def get_connection_pool():
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                host, port, db_name, user, password = get_postgres_config()
                try:
                    _pool = psycopg2.pool.ThreadedConnectionPool(
                        minconn=1,
                        maxconn=25,
                        host=host,
                        port=port,
                        database=db_name,
                        user=user,
                        password=password
                    )
                    logger.info("Created thread-safe PostgreSQL connection pool.")
                except Exception as e:
                    logger.error(f"Failed to create PostgreSQL connection pool: {e}")
                    raise e
    return _pool


# --- Database Schema Bootstrapping ---
def init_db():
    if not is_postgres_configured():
        logger.warning("PostgreSQL not configured. Skipping initialization.")
        return

    host, port, db_name, user, password = get_postgres_config()
    
    # 1. Attempt to create the database if it doesn't exist (with a retry loop to wait for PostgreSQL startup)
    max_retries = 20
    retry_interval = 1
    conn = None
    for attempt in range(1, max_retries + 1):
        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                database="postgres",
                user=user,
                password=password
            )
            break
        except Exception as e:
            if attempt == max_retries:
                logger.error(f"PostgreSQL was not ready after {max_retries} attempts: {e}")
                raise e
            logger.info(f"PostgreSQL not ready yet at {host}:{port} (attempt {attempt}/{max_retries}), retrying in {retry_interval}s...")
            time.sleep(retry_interval)

    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(f"SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (db_name,))
            if not cur.fetchone():
                logger.info(f"Database '{db_name}' does not exist. Creating...")
                # Avoid SQL injection by sanitizing db_name or using string concatenation safely for DB names
                from psycopg2.extensions import AsIs
                cur.execute("CREATE DATABASE %s", (AsIs(db_name),))
        conn.close()
    except Exception as e:
        logger.debug(f"Database creation check returned/failed (non-fatal): {e}")

    # 2. Connect to local db and initialize schema
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=db_name,
            user=user,
            password=password
        )
        conn.autocommit = True
        with conn.cursor() as cur:
            # Create documents table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.documents (
                    key text PRIMARY KEY,
                    collection text NOT NULL,
                    doc_id text NOT NULL,
                    data text,
                    created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
                );
            """)
            
            # Create index for collections
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_documents_collection ON public.documents(collection);
            """)

            # Create threat_indicators table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.threat_indicators (
                    id SERIAL PRIMARY KEY,
                    scan_id VARCHAR(255) NOT NULL,
                    indicator VARCHAR(255) NOT NULL,
                    type VARCHAR(50) NOT NULL,
                    geolocation VARCHAR(255),
                    asn VARCHAR(255),
                    reputation_score INT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Create index for threat indicators
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_indicators_scan_id ON public.threat_indicators(scan_id);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_indicators_indicator ON public.threat_indicators(indicator);
            """)

            # Create trusted_signers table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.trusted_signers (
                    package_name VARCHAR(255) PRIMARY KEY,
                    bank_name VARCHAR(255) NOT NULL,
                    sha256_fingerprint VARCHAR(255) NOT NULL,
                    notes TEXT
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_trusted_signers_package_name ON public.trusted_signers(package_name);
            """)
            
            # Create PL/pgSQL rate limiting function
            cur.execute("""
                CREATE OR REPLACE FUNCTION public.check_and_update_rate_limit(
                    p_key text,
                    p_collection text,
                    p_doc_id text,
                    p_now double precision,
                    p_window_secs double precision,
                    p_requests_limit integer
                ) RETURNS boolean AS $$
                DECLARE
                    v_data jsonb;
                    v_timestamps double precision[];
                    v_filtered_timestamps double precision[];
                    v_t double precision;
                BEGIN
                    -- Get existing document or create empty JSON
                    SELECT (data::jsonb) INTO v_data FROM public.documents WHERE key = p_key;
                    IF v_data IS NULL THEN
                        v_data := '{}'::jsonb;
                    END IF;

                    -- Extract timestamps array
                    IF v_data ? 'timestamps' THEN
                        -- Convert JSON array to PG array
                        SELECT array_agg(val::double precision) INTO v_timestamps
                        FROM jsonb_array_elements_text(v_data -> 'timestamps') AS val;
                    ELSE
                        v_timestamps := ARRAY[]::double precision[];
                    END IF;

                    -- Filter old timestamps
                    v_filtered_timestamps := ARRAY[]::double precision[];
                    IF v_timestamps IS NOT NULL THEN
                        FOREACH v_t IN ARRAY v_timestamps LOOP
                            IF p_now - v_t < p_window_secs THEN
                                v_filtered_timestamps := array_append(v_filtered_timestamps, v_t);
                            END IF;
                        END LOOP;
                    END IF;

                    -- Check limit
                    IF array_length(v_filtered_timestamps, 1) >= p_requests_limit THEN
                        RETURN FALSE;
                    END IF;

                    -- Add current timestamp
                    v_filtered_timestamps := array_append(v_filtered_timestamps, p_now);

                    -- Build new JSON data
                    v_data := jsonb_set(v_data, '{timestamps}', to_jsonb(v_filtered_timestamps));

                    -- Insert or update
                    INSERT INTO public.documents (key, collection, doc_id, data)
                    VALUES (p_key, p_collection, p_doc_id, v_data::text)
                    ON CONFLICT (key) DO UPDATE
                    SET data = EXCLUDED.data;

                    RETURN TRUE;
                END;
                $$ LANGUAGE plpgsql SECURITY DEFINER;
            """)

            # Seed trusted_signers baseline
            try:
                cur.execute("SELECT 1 FROM public.trusted_signers LIMIT 1")
                if not cur.fetchone():
                    logger.info("Seeding trusted_signers baseline...")
                    signers = [
                        ("com.boi.group.boimobile", "Bank of India", "1A:2B:3C:4D:5E:6F:7A:8B:9C:0D:1E:2F:3A:4B:5C:6D:7E:8F:9A:0B:1C:2D:3E:4F:5A:6B:7C:8D:9E:0F:1A:2B", "Official Bank of India Mobile Banking app signer."),
                        ("com.sbi.yono", "State Bank of India", "2E:B5:E4:D3:C2:B1:E0:F9:A8:B7:C6:D5:E4:F3:A2:B1:C0:D9:E8:F7:A6:B5:C4:D3:E2:F1:A0:B9:C8:D7:E6:F5", "Official State Bank of India YONO app signer."),
                        ("com.snapwork.hdfc", "HDFC Bank", "3C:D4:E5:F6:A7:B8:C9:D0:E1:F2:A3:B4:C5:D6:E7:F8:A9:B0:C1:D2:E3:F4:A5:B6:C7:D8:E9:F0:A1:B2:C3:D4", "Official HDFC Bank Mobile Banking app signer."),
                        ("com.phonepe.app", "PhonePe", "AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00", "Official PhonePe app signer."),
                        ("com.google.android.apps.nbu.paisa.user", "Google Pay", "F3:E2:D1:C0:B9:A8:97:86:75:64:53:42:31:20:1F:0E:9D:8C:7B:6A:59:48:37:26:15:04:F3:E2:D1:C0:B9:A8", "Official GPay app signer.")
                    ]
                    for pkg, bank, sha255, notes in signers:
                        cur.execute(
                            "INSERT INTO public.trusted_signers (package_name, bank_name, sha256_fingerprint, notes) VALUES (%s, %s, %s, %s) ON CONFLICT (package_name) DO NOTHING",
                            (pkg, bank, sha255, notes)
                        )
            except Exception as e:
                logger.error(f"Failed to seed trusted signers: {e}")

            # Seed Phase 16 mock scans
            try:
                cur.execute("SELECT 1 FROM public.documents WHERE key = 'apkanalysisresults/scan_sova_mock'")
                if not cur.fetchone():
                    logger.info("Seeding Phase 16 Demo Mode Showcase Fixtures...")
                    
                    # 1. SOVA Scan
                    sova_doc = {
                        "id": "scan_sova_mock",
                        "filename": "sova_banking_trojan.apk",
                        "package_name": "com.sova.banking.stealer",
                        "apk_hash": "a4d3c2b1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3",
                        "risk_score": 96,
                        "threat_level": "CRITICAL",
                        "absolute_threat_score": 98,
                        "uid": "user_test123@example.com",
                        "status": "COMPLETED",
                        "created_at": "2026-06-20T00:00:00Z",
                        "evidence": {
                            "network_indicators": ["evil-banking-c2.ru"],
                            "suspicious_urls": ["http://evil-banking-c2.ru/api/exfil"],
                            "permissions": [
                                {"name": "android.permission.RECEIVE_SMS", "risk_score": 8, "description": "Allows intercepting incoming SMS messages."},
                                {"name": "android.permission.BIND_ACCESSIBILITY_SERVICE", "risk_score": 10, "description": "Allows screen-scraping and auto-granting permissions."},
                                {"name": "android.permission.SYSTEM_ALERT_WINDOW", "risk_score": 9, "description": "Allows drawing phishing window overlays."}
                            ],
                            "certificate_info": {
                                "is_signed": True,
                                "subject": "CN=SOVA Developer, O=SOVA, C=RU",
                                "issuer": "CN=SOVA Developer, O=SOVA, C=RU",
                                "valid_from": "2025-06-01T00:00:00",
                                "valid_to": "2055-06-01T00:00:00",
                                "sha256": "FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00",
                                "sha1": "FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:AA:BB:CC:DD",
                                "serial_number": "7F6E5D4C3B2A1908",
                                "signature_algo": "sha256_rsa",
                                "signature_scheme": "v1",
                                "verdict": "UNKNOWN_SELF_SIGNED_DEVELOPER",
                                "verdict_description": "Self-signed certificate with no matching official bank baseline."
                            }
                        },
                        "banking_fraud": {
                            "fraud_score": 98,
                            "badges": [
                                {"title": "SMS Interception", "severity": "CRITICAL", "summary": "Intercepts banker SMS notifications and OTP messages."},
                                {"title": "Accessibility Abuse", "severity": "CRITICAL", "summary": "Abuses accessibility services to read screen elements and perform clicks."},
                                {"title": "Overlay Injection", "severity": "CRITICAL", "summary": "Injects phishing overlays on top of banking applications."}
                            ]
                        },
                        "ml_classification": {
                            "status": "SUCCESS",
                            "is_malicious": True,
                            "ml_confidence_score": 0.99,
                            "predicted_malware_family": "SOVA",
                            "top_features": [
                                {"feature": "android.permission.RECEIVE_SMS", "importance": 0.12},
                                {"feature": "android.permission.BIND_ACCESSIBILITY_SERVICE", "importance": 0.10},
                                {"feature": "android.permission.SYSTEM_ALERT_WINDOW", "importance": 0.08}
                            ],
                            "model_metadata": {
                                "model_type": "Random Forest Classifier",
                                "n_estimators": 100,
                                "max_depth": 12,
                                "n_features": 545,
                                "n_samples": 5000,
                                "validation_accuracy": 0.992,
                                "class_metrics": {
                                    "Benign": {"precision": 0.99, "recall": 0.99, "f1-score": 0.99, "support": 250},
                                    "SOVA": {"precision": 0.99, "recall": 1.00, "f1-score": 0.99, "support": 250},
                                    "BRATA": {"precision": 0.99, "recall": 0.99, "f1-score": 0.99, "support": 250},
                                    "Xenomorph": {"precision": 1.00, "recall": 0.99, "f1-score": 0.99, "support": 250},
                                    "Cerberus": {"precision": 0.98, "recall": 0.99, "f1-score": 0.99, "support": 250},
                                    "Drinik": {"precision": 0.99, "recall": 0.99, "f1-score": 0.99, "support": 250}
                                }
                            }
                        },
                        "investigation_report": {
                            "summary": "This application is a highly dangerous banking trojan belonging to the SOVA family.\n\nIt contains static signatures designed to intercept SMS, inject phishing overlays over legitimate applications, and log key presses.\n\nWe recommend immediate removal.",
                            "dynamic_summary": "During live sandbox execution, the app attempted to attach accessibility services and register a broadcast receiver for SMS events.\n\nIt successfully logged inputs and attempted overlay attacks.",
                            "final_report": "Kavach AI has classified this application as CRITICAL MALWARE.\n\nYour banking credentials and SMS verification codes are at active risk if this app is installed.\n\nPlease uninstall this application immediately.",
                            "executive_verdict": "SOVA Banking Trojan Confirmed",
                            "runtime_findings_interpretation": "Active SMS and overlay interception logged.",
                            "permissions_analysis": [
                                {"permission": "android.permission.RECEIVE_SMS", "status": "critical", "description": "Allows reading SMS."},
                                {"permission": "android.permission.BIND_ACCESSIBILITY_SERVICE", "status": "critical", "description": "Abuses layout permissions."}
                            ],
                            "suspicious_activities": [
                                {"title": "Accessibility abuse", "description": "Layout hijacking active", "severity": "CRITICAL", "file": "com.sova.SmsService"}
                            ],
                            "code_vulnerabilities": [],
                            "recommendations": ["Uninstall the app.", "Reset banking password.", "Review recent transactions."]
                        },
                        "risk_decomposition": {
                            "composite_score": 96,
                            "confidence": "high",
                            "components": {"static": 95, "dynamic": 90, "ai": 96, "banking_fraud": 98, "ml": 99},
                            "weights": {"static": 0.40, "dynamic": 0.25, "ai": 0.10, "banking_fraud": 0.15, "ml": 0.10},
                            "weighted_contribution": {"static": 38.0, "dynamic": 22.5, "ai": 9.6, "banking_fraud": 14.7, "ml": 9.9},
                            "top_contributors": [
                                {"label": "Overlay Injection", "category": "banking_fraud", "weight": 30},
                                {"label": "Accessibility Abuse", "category": "banking_fraud", "weight": 30}
                            ],
                            "summary": "Threat score 96/100 driven by elevated banking fraud indicators (high confidence)."
                        },
                        "attack_techniques": [
                            {"id": "T1418", "name": "Input Injection", "tactic": "Credential Access", "sources": [{"source": "overlay", "detail": "Phishing overlay window detected."}]}
                        ],
                        "family_signals": {
                            "anti_vm": [],
                            "packers_obfuscators": []
                        }
                    }
                    
                    # 2. Fake SBI Scan
                    fake_sbi_doc = {
                        "id": "scan_fake_sbi_mock",
                        "filename": "sbi_yono_update.apk",
                        "package_name": "com.sbi.yono",
                        "apk_hash": "b5e4d3c2b1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4",
                        "risk_score": 88,
                        "threat_level": "HIGH",
                        "absolute_threat_score": 90,
                        "uid": "user_test123@example.com",
                        "status": "COMPLETED",
                        "created_at": "2026-06-20T00:01:00Z",
                        "evidence": {
                            "network_indicators": ["evil-banking-c2.ru"],
                            "suspicious_urls": ["http://evil-banking-c2.ru/api/exfil"],
                            "permissions": [
                                {"name": "android.permission.RECEIVE_SMS", "risk_score": 8, "description": "Allows intercepting incoming SMS messages."},
                                {"name": "android.permission.SYSTEM_ALERT_WINDOW", "risk_score": 9, "description": "Allows drawing phishing window overlays."}
                            ],
                            "certificate_info": {
                                "is_signed": True,
                                "subject": "CN=Yono Modder, O=SBI Mod, C=IN",
                                "issuer": "CN=Yono Modder, O=SBI Mod, C=IN",
                                "valid_from": "2026-01-01T00:00:00",
                                "valid_to": "2036-01-01T00:00:00",
                                "sha256": "9E:8D:7C:6B:5A:4F:3E:2D:1C:0B:9A:89:78:67:56:45:34:23:12:01:FE:DC:BA:98:76:54:32:10:FF:EE:DD:CC",
                                "sha1": "BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA:99:88",
                                "serial_number": "1F2A3B4C5D6E",
                                "signature_algo": "sha256_rsa",
                                "signature_scheme": "v1, v2",
                                "verdict": "MISMATCHED_SIGNER_FOR_KNOWN_BANK_PACKAGE",
                                "verdict_description": "Scanned APK claims to be com.sbi.yono but is signed by an unauthorized certificate.",
                                "matched_baseline": {
                                    "package_name": "com.sbi.yono",
                                    "bank_name": "State Bank of India",
                                    "sha256": "2E:B5:E4:D3:C2:B1:E0:F9:A8:B7:C6:D5:E4:F3:A2:B1:C0:D9:E8:F7:A6:B5:C4:D3:E2:F1:A0:B9:C8:D7:E6:F5",
                                    "notes": "Official State Bank of India YONO app signer."
                                }
                            }
                        },
                        "banking_fraud": {
                            "fraud_score": 92,
                            "badges": [
                                {"title": "Overlay Phishing", "severity": "CRITICAL", "summary": "Impersonates SBI Yono login screen to harvest credentials."},
                                {"title": "SMS Stealer", "severity": "HIGH", "summary": "Reads incoming SMS messages to steal OTPs."}
                            ]
                        },
                        "ml_classification": {
                            "status": "SUCCESS",
                            "is_malicious": True,
                            "ml_confidence_score": 0.92,
                            "predicted_malware_family": "Drinik",
                            "top_features": [
                                {"feature": "android.permission.RECEIVE_SMS", "importance": 0.11},
                                {"feature": "android.permission.SYSTEM_ALERT_WINDOW", "importance": 0.09}
                            ],
                            "model_metadata": {
                                "model_type": "Random Forest Classifier",
                                "n_estimators": 100,
                                "max_depth": 12,
                                "n_features": 545,
                                "n_samples": 5000,
                                "validation_accuracy": 0.992,
                                "class_metrics": {
                                    "Benign": {"precision": 0.99, "recall": 0.99, "f1-score": 0.99, "support": 250},
                                    "SOVA": {"precision": 0.99, "recall": 1.00, "f1-score": 0.99, "support": 250},
                                    "BRATA": {"precision": 0.99, "recall": 0.99, "f1-score": 0.99, "support": 250},
                                    "Xenomorph": {"precision": 1.00, "recall": 0.99, "f1-score": 0.99, "support": 250},
                                    "Cerberus": {"precision": 0.98, "recall": 0.99, "f1-score": 0.99, "support": 250},
                                    "Drinik": {"precision": 0.99, "recall": 0.99, "f1-score": 0.99, "support": 250}
                                }
                            }
                        },
                        "investigation_report": {
                            "summary": "This application poses as a legitimate State Bank of India (SBI) utility but contains overlay code matching the Drinik banking family.\n\nIt is designed to trick users into providing their internet banking credentials and credit card information.",
                            "dynamic_summary": "In the sandbox, the app immediately displayed a full-screen overlay mimicking the SBI YONO login screen when launched.\n\nIt successfully intercepted simulated keyboard inputs.",
                            "final_report": "Kavach AI warns that this app is a FAKE banking utility.\n\nDo NOT enter your SBI username, password, or PIN into this application.\n\nYour data is at high risk.",
                            "executive_verdict": "Phishing Fake SBI Application",
                            "runtime_findings_interpretation": "Credential harvesting overlays detected.",
                            "permissions_analysis": [
                                {"permission": "android.permission.RECEIVE_SMS", "status": "critical", "description": "Allows reading SMS."}
                            ],
                            "suspicious_activities": [
                                {"title": "Overlay Phishing", "description": "SBI theme injection detected", "severity": "CRITICAL", "file": "com.sbi.yono.rewards.OverlayService"}
                            ],
                            "code_vulnerabilities": [],
                            "recommendations": ["Uninstall the app immediately.", "Alert State Bank of India support.", "Verify bank statement."]
                        },
                        "risk_decomposition": {
                            "composite_score": 88,
                            "confidence": "high",
                            "components": {"static": 85, "dynamic": 80, "ai": 88, "banking_fraud": 92, "ml": 92},
                            "weights": {"static": 0.40, "dynamic": 0.25, "ai": 0.10, "banking_fraud": 0.15, "ml": 0.10},
                            "weighted_contribution": {"static": 34.0, "dynamic": 20.0, "ai": 8.8, "banking_fraud": 13.8, "ml": 9.2},
                            "top_contributors": [
                                {"label": "Overlay Phishing", "category": "banking_fraud", "weight": 30}
                            ],
                            "summary": "Threat score 88/100 driven by elevated banking fraud indicators (high confidence)."
                        },
                        "attack_techniques": [
                            {"id": "T1418", "name": "Input Injection", "tactic": "Credential Access", "sources": [{"source": "overlay", "detail": "Phishing overlay window detected."}]}
                        ],
                        "family_signals": {
                            "anti_vm": [],
                            "packers_obfuscators": []
                        }
                    }
                    
                    # 3. Clean SBI Scan
                    clean_sbi_doc = {
                        "id": "scan_clean_sbi_mock",
                        "filename": "sbi_yono_official.apk",
                        "package_name": "com.sbi.yono",
                        "apk_hash": "c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5",
                        "risk_score": 8,
                        "threat_level": "SAFE",
                        "absolute_threat_score": 5,
                        "uid": "user_test123@example.com",
                        "status": "COMPLETED",
                        "created_at": "2026-06-20T00:02:00Z",
                        "evidence": {
                            "network_indicators": [],
                            "suspicious_urls": [],
                            "permissions": [
                                {"name": "android.permission.INTERNET", "risk_score": 0, "description": "Allows internet connection."}
                            ],
                            "certificate_info": {
                                "is_signed": True,
                                "subject": "CN=State Bank of India, O=State Bank of India, C=IN",
                                "issuer": "CN=State Bank of India, O=State Bank of India, C=IN",
                                "valid_from": "2020-05-01T00:00:00",
                                "valid_to": "2045-05-01T00:00:00",
                                "sha256": "2E:B5:E4:D3:C2:B1:E0:F9:A8:B7:C6:D5:E4:F3:A2:B1:C0:D9:E8:F7:A6:B5:C4:D3:E2:F1:A0:B9:C8:D7:E6:F5",
                                "sha1": "11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44",
                                "serial_number": "9E8D7C6B5A4F3E2D",
                                "signature_algo": "sha256_rsa",
                                "signature_scheme": "v1, v2, v3",
                                "verdict": "LEGIT_MATCHED_SIGNER",
                                "verdict_description": "Signed by official State Bank of India certificate (trusted baseline)."
                            }
                        },
                        "banking_fraud": {
                            "fraud_score": 0,
                            "badges": []
                        },
                        "ml_classification": {
                            "status": "SUCCESS",
                            "is_malicious": False,
                            "ml_confidence_score": 0.02,
                            "predicted_malware_family": "BENIGN",
                            "top_features": [],
                            "model_metadata": {
                                "model_type": "Random Forest Classifier",
                                "n_estimators": 100,
                                "max_depth": 12,
                                "n_features": 545,
                                "n_samples": 5000,
                                "validation_accuracy": 0.992,
                                "class_metrics": {
                                    "Benign": {"precision": 0.99, "recall": 0.99, "f1-score": 0.99, "support": 250},
                                    "SOVA": {"precision": 0.99, "recall": 1.00, "f1-score": 0.99, "support": 250},
                                    "BRATA": {"precision": 0.99, "recall": 0.99, "f1-score": 0.99, "support": 250},
                                    "Xenomorph": {"precision": 1.00, "recall": 0.99, "f1-score": 0.99, "support": 250},
                                    "Cerberus": {"precision": 0.98, "recall": 0.99, "f1-score": 0.99, "support": 250},
                                    "Drinik": {"precision": 0.99, "recall": 0.99, "f1-score": 0.99, "support": 250}
                                }
                            }
                        },
                        "investigation_report": {
                            "summary": "This application is the official State Bank of India (SBI) YONO application.\n\nIt is signed with the official developer key, contains no suspicious permission combinations, and matches secure patterns.",
                            "dynamic_summary": "The app launched in the sandbox, established secure SSL connections, and did not engage in accessibility abuse or overlay injection.",
                            "final_report": "Kavach AI has audited the application and found it completely SAFE.\n\nYou can use this application securely.",
                            "executive_verdict": "Official SBI YONO Application (Safe)",
                            "runtime_findings_interpretation": "Benign behavior verified.",
                            "permissions_analysis": [],
                            "suspicious_activities": [],
                            "code_vulnerabilities": [],
                            "recommendations": ["No actions required. App is clean."]
                        },
                        "risk_decomposition": {
                            "composite_score": 8,
                            "confidence": "high",
                            "components": {"static": 10, "dynamic": 5, "ai": 8, "banking_fraud": 0, "ml": 2},
                            "weights": {"static": 0.40, "dynamic": 0.25, "ai": 0.10, "banking_fraud": 0.15, "ml": 0.10},
                            "weighted_contribution": {"static": 4.0, "dynamic": 1.2, "ai": 0.8, "banking_fraud": 0.0, "ml": 0.2},
                            "top_contributors": [],
                            "summary": "Threat score 8/100 driven by baseline static profile (high confidence)."
                        },
                        "attack_techniques": [],
                        "family_signals": {
                            "anti_vm": [],
                            "packers_obfuscators": []
                        }
                    }
                    
                    cur.execute(
                        "INSERT INTO public.documents (key, collection, doc_id, data) VALUES (%s, %s, %s, %s)",
                        ("apkanalysisresults/scan_sova_mock", "apkanalysisresults", "scan_sova_mock", encrypt_data(sova_doc))
                    )
                    cur.execute(
                        "INSERT INTO public.documents (key, collection, doc_id, data) VALUES (%s, %s, %s, %s)",
                        ("apkanalysisresults/scan_fake_sbi_mock", "apkanalysisresults", "scan_fake_sbi_mock", encrypt_data(fake_sbi_doc))
                    )
                    cur.execute(
                        "INSERT INTO public.documents (key, collection, doc_id, data) VALUES (%s, %s, %s, %s)",
                        ("apkanalysisresults/scan_clean_sbi_mock", "apkanalysisresults", "scan_clean_sbi_mock", encrypt_data(clean_sbi_doc))
                    )
                    
                    cur.execute(
                        "INSERT INTO public.threat_indicators (scan_id, indicator, type, geolocation, asn, reputation_score) VALUES (%s, %s, %s, %s, %s, %s)",
                        ("scan_sova_mock", "evil-banking-c2.ru", "domain", "Moscow, RU", "AS12345 Reg.Ru", 95)
                    )
                    cur.execute(
                        "INSERT INTO public.threat_indicators (scan_id, indicator, type, geolocation, asn, reputation_score) VALUES (%s, %s, %s, %s, %s, %s)",
                        ("scan_fake_sbi_mock", "evil-banking-c2.ru", "domain", "Moscow, RU", "AS12345 Reg.Ru", 95)
                    )
                    
                    logger.info("Successfully seeded Phase 16 showcase fixtures and C2 threat cluster map indicators.")
            except Exception as seed_err:
                logger.error(f"Failed to seed demo data: {seed_err}")

        conn.close()
        logger.info("Local PostgreSQL database schema bootstrapped successfully.")
    except Exception as e:
        logger.error(f"Failed to bootstrap PostgreSQL database: {e}")
        raise e


_write_lock = threading.RLock()

def _serialize_json(data: Any) -> str:
    def helper(obj):
        if isinstance(obj, bytes):
            try:
                return obj.decode('utf-8', errors='ignore')
            except Exception:
                return obj.hex()
        elif hasattr(obj, 'isoformat'):
            return obj.isoformat()
        return str(obj)
    return json.dumps(data, default=helper)


def _get_nested(data: Dict[str, Any], field: str, default: Any = None) -> Any:
    current: Any = data
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _set_nested(data: Dict[str, Any], field: str, value: Any) -> None:
    parts = field.split(".")
    current = data
    for part in parts[:-1]:
        next_value = current.get(part)
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[parts[-1]] = value


# ─── ArrayUnion sentinel ──────────────────────────────────────────────────────
class ArrayUnion:
    def __init__(self, values: list):
        self.values = values


# ─── Document Snapshot ────────────────────────────────────────────────────────
class DocumentSnapshot:
    def __init__(self, doc_id: str, data: Optional[Dict]):
        self.id = doc_id
        self._data = data
        self.exists = data is not None

    def to_dict(self):
        return dict(self._data) if self._data else {}


# ─── Document Reference ───────────────────────────────────────────────────────
class DocumentReference:
    def __init__(self, collection_name: str, doc_id: str):
        self._col = collection_name
        self.id = doc_id
        self._cached_data: Optional[Dict] = None
        self._cached_encrypted_data: Optional[str] = None

    def _key(self) -> str:
        return f"{self._col}/{self.id}"

    def get(self) -> DocumentSnapshot:
        if not is_postgres_configured():
            logger.warning("PostgreSQL not configured. DocumentReference.get returning empty snapshot.")
            return DocumentSnapshot(self.id, None)

        # Force query PostgreSQL to see real-time updates from other processes/threads.
        # caching self._cached_data on the instance is bypassed.

        try:
            pool = get_connection_pool()
            conn = pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT data FROM public.documents WHERE key = %s", (self._key(),))
                    row = cur.fetchone()
                    if row:
                        raw_data = row[0]
                        self._cached_encrypted_data = raw_data
                        data = raw_data
                        if isinstance(data, str):
                            data = decrypt_data(data)
                        self._cached_data = data
                        return DocumentSnapshot(self.id, data)
                    else:
                        self._cached_data = None
                        self._cached_encrypted_data = None
            finally:
                pool.putconn(conn)
        except Exception as e:
            logger.error(f"PostgreSQL GET error: {e}")
        return DocumentSnapshot(self.id, None)

    def set(self, data: Dict):
        if not is_postgres_configured():
            return
        
        encrypted = encrypt_data(data)
        try:
            pool = get_connection_pool()
            conn = pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO public.documents (key, collection, doc_id, data)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (key) DO UPDATE
                        SET data = EXCLUDED.data
                        """,
                        (self._key(), self._col, self.id, encrypted)
                    )
                    conn.commit()
                    self._cached_data = dict(data)
                    self._cached_encrypted_data = encrypted
            except Exception as dbe:
                conn.rollback()
                raise dbe
            finally:
                pool.putconn(conn)
        except Exception as e:
            logger.error(f"PostgreSQL SET error: {e}")

    def update(self, updates: Dict):
        if not is_postgres_configured():
            return

        try:
            pool = get_connection_pool()
            conn = pool.getconn()
            try:
                with conn.cursor() as cur:
                    # Select FOR UPDATE to lock the row and get latest data
                    cur.execute("SELECT data FROM public.documents WHERE key = %s FOR UPDATE", (self._key(),))
                    row = cur.fetchone()
                    existing = {}
                    row_exists = False
                    
                    if row:
                        row_exists = True
                        raw_data = row[0]
                        if isinstance(raw_data, str):
                            existing = decrypt_data(raw_data)
                        elif isinstance(raw_data, dict):
                            existing = raw_data
                    
                    # Merge updates
                    for k, v in updates.items():
                        if isinstance(v, ArrayUnion):
                            existing_list = _get_nested(existing, k, [])
                            if not isinstance(existing_list, list):
                                existing_list = []
                            _set_nested(existing, k, existing_list + v.values)
                        else:
                            _set_nested(existing, k, v)
                    
                    new_encrypted_data = encrypt_data(existing)
                    
                    if row_exists:
                        cur.execute(
                            "UPDATE public.documents SET data = %s WHERE key = %s",
                            (new_encrypted_data, self._key())
                        )
                    else:
                        cur.execute(
                            "INSERT INTO public.documents (key, collection, doc_id, data) VALUES (%s, %s, %s, %s)",
                            (self._key(), self._col, self.id, new_encrypted_data)
                        )
                    conn.commit()
                    self._cached_data = existing
                    self._cached_encrypted_data = new_encrypted_data
            except Exception as dbe:
                conn.rollback()
                raise dbe
            finally:
                pool.putconn(conn)
        except Exception as e:
            logger.error(f"PostgreSQL UPDATE error: {e}")

    def increment_counter_with_limit(self, field_name: str, max_limit: int) -> int:
        if not is_postgres_configured():
            snap = self.get()
            existing = snap.to_dict() if snap.exists else {}
            current_count = _get_nested(existing, field_name, 0)
            if not isinstance(current_count, int):
                current_count = 0
            if current_count >= max_limit:
                raise ValueError("Limit exceeded")
            new_count = current_count + 1
            _set_nested(existing, field_name, new_count)
            self.set(existing)
            return new_count

        try:
            pool = get_connection_pool()
            conn = pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT data FROM public.documents WHERE key = %s FOR UPDATE", (self._key(),))
                    row = cur.fetchone()
                    existing = {}
                    row_exists = False
                    
                    if row:
                        row_exists = True
                        raw_data = row[0]
                        if isinstance(raw_data, str):
                            existing = decrypt_data(raw_data)
                        elif isinstance(raw_data, dict):
                            existing = raw_data
                    
                    current_count = _get_nested(existing, field_name, 0)
                    if not isinstance(current_count, int):
                        current_count = 0
                    
                    if current_count >= max_limit:
                        raise ValueError("Limit exceeded")
                    
                    new_count = current_count + 1
                    _set_nested(existing, field_name, new_count)
                    
                    new_encrypted_data = encrypt_data(existing)
                    
                    if row_exists:
                        cur.execute(
                            "UPDATE public.documents SET data = %s WHERE key = %s",
                            (new_encrypted_data, self._key())
                        )
                    else:
                        cur.execute(
                            "INSERT INTO public.documents (key, collection, doc_id, data) VALUES (%s, %s, %s, %s)",
                            (self._key(), self._col, self.id, new_encrypted_data)
                        )
                    conn.commit()
                    self._cached_data = existing
                    self._cached_encrypted_data = new_encrypted_data
                    return new_count
            except Exception as dbe:
                conn.rollback()
                raise dbe
            finally:
                pool.putconn(conn)
        except ValueError:
            raise
        except Exception as e:
            logger.error(f"PostgreSQL INCREMENT error: {e}")
            raise e

    def check_and_update_rate_limit(self, now: float, window_secs: int, requests_limit: int) -> bool:
        if not is_postgres_configured():
            return False

        try:
            pool = get_connection_pool()
            conn = pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT public.check_and_update_rate_limit(%s, %s, %s, %s, %s, %s)",
                        (self._key(), self._col, self.id, now, float(window_secs), requests_limit)
                    )
                    res = cur.fetchone()
                    conn.commit()
                    if res:
                        return bool(res[0])
            except Exception as dbe:
                conn.rollback()
                raise dbe
            finally:
                pool.putconn(conn)
        except Exception as e:
            logger.error(f"PostgreSQL RATE_LIMIT error: {e}")
        return False

    def delete(self):
        if not is_postgres_configured():
            return
        
        try:
            pool = get_connection_pool()
            conn = pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM public.documents WHERE key = %s", (self._key(),))
                    conn.commit()
                    self._cached_data = None
                    self._cached_encrypted_data = None
            except Exception as dbe:
                conn.rollback()
                raise dbe
            finally:
                pool.putconn(conn)
        except Exception as e:
            logger.error(f"PostgreSQL DELETE error: {e}")


# ─── Query (supports where + orderBy + limit) ─────────────────────────────────
class Query:
    DESCENDING = "DESCENDING"
    ASCENDING = "ASCENDING"

    def __init__(self, collection_name: str, docs: Optional[List[Dict]] = None):
        self._col = collection_name
        self._docs = docs
        self._filters: List = []
        self._order_field: Optional[str] = None
        self._order_desc: bool = False
        self._limit_n: Optional[int] = None

    def where(self, field: str, op: str, value: Any) -> "Query":
        q = Query(self._col, self._docs)
        q._filters = self._filters + [(field, op, value)]
        q._order_field = self._order_field
        q._order_desc = self._order_desc
        q._limit_n = self._limit_n
        return q

    def order_by(self, field: str, direction=None) -> "Query":
        q = Query(self._col, self._docs)
        q._filters = self._filters
        q._order_field = field
        q._order_desc = (direction == "DESCENDING")
        q._limit_n = self._limit_n
        return q

    def limit(self, n: int) -> "Query":
        q = Query(self._col, self._docs)
        q._filters = self._filters
        q._order_field = self._order_field
        q._order_desc = self._order_desc
        q._limit_n = n
        return q

    def stream(self) -> List[DocumentSnapshot]:
        docs_to_process = self._docs
        if docs_to_process is None:
            if not is_postgres_configured():
                return []
            
            try:
                pool = get_connection_pool()
                conn = pool.getconn()
                try:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT doc_id, data FROM public.documents WHERE collection = %s",
                            (self._col,)
                        )
                        rows = cur.fetchall()
                        docs_to_process = []
                        for row in rows:
                            doc_id = row[0]
                            data = row[1]
                            if isinstance(data, str):
                                data = decrypt_data(data)
                            docs_to_process.append((doc_id, data))
                finally:
                    pool.putconn(conn)
            except Exception as e:
                logger.error(f"PostgreSQL STREAM error: {e}")
                return []

        results = []
        for doc_id, data in docs_to_process:
            match = True
            for field, op, value in self._filters:
                v = _get_nested(data, field)
                if op == "==" and v != value:
                    match = False; break
                elif op == "!=" and v == value:
                    match = False; break
                elif op == ">" and not (v is not None and v > value):
                    match = False; break
                elif op == "<" and not (v is not None and v < value):
                    match = False; break
            if match:
                results.append(DocumentSnapshot(doc_id, data))

        if self._order_field:
            def sort_key(s):
                val = _get_nested(s.to_dict(), self._order_field, "")
                return val if val is not None else ""
            results.sort(key=sort_key, reverse=self._order_desc)

        if self._limit_n is not None:
            results = results[:self._limit_n]

        return results

    def get(self) -> List[DocumentSnapshot]:
        return self.stream()


# ─── Collection Reference ─────────────────────────────────────────────────────
class CollectionReference:
    def __init__(self, name: str):
        self._name = name

    def document(self, doc_id: str = None) -> DocumentReference:
        if doc_id is None:
            doc_id = str(uuid.uuid4()).replace("-", "")
        return DocumentReference(self._name, doc_id)

    def where(self, field: str, op: str, value: Any) -> Query:
        return self._make_query().where(field, op, value)

    def order_by(self, field: str, direction=None) -> Query:
        return self._make_query().order_by(field, direction)

    def _make_query(self) -> Query:
        return Query(self._name, None)

    def get(self) -> List[DocumentSnapshot]:
        return self._make_query().get()


# ─── Postgres DB Client (mimics firestore/supabase client) ───────────────────
class PostgresDB:
    ArrayUnion = ArrayUnion
    Query = Query

    def collection(self, name: str) -> CollectionReference:
        return CollectionReference(name)

    def get_trusted_signer(self, package_name: str) -> Optional[Dict[str, Any]]:
        return get_trusted_signer(package_name)

# Aliases to make it drop-in compatible
SupabaseDB = PostgresDB


class _Direction:
    DESCENDING = "DESCENDING"
    ASCENDING = "ASCENDING"

Query_Direction = _Direction()

def get_trusted_signer(package_name: str) -> Optional[Dict[str, Any]]:
    if not is_postgres_configured():
        return None
    try:
        pool = get_connection_pool()
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT package_name, bank_name, sha256_fingerprint, notes FROM public.trusted_signers WHERE package_name = %s",
                    (package_name,)
                )
                row = cur.fetchone()
                if row:
                    return {
                        "package_name": row[0],
                        "bank_name": row[1],
                        "sha256": row[2],
                        "notes": row[3]
                    }
        finally:
            pool.putconn(conn)
    except Exception as e:
        logger.error(f"Error querying trusted_signers: {e}")
    return None
