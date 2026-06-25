"""
Unit tests for APK Certificate & Signing Forensics (Phase 2).
"""

import pytest
from unittest.mock import patch, MagicMock
from analysis_engine import verify_certificate, calculate_deterministic_score
from risk_engine import build_contributors

def test_verify_certificate_unsigned():
    # Test case: Unsigned APK
    cert_info = {"is_signed": False}
    result = verify_certificate(cert_info, "com.example.app")
    assert result["is_signed"] is False
    assert result["verdict"] == "UNSIGNED"
    assert "not cryptographically signed" in result["verdict_description"]

    # None or empty dict input should also fallback to unsigned
    result = verify_certificate({}, "com.example.app")
    assert result["is_signed"] is False
    assert result["verdict"] == "UNSIGNED"

def test_verify_certificate_debug_key():
    # Test case: Debug signing key
    cert_info = {
        "is_signed": True,
        "subject": "CN=Android Debug, O=Android, C=US",
        "issuer": "CN=Android Debug, O=Android, C=US",
        "sha256": "4A:5B:6C..."
    }
    result = verify_certificate(cert_info, "com.example.app")
    assert result["verdict"] == "DEBUG_KEY_SIGNED"
    assert "debug key" in result["verdict_description"].lower()

def test_verify_certificate_legit_matched_signer():
    # Test case: Legitimate bank signer match (using fallback baseline since postgres is not configured by default in test env)
    cert_info = {
        "is_signed": True,
        "subject": "CN=State Bank of India, O=State Bank of India, C=IN",
        "issuer": "CN=State Bank of India, O=State Bank of India, C=IN",
        "sha256": "2E:B5:E4:D3:C2:B1:E0:F9:A8:B7:C6:D5:E4:F3:A2:B1:C0:D9:E8:F7:A6:B5:C4:D3:E2:F1:A0:B9:C8:D7:E6:F5"
    }
    result = verify_certificate(cert_info, "com.sbi.yono")
    assert result["verdict"] == "LEGIT_MATCHED_SIGNER"
    assert "official State Bank of India certificate" in result["verdict_description"]

def test_verify_certificate_mismatched_signer():
    # Test case: Package name matches a registered bank but the fingerprint differs
    cert_info = {
        "is_signed": True,
        "subject": "CN=Hacker Dev, O=Fraud, C=IN",
        "issuer": "CN=Hacker Dev, O=Fraud, C=IN",
        "sha256": "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF"
    }
    result = verify_certificate(cert_info, "com.sbi.yono")
    assert result["verdict"] == "MISMATCHED_SIGNER_FOR_KNOWN_BANK_PACKAGE"
    assert "trojanized clone" in result["verdict_description"]
    assert result["matched_baseline"] is not None
    assert result["matched_baseline"]["bank_name"] == "State Bank of India"
    assert "2E:B5" in result["matched_baseline"]["sha256"]

def test_verify_certificate_lookalike_package():
    # Test case: Lookalike package name (e.g. contains 'yono' or 'sbi' but not exactly registered)
    cert_info = {
        "is_signed": True,
        "subject": "CN=Unknown Dev, O=Malicious, C=IN",
        "issuer": "CN=Unknown Dev, O=Malicious, C=IN",
        "sha256": "BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB"
    }
    result = verify_certificate(cert_info, "com.sbi.yono.login.helper")
    assert result["verdict"] == "MISMATCHED_SIGNER_FOR_KNOWN_BANK_PACKAGE"
    assert "contains keywords associated with State Bank of India" in result["verdict_description"]
    assert result["matched_baseline"] is not None
    assert result["matched_baseline"]["package_name"] == "com.sbi.yono"

def test_verify_certificate_unknown_self_signed():
    # Test case: Generic unknown self-signed developer
    cert_info = {
        "is_signed": True,
        "subject": "CN=Generic Developer, O=Independent, C=US",
        "issuer": "CN=Generic Developer, O=Independent, C=US",
        "sha256": "DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD"
    }
    result = verify_certificate(cert_info, "com.example.utility")
    assert result["verdict"] == "UNKNOWN_SELF_SIGNED_DEVELOPER"
    assert "no matching official bank baseline" in result["verdict_description"]

@patch("postgres_db.is_postgres_configured")
@patch("postgres_db.get_trusted_signer")
def test_verify_certificate_with_postgres_mock(mock_get_trusted, mock_is_configured):
    # Test case: Database integration works correctly when Postgres is configured
    mock_is_configured.return_value = True
    mock_get_trusted.return_value = {
        "package_name": "com.boi.group.boimobile",
        "bank_name": "Bank of India",
        "sha256": "1A:2B:3C:4D:5E:6F:7A:8B:9C:0D:1E:2F:3A:4B:5C:6D:7E:8F:9A:0B:1C:2D:3E:4F:5A:6B:7C:8D:9E:0F:1A:2B",
        "notes": "Official Bank of India Mobile Banking app signer."
    }

    cert_info = {
        "is_signed": True,
        "subject": "CN=Official Bank of India, O=Bank of India, C=IN",
        "issuer": "CN=Official Bank of India, O=Bank of India, C=IN",
        "sha256": "1A:2B:3C:4D:5E:6F:7A:8B:9C:0D:1E:2F:3A:4B:5C:6D:7E:8F:9A:0B:1C:2D:3E:4F:5A:6B:7C:8D:9E:0F:1A:2B"
    }
    result = verify_certificate(cert_info, "com.boi.group.boimobile")
    mock_get_trusted.assert_called_once_with("com.boi.group.boimobile")
    assert result["verdict"] == "LEGIT_MATCHED_SIGNER"

def test_deterministic_scoring_integration():
    # Verify that calculate_deterministic_score correctly integrates certificate forensics into scoring
    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.sbi.yono">
    </manifest>"""
    
    # 1. Test mismatched certificate scoring impact (+40 critical finding)
    androguard_res = {
        "is_signed": True,
        "certificate_info": {
            "is_signed": True,
            "subject": "CN=Hacker Dev, O=Fraud, C=IN",
            "issuer": "CN=Hacker Dev, O=Fraud, C=IN",
            "sha256": "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF"
        }
    }
    
    score_res = calculate_deterministic_score(
        manifest_content=manifest_xml,
        jadx_sources={},
        androguard_res=androguard_res,
        package_name="com.sbi.yono"
    )
    
    # Check that the verdict in certificate_info is correct
    cert_info = score_res["evidence"]["certificate_info"]
    assert cert_info["verdict"] == "MISMATCHED_SIGNER_FOR_KNOWN_BANK_PACKAGE"
    
    # Check that build_contributors detects this signer mismatch
    contributors = build_contributors(score_res["evidence"], [], [])
    assert any(c["label"] == "Signature Signer Mismatch" and c["weight"] == 40 for c in contributors)

    # 2. Test debug key certificate scoring impact (+25 high finding)
    androguard_res_debug = {
        "is_signed": True,
        "certificate_info": {
            "is_signed": True,
            "subject": "CN=Android Debug, O=Android, C=US",
            "issuer": "CN=Android Debug, O=Android, C=US",
            "sha256": "DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD:DD"
        }
    }
    
    score_res_debug = calculate_deterministic_score(
        manifest_content=manifest_xml,
        jadx_sources={},
        androguard_res=androguard_res_debug,
        package_name="com.sbi.yono"
    )
    
    # Check that the verdict in certificate_info is correct
    cert_info_debug = score_res_debug["evidence"]["certificate_info"]
    assert cert_info_debug["verdict"] == "DEBUG_KEY_SIGNED"
    
    # Check that build_contributors detects this debug signing key
    contributors_debug = build_contributors(score_res_debug["evidence"], [], [])
    assert any(c["label"] == "Debug Build Signing Cert" and c["weight"] == 25 for c in contributors_debug)

def test_verify_certificate_weak_algorithm():
    # Test case: Weak / outdated signature algorithm (e.g. SHA-1 or MD5)
    cert_info = {
        "is_signed": True,
        "subject": "CN=Some Developer, O=Corp, C=US",
        "issuer": "CN=Some Developer, O=Corp, C=US",
        "sha256": "4A:5B:6C...",
        "signature_algo": "sha1withrsaencryption"
    }
    result = verify_certificate(cert_info, "com.example.utility")
    assert result["verdict"] == "UNUSUAL_CERT_CHARACTERISTICS"
    assert "weak/outdated signature hashing algorithm" in result["verdict_description"]
