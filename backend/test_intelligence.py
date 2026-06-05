"""Tests for banking fraud, risk engine, and ATT&CK mapping."""

from banking_fraud import analyze_banking_fraud
from attack_mapping import map_evidence_to_attack
from risk_engine import build_risk_decomposition, derive_dynamic_score


MANIFEST_SMS = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-permission android:name="android.permission.RECEIVE_SMS"/>
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
</manifest>"""


def test_banking_fraud_detects_sms_and_overlay():
    result = analyze_banking_fraud(MANIFEST_SMS, {}, [], [])
    ids = {b["id"] for b in result["badges"]}
    assert "BANK-SMS-STEALER" in ids
    assert "BANK-OVERLAY" in ids
    assert result["fraud_score"] > 0


def test_attack_mapping_from_permissions():
    evidence = {"permissions": [{"name": "android.permission.RECEIVE_SMS"}]}
    techniques = map_evidence_to_attack(evidence, [])
    assert any(t["id"] == "T1636.001" for t in techniques)


def test_risk_decomposition():
    dec = build_risk_decomposition(60, 40, 70, 50)
    assert dec["composite_score"] > 0
    assert "static" in dec["components"]


def test_dynamic_score_zero_when_unavailable():
    assert derive_dynamic_score([], 0, "UNAVAILABLE") == 0


def test_zipbomb_prevention_on_download():
    import tempfile
    import os
    import zipfile
    import io
    import pytest
    from main import _write_downloaded_apk

    with tempfile.TemporaryDirectory() as tmpdir:
        fake_apk = os.path.join(tmpdir, "test_bomb.apk")
        
        # Create a tiny zip with fake metadata claiming 600MB uncompressed
        zinfo = zipfile.ZipInfo("fake.txt")
        zinfo.file_size = 600 * 1024 * 1024
        zinfo.compress_size = 4
        
        # Write it to raw bytes
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr(zinfo, b"tiny")
            zf.filelist[0].file_size = 600 * 1024 * 1024
        raw_bytes = zip_buffer.getvalue()
        
        # Run _write_downloaded_apk and expect Exception
        with pytest.raises(Exception) as excinfo:
            _write_downloaded_apk(raw_bytes, fake_apk)
        
        assert "Possible zipbomb" in str(excinfo.value)
        assert not os.path.exists(fake_apk)


def test_rate_limiter():
    from routes import InMemRateLimiter
    limiter = InMemRateLimiter(2, 60)
    assert limiter.check("ip1") is True
    assert limiter.check("ip1") is True
    assert limiter.check("ip1") is False  # 3rd time within 60s is blocked
    assert limiter.check("ip2") is True  # other key/IP is not blocked


