"""
End-to-end tests for the ScanForge API, focused on ZIP handling and
signature detection — the areas this hardening pass touched.

Run with: pytest (from backend/), after `pip install -r requirements.txt`.
"""

import io
import zipfile

import pytest
from fastapi.testclient import TestClient

import main

client = TestClient(main.app)

EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def _zip_bytes(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_eicar_raw_upload_is_malicious():
    resp = client.post(
        "/analyze",
        files={"file": ("eicar.com", EICAR, "application/octet-stream")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "MALICIOUS"
    assert data["risk_score"] == 100.0
    assert data["signature_match"]
    # Full pipeline ran: signature factor present, raw-byte entropy reported
    assert any("signature" in f["label"].lower() for f in data["factors"])
    assert data["avg_section_entropy"] > 0
    assert data["sha256"]


def test_eicar_zip_upload_is_malicious():
    zbytes = _zip_bytes({"eicar.com": EICAR})
    resp = client.post(
        "/analyze",
        files={"file": ("eicar.zip", zbytes, "application/zip")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "MALICIOUS"
    assert data["signature_match"]
    assert data["archive_name"] == "eicar.zip"
    # The zipped entry followed the same full pipeline as a raw upload
    assert any("signature" in f["label"].lower() for f in data["factors"])
    assert data["avg_section_entropy"] > 0


def test_signature_match_keeps_structural_factors_for_pe():
    """A PE that ALSO matches a signature must keep its structural factors
    in the report alongside the leading signature factor."""
    import signatures as sigs
    from pathlib import Path
    pe_bytes = Path(main.SAMPLES_DIR / "packed.exe").read_bytes()
    sha = __import__("hashlib").sha256(pe_bytes).hexdigest()
    sigs.KNOWN_HASHES[sha] = "Test-Packed-Signature"
    try:
        resp = client.post(
            "/analyze",
            files={"file": ("packed.exe", pe_bytes, "application/octet-stream")},
        )
        data = resp.json()
        assert data["verdict"] == "MALICIOUS"
        assert data["risk_score"] == 100.0
        labels = [f["label"].lower() for f in data["factors"]]
        assert any("signature" in l for l in labels)
        assert any("entropy" in l for l in labels)  # structural factor retained
    finally:
        del sigs.KNOWN_HASHES[sha]


def test_nested_zip_with_eicar_is_still_detected():
    inner = _zip_bytes({"eicar.com": EICAR})
    outer = _zip_bytes({"inner.zip": inner})
    resp = client.post(
        "/analyze",
        files={"file": ("outer.zip", outer, "application/zip")},
    )
    data = resp.json()
    assert data["verdict"] == "MALICIOUS"
    assert "eicar.com" in data["archive_note"]


def test_empty_zip_reports_gracefully():
    zbytes = _zip_bytes({})
    resp = client.post(
        "/analyze",
        files={"file": ("empty.zip", zbytes, "application/zip")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["not_pe"] is True
    assert "empty" in data["parse_note"].lower()


def test_benign_text_zip_reports_no_threats_found():
    zbytes = _zip_bytes({"readme.txt": b"hello world, nothing to see here"})
    resp = client.post(
        "/analyze",
        files={"file": ("docs.zip", zbytes, "application/zip")},
    )
    data = resp.json()
    assert data["not_pe"] is True
    assert data["verdict"] == "NOT A PE FILE"
    assert "readme.txt" in data["parse_note"]


def test_zip_bomb_declared_size_is_rejected_fast():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("bomb.bin", b"\x00" * (300 * 1024 * 1024))
    resp = client.post(
        "/analyze",
        files={"file": ("bomb.zip", buf.getvalue(), "application/zip")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["not_pe"] is True
    assert "rejected" in data["parse_note"].lower()


def test_zip_with_too_many_entries_is_rejected():
    entries = {f"f{i}.txt": b"x" for i in range(600)}
    zbytes = _zip_bytes(entries)
    resp = client.post(
        "/analyze",
        files={"file": ("many.zip", zbytes, "application/zip")},
    )
    data = resp.json()
    assert "more than" in data["parse_note"]


def test_misnamed_non_zip_falls_back_to_raw_analysis():
    resp = client.post(
        "/analyze",
        files={"file": ("fake.zip", b"not actually a zip file", "application/zip")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["not_pe"] is True


def test_unsupported_extension_rejected():
    resp = client.post(
        "/analyze",
        files={"file": ("malware.pdf", b"whatever", "application/pdf")},
    )
    assert resp.status_code == 415


def test_empty_upload_rejected():
    resp = client.post(
        "/analyze",
        files={"file": ("empty.exe", b"", "application/octet-stream")},
    )
    assert resp.status_code == 400


@pytest.mark.parametrize("name", ["benign.exe", "packed.exe", "suspicious_imports.exe", "eicar.com"])
def test_all_preloaded_samples_are_servable(name):
    resp = client.get(f"/sample/{name}")
    assert resp.status_code == 200
    assert resp.json()["verdict"] in {"BENIGN", "SUSPICIOUS", "MALICIOUS"}


def test_unknown_sample_name_404s():
    resp = client.get("/sample/not_a_real_sample")
    assert resp.status_code == 404
