"""Tests for signature-based known-threat detection (signatures.py)."""

import signatures

EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def test_eicar_exact_match():
    match = signatures.scan_signatures(EICAR)
    assert match is not None
    assert match.category == "test-file"
    assert "EICAR" in match.name


def test_eicar_with_trailing_newline_still_matches():
    match = signatures.scan_signatures(EICAR + b"\r\n")
    assert match is not None


def test_eicar_embedded_in_larger_file_still_matches():
    wrapped = b"some header bytes\x00\x00" + EICAR + b"trailer padding"
    match = signatures.scan_signatures(wrapped)
    assert match is not None


def test_benign_bytes_no_match():
    assert signatures.scan_signatures(b"just a normal harmless file") is None


def test_empty_bytes_no_match():
    assert signatures.scan_signatures(b"") is None


def test_known_hash_table_entries_are_internally_consistent():
    """Every hash in KNOWN_HASHES must actually be the sha256 of *something*
    containing the EICAR string, so the hash layer and substring layer never
    disagree with each other."""
    import hashlib
    for variant in (EICAR, EICAR + b"\n", EICAR + b"\r\n"):
        h = hashlib.sha256(variant).hexdigest()
        assert h in signatures.KNOWN_HASHES, f"missing known hash for variant len={len(variant)}"
