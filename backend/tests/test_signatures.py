"""Tests for the known-hash blocklist (signatures.py)."""

import hashlib

import signatures


def test_blocklist_has_exactly_one_preexisting_hash():
    assert len(signatures.KNOWN_HASHES) == 1


def test_the_one_hash_is_canonical_eicar():
    sha = hashlib.sha256(signatures.EICAR_STRING).hexdigest()
    assert sha in signatures.KNOWN_HASHES
    assert signatures.KNOWN_HASHES[sha] == "EICAR-Test-File"


def test_match_hash_hits_on_known_hash():
    sha = hashlib.sha256(signatures.EICAR_STRING).hexdigest()
    match = signatures.match_hash(sha)
    assert match is not None
    assert match.name == "EICAR-Test-File"
    assert match.category == "test-file"


def test_match_hash_misses_on_unknown_hash():
    sha = hashlib.sha256(b"some other file entirely").hexdigest()
    assert signatures.match_hash(sha) is None


def test_padded_eicar_variant_does_not_match():
    """Only ONE exact hash ships — a padded variant hashes differently."""
    sha = hashlib.sha256(signatures.EICAR_STRING + b"\r\n").hexdigest()
    assert signatures.match_hash(sha) is None
