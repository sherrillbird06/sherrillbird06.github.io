#!/usr/bin/env python3
"""
Test suite for all five tools.

The security-relevant assertions are the point. It is easy to write a
test that proves encryption round-trips and call it done — that only
proves the happy path. The tests that matter here are the ones that
prove the failure paths fail: tampering rejected, wrong keys rejected,
lockouts triggered, allowlists honoured.

Run:  python3 -m pytest test_all.py -v
"""

import importlib.util
import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).parent


def load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, ROOT / relpath)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


passforge  = load("passforge",  "passforge/passforge.py")
lockbox    = load("lockbox",    "lockbox/lockbox.py")
lockout_lens = load("lockout_lens", "lockout-lens/lockout_lens.py")


# ── PassForge ───────────────────────────────────────────────────────

class TestPassForge:
    def test_length_respected(self):
        for n in (12, 20, 64):
            assert len(passforge.generate(n)) == n

    def test_all_classes_present(self):
        pw = passforge.generate(20)
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)

    def test_no_ambiguous_characters(self):
        for _ in range(50):
            assert not set(passforge.generate(30)) & set(passforge.AMBIGUOUS)

    def test_outputs_are_unique(self):
        # A generator that repeats itself is broken, not random.
        assert len({passforge.generate(16) for _ in range(500)}) == 500

    def test_entropy_rises_with_length(self):
        assert passforge.entropy_bits("aaaaaaaa") < passforge.entropy_bits("aaaaaaaaaaaaaaaa")

    def test_entropy_rises_with_pool(self):
        assert passforge.entropy_bits("abcdefgh") < passforge.entropy_bits("aBc3!fgh")

    def test_passphrase_scored_as_words_not_chars(self):
        # The whole point of the fix: a 3-word phrase must not score as
        # if it were ~20 random characters.
        phrase = passforge.generate_passphrase(3)
        as_words = passforge.entropy_bits(phrase, word_count=3)
        as_chars = passforge.entropy_bits(phrase)
        assert as_words < as_chars

    def test_known_weak_password_fails(self):
        assert passforge.verdict(passforge.entropy_bits("password")) == "TOO WEAK"

    def test_rejects_impossible_length(self):
        with pytest.raises(ValueError):
            passforge.generate(2)


# ── Lockbox ─────────────────────────────────────────────────────────

class TestLockbox:
    def test_round_trip(self, tmp_path):
        src = tmp_path / "a.txt"
        src.write_bytes(b"classified\n" * 5000)
        enc, dec = tmp_path / "a.lockbox", tmp_path / "a.out"

        lockbox.encrypt_file(src, enc, "passphrase-for-testing")
        lockbox.decrypt_file(enc, dec, "passphrase-for-testing")
        assert dec.read_bytes() == src.read_bytes()

    def test_ciphertext_is_not_plaintext(self, tmp_path):
        src = tmp_path / "a.txt"
        src.write_bytes(b"TOPSECRETMARKER" * 100)
        enc = tmp_path / "a.lockbox"
        lockbox.encrypt_file(src, enc, "pw-testing-123")
        assert b"TOPSECRETMARKER" not in enc.read_bytes()

    def test_wrong_passphrase_rejected(self, tmp_path):
        src = tmp_path / "a.txt"; src.write_bytes(b"data")
        enc, dec = tmp_path / "a.lockbox", tmp_path / "a.out"
        lockbox.encrypt_file(src, enc, "right-passphrase")
        with pytest.raises(ValueError):
            lockbox.decrypt_file(enc, dec, "wrong-passphrase")

    def test_tampering_detected(self, tmp_path):
        src = tmp_path / "a.txt"; src.write_bytes(b"data" * 1000)
        enc, dec = tmp_path / "a.lockbox", tmp_path / "a.out"
        lockbox.encrypt_file(src, enc, "pw-testing-123")

        raw = bytearray(enc.read_bytes())
        raw[-5] ^= 0x01
        enc.write_bytes(bytes(raw))

        with pytest.raises(ValueError):
            lockbox.decrypt_file(enc, dec, "pw-testing-123")

    def test_failed_decrypt_leaves_no_partial_file(self, tmp_path):
        src = tmp_path / "a.txt"; src.write_bytes(b"x" * 200_000)
        enc, dec = tmp_path / "a.lockbox", tmp_path / "a.out"
        lockbox.encrypt_file(src, enc, "right-passphrase")
        with pytest.raises(ValueError):
            lockbox.decrypt_file(enc, dec, "wrong-passphrase")
        assert not dec.exists()
        assert not list(tmp_path.glob("*.part"))

    def test_same_passphrase_gives_different_ciphertext(self, tmp_path):
        # Random salt per file. Identical output would leak that two
        # files share a passphrase, and worse, that they're identical.
        src = tmp_path / "a.txt"; src.write_bytes(b"same content")
        e1, e2 = tmp_path / "1.lb", tmp_path / "2.lb"
        lockbox.encrypt_file(src, e1, "identical-passphrase")
        lockbox.encrypt_file(src, e2, "identical-passphrase")
        assert e1.read_bytes() != e2.read_bytes()

    def test_rejects_foreign_file(self, tmp_path):
        junk = tmp_path / "junk.lockbox"
        junk.write_bytes(b"not a lockbox file at all")
        with pytest.raises(ValueError):
            lockbox.decrypt_file(junk, tmp_path / "out", "pw-testing-123")



# ── Lockout Lens ──────────────────────────────────────────────────────

FAIL = "Failed password for invalid user admin from {ip} port 22 ssh2"
OK   = "Accepted password for ada from {ip} port 22 ssh2"


@pytest.fixture
def wt(tmp_path, monkeypatch):
    monkeypatch.setattr(lockout_lens, "STATE", tmp_path / "state.json")
    return lockout_lens.LockoutLens(threshold=5, window=300)


class TestLockoutLens:
    def test_bans_after_threshold(self, wt):
        hits = [wt.feed(FAIL.format(ip="203.0.113.9"), now=1000 + i) for i in range(5)]
        assert hits[:4] == [None] * 4
        assert hits[4]["ip"] == "203.0.113.9"

    def test_under_threshold_is_left_alone(self, wt):
        for i in range(4):
            assert wt.feed(FAIL.format(ip="203.0.113.9"), now=1000 + i) is None
        assert not wt.banned

    def test_old_failures_fall_out_of_window(self, wt):
        # Four failures, a long gap, then four more is not an attack.
        for i in range(4):
            wt.feed(FAIL.format(ip="203.0.113.9"), now=1000 + i)
        for i in range(4):
            wt.feed(FAIL.format(ip="203.0.113.9"), now=5000 + i)
        assert not wt.banned

    def test_allowlist_is_never_banned(self, wt):
        for i in range(50):
            wt.feed(FAIL.format(ip="192.168.1.50"), now=1000 + i)
        assert not wt.banned

    def test_success_clears_the_record(self, wt):
        for i in range(4):
            wt.feed(FAIL.format(ip="198.51.100.3"), now=1000 + i)
        wt.feed(OK.format(ip="198.51.100.3"), now=1005)
        for i in range(4):
            wt.feed(FAIL.format(ip="198.51.100.3"), now=1010 + i)
        assert not wt.banned

    def test_bans_escalate(self, wt):
        first  = wt.ban("203.0.113.9", now=1000)
        wt.banned.clear()
        second = wt.ban("203.0.113.9", now=2000)
        assert second["seconds"] > first["seconds"]

    def test_bans_are_capped(self, wt):
        for i in range(20):
            wt.banned.clear()
            hit = wt.ban("203.0.113.9", now=1000 * i)
        assert hit["seconds"] <= lockout_lens.MAX_BAN

    def test_bans_expire(self, wt):
        wt.ban("203.0.113.9", now=1000)
        assert wt.expire(now=1000 + lockout_lens.BASE_BAN + 1) == ["203.0.113.9"]

    def test_malformed_lines_are_survivable(self, wt):
        for junk in ("", "\n", "not a log line", "Failed password for from", "🔥" * 50):
            assert wt.feed(junk, now=1000) is None

    def test_ruleset_is_valid_nftables_shape(self, wt):
        wt.ban("203.0.113.9", now=time.time())
        rules = wt.ruleset()
        assert "table inet lockoutlens" in rules
        assert "203.0.113.9" in rules
        assert rules.count("{") == rules.count("}")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
