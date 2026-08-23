#!/usr/bin/env python3
"""
PassForge — password generator and entropy analyzer.

Two things most generators get wrong, and why this one doesn't:

  1. They use `random`, which is a Mersenne Twister. Observe ~624 outputs
     and you can predict every future one. `secrets` pulls from the OS
     CSPRNG instead. That is the whole difference, and it is not optional.

  2. They score passwords with rules ("has a capital? +1 point"), which
     rewards P@ssw0rd1 and punishes four honest random words. This scores
     actual entropy in bits, then checks the result against a breach list,
     because a high-entropy string that has already leaked is worthless.

Usage:
    python3 passforge.py                       # one 20-char password
    python3 passforge.py -n 5 -l 32            # five 32-char passwords
    python3 passforge.py --words 5             # passphrase instead
    python3 passforge.py --check "hunter2"     # analyze, don't generate
"""

import argparse
import math
import secrets
import string
import sys
from pathlib import Path

# Ambiguous glyphs removed. A password you transcribe wrong is a password
# you reset, and a reset flow is more attackable than the password was.
AMBIGUOUS = "Il1O0`'\"|"

LOWER = "".join(c for c in string.ascii_lowercase if c not in AMBIGUOUS)
UPPER = "".join(c for c in string.ascii_uppercase if c not in AMBIGUOUS)
DIGIT = "".join(c for c in string.digits if c not in AMBIGUOUS)
SYMBOL = "".join(c for c in "!@#$%^&*()-_=+[]{};:,.<>?/~" if c not in AMBIGUOUS)

BREACHFILE = Path(__file__).parent / "breached.txt"
GUESSES_PER_SEC = 1e11  # offline GPU rate against a fast hash


# ── Generation ──────────────────────────────────────────────────────

def generate(length=20, use_symbols=True):
    """Build a password guaranteed to contain every enabled class.

    The naive approach picks characters uniformly and hopes for a digit.
    The lazy fix is to append one, which biases the last position. This
    seeds one of each class, fills the rest, then shuffles the whole thing.
    """
    pools = [LOWER, UPPER, DIGIT] + ([SYMBOL] if use_symbols else [])
    alphabet = "".join(pools)

    if length < len(pools):
        raise ValueError(f"length must be at least {len(pools)}")

    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(pools))]

    # Fisher-Yates with a CSPRNG source. random.shuffle would undo the
    # entire point of using secrets above.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)


def generate_passphrase(count=4, sep="-"):
    """Diceware-style passphrase. Long and typeable beats short and cryptic."""
    words = _wordlist()
    return sep.join(secrets.choice(words) for _ in range(count))


def _wordlist():
    wl = Path(__file__).parent / "wordlist.txt"
    if wl.exists():
        words = [w.strip() for w in wl.read_text().split() if w.strip()]
        if len(words) >= 100:
            return words
    # Fallback so the tool still runs without the full list present.
    return ("anchor beacon cactus dagger ember falcon gadget harbor ingot "
            "jungle kettle lantern marble nectar orbit pigment quarry ribbon "
            "sandal timber umbra velvet walnut xenon yonder zephyr").split()


# ── Analysis ────────────────────────────────────────────────────────

def pool_size(pw):
    """Infer the search space an attacker would need to cover."""
    size = 0
    if any(c.islower() for c in pw):                        size += 26
    if any(c.isupper() for c in pw):                        size += 26
    if any(c.isdigit() for c in pw):                        size += 10
    if any(c in string.punctuation or c == " " for c in pw): size += 33
    if any(ord(c) > 126 for c in pw):                       size += 100
    return size


def entropy_bits(pw, word_count=None):
    """Bits of entropy.

    Character-pool math is wrong for passphrases and flatters them badly.
    'sandal-ember-anchor' is not 19 random characters — it is 3 choices
    from a known wordlist. An attacker guesses words, not letters, so the
    honest number is count x log2(wordlist size).
    """
    if word_count:
        return word_count * math.log2(len(_wordlist()))
    pool = pool_size(pw)
    return len(pw) * math.log2(pool) if pool else 0.0


def crack_time(bits):
    """Expected time at half the keyspace."""
    if bits <= 0:
        return "instant"
    secs = (2 ** (bits - 1)) / GUESSES_PER_SEC
    for div, name in ((1, "seconds"), (60, "minutes"), (3600, "hours"),
                      (86400, "days"), (2629800, "months"),
                      (31557600, "years")):
        if secs / div < 1000:
            v = secs / div
            return "instant" if v < 1 and name == "seconds" else f"{v:,.1f} {name}"
    return f"{secs / 31557600:.2e} years"


def is_breached(pw):
    """Check a local breach wordlist.

    Local on purpose. Sending a password to a third-party API to ask
    whether it is safe is a strange way to keep it safe.
    """
    if not BREACHFILE.exists():
        return None
    target = pw.lower()
    with BREACHFILE.open(encoding="utf-8", errors="ignore") as fh:
        return any(line.strip().lower() == target for line in fh)


def verdict(bits):
    if bits < 50:  return "TOO WEAK"
    if bits < 75:  return "PASSABLE"
    if bits < 100: return "STRONG"
    return "EXCELLENT"


def report(pw, reveal=True, word_count=None):
    bits = entropy_bits(pw, word_count)
    breached = is_breached(pw)

    print(f"\n  {pw if reveal else '*' * len(pw)}")
    print(f"  {'─' * max(len(pw), 34)}")
    print(f"  entropy     {bits:.1f} bits")
    if word_count:
        print(f"  pool        {len(_wordlist())} words (guessed as words, not chars)")
    else:
        print(f"  pool        {pool_size(pw)} characters")
    print(f"  length      {len(pw)}")
    print(f"  crack time  {crack_time(bits)}")
    print(f"  verdict     {verdict(bits)}")

    if breached is True:
        print("  BREACHED    found in local breach list — do not use")
    elif breached is None:
        print("  breach      skipped (no breached.txt present)")
    print()


# ── CLI ─────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Generate and analyze passwords.")
    ap.add_argument("-l", "--length", type=int, default=20)
    ap.add_argument("-n", "--number", type=int, default=1)
    ap.add_argument("--no-symbols", action="store_true")
    ap.add_argument("--words", type=int, metavar="N", help="passphrase of N words")
    ap.add_argument("--check", metavar="PASSWORD", help="analyze instead of generate")
    ap.add_argument("--quiet", action="store_true", help="print only, no report")
    args = ap.parse_args()

    if args.check:
        report(args.check)
        return

    for _ in range(args.number):
        pw = (generate_passphrase(args.words) if args.words
              else generate(args.length, not args.no_symbols))
        if args.quiet:
            print(pw)
        else:
            report(pw, word_count=args.words)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyboardInterrupt) as e:
        sys.exit(f"passforge: {e}" if str(e) else 1)
