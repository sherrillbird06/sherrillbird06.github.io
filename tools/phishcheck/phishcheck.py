#!/usr/bin/env python3
"""
Phish Check — read a suspicious email and say what's wrong with it.

This came out of building the phishing module in the Help Desk Simulator.
That module teaches people what to look for; this checks a real message
against the same list.

Every finding is explained rather than just scored, because the point is
that the person reading the output learns the tell and catches the next
one without the tool.

Usage:
    python3 phishcheck.py suspicious.eml
    python3 phishcheck.py --folder ./reported     # batch a mailbox dump
"""

import argparse
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

# Domains that get impersonated most in the tickets I've read about.
COMMON_TARGETS = [
    "microsoft.com", "office365.com", "google.com", "apple.com",
    "amazon.com", "paypal.com", "netflix.com", "docusign.com",
    "dropbox.com", "adobe.com", "chase.com", "wellsfargo.com",
]

# Characters swapped in to make a domain read correctly at a glance.
LOOKALIKES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "$": "s",
    "rn": "m", "vv": "w", "l": "i",
}

URGENCY = [
    "urgent", "immediately", "within 24 hours", "account will be closed",
    "suspended", "verify your account", "confirm your identity",
    "unusual activity", "final notice", "action required", "expire",
    "click here", "failure to respond", "avoid termination",
]

SENSITIVE_ASKS = [
    "password", "ssn", "social security", "wire transfer", "gift card",
    "bank details", "routing number", "credentials", "login",
    "one-time code", "verification code", "mfa code",
]


class Finding:
    def __init__(self, weight, title, detail, teaches):
        self.weight = weight      # 1 low, 2 medium, 3 high
        self.title = title
        self.detail = detail
        self.teaches = teaches    # why this matters


def normalize(domain):
    """Collapse lookalike substitutions so paypa1.com reads as paypal.com."""
    d = domain.lower()
    for fake, real in LOOKALIKES.items():
        d = d.replace(fake, real)
    return d


def domain_of(address):
    return address.split("@")[-1].lower().strip(">") if "@" in address else ""


def check_sender(msg, findings):
    display, addr = parseaddr(msg.get("From", ""))
    from_domain = domain_of(addr)

    if not addr:
        findings.append(Finding(3, "No sender address",
            "The From header has no usable address.",
            "Legitimate mail always has one. Its absence means the header was forged badly."))
        return from_domain

    # Display name claims one company, address is somewhere else entirely.
    for target in COMMON_TARGETS:
        brand = target.split(".")[0]
        if brand in display.lower() and brand not in from_domain:
            findings.append(Finding(3, "Display name doesn't match the address",
                f'Shows as "{display}" but sends from {addr}.',
                "Mail clients show the display name and hide the address. "
                "Anyone can set the display name to anything."))
            break

    # Lookalike domain.
    normalized = normalize(from_domain)
    for target in COMMON_TARGETS:
        if normalized == target and from_domain != target:
            findings.append(Finding(3, "Lookalike domain",
                f"{from_domain} is built to read as {target}.",
                "Characters get swapped for ones that look the same at a glance — "
                "a 1 for an l, a 0 for an o, rn for m."))
            break

    # Non-ASCII in a domain is almost always a homograph attack.
    if any(ord(c) > 127 for c in from_domain):
        findings.append(Finding(3, "Non-English characters in the domain",
            f"{from_domain} contains characters outside the standard set.",
            "Cyrillic and Greek letters render identically to Latin ones. "
            "This is nearly always deliberate."))

    # Reply-to pointing somewhere else.
    _, reply_to = parseaddr(msg.get("Reply-To", ""))
    if reply_to and domain_of(reply_to) != from_domain:
        findings.append(Finding(3, "Reply-To goes to a different domain",
            f"Sent from {from_domain}, replies go to {domain_of(reply_to)}.",
            "The reply lands with the attacker while the original still looks legitimate. "
            "This is one of the strongest single indicators."))

    # Return-Path mismatch.
    _, return_path = parseaddr(msg.get("Return-Path", ""))
    if return_path and domain_of(return_path) != from_domain:
        findings.append(Finding(2, "Return-Path doesn't match the sender",
            f"From is {from_domain}, Return-Path is {domain_of(return_path)}.",
            "The Return-Path is set by the actual sending server and is harder to fake "
            "than the From header."))

    return from_domain


def check_authentication(msg, findings):
    """SPF, DKIM, and DMARC results are already in the headers if the
    receiving server checked them. Most people never look."""
    results = (msg.get("Authentication-Results", "") or "").lower()
    if not results:
        findings.append(Finding(1, "No authentication results",
            "The receiving server didn't record SPF, DKIM, or DMARC.",
            "Not suspicious on its own, but it means one useful check is unavailable."))
        return

    for mech, meaning in (
        ("spf",   "whether the sending server was authorized for that domain"),
        ("dkim",  "whether the message was signed and unmodified"),
        ("dmarc", "what the domain owner says to do when the other two fail"),
    ):
        if f"{mech}=fail" in results or f"{mech}=softfail" in results:
            findings.append(Finding(3, f"{mech.upper()} failed",
                f"The header records {mech}=fail.",
                f"{mech.upper()} checks {meaning}. A failure means the domain "
                "very likely did not send this."))


def check_links(msg, findings):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""

    # Anchor text that looks like a URL but points somewhere else.
    for href, text in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                                 body, re.I | re.S):
        clean = re.sub(r"<[^>]+>", "", text).strip()
        if re.match(r"https?://", clean, re.I):
            shown = domain_of(clean.replace("https://", "@").replace("http://", "@"))
            actual = domain_of(href.replace("https://", "@").replace("http://", "@"))
            if shown and actual and shown.split("/")[0] != actual.split("/")[0]:
                findings.append(Finding(3, "Link text doesn't match its destination",
                    f"Displays {shown.split('/')[0]}, actually goes to {actual.split('/')[0]}.",
                    "Hovering a link shows the real destination. On mobile, press and hold."))
                break

    # IP address instead of a hostname.
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", body):
        findings.append(Finding(3, "Link points to a raw IP address",
            "A URL uses an IP instead of a domain name.",
            "Real companies use their domain. An IP skips the check entirely."))

    # Urgency and sensitive asks.
    low = body.lower()
    hits = [p for p in URGENCY if p in low]
    if len(hits) >= 2:
        findings.append(Finding(2, "Pressure language",
            f"Found: {', '.join(hits[:4])}.",
            "Urgency exists to stop you thinking. Real IT and finance departments "
            "give you time."))

    asks = [p for p in SENSITIVE_ASKS if p in low]
    if asks:
        findings.append(Finding(3, "Asks for something sensitive",
            f"Mentions: {', '.join(asks[:4])}.",
            "No legitimate support desk asks for a password or an MFA code. "
            "Ever. That request alone is enough to report it."))

    return body


def check_attachments(msg, findings):
    RISKY = {".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd",
             ".iso", ".img", ".hta", ".lnk", ".ps1"}
    MACRO = {".docm", ".xlsm", ".pptm"}

    for part in msg.walk():
        name = part.get_filename()
        if not name:
            continue
        ext = Path(name).suffix.lower()

        if ext in RISKY:
            findings.append(Finding(3, f"Executable attachment: {name}",
                f"{ext} files run code when opened.",
                "Almost no legitimate business email needs to send one."))
        elif ext in MACRO:
            findings.append(Finding(2, f"Macro-enabled document: {name}",
                f"{ext} can contain macros.",
                "Macros are code. If a document asks you to enable them, that's the attack."))

        # Double extension hiding the real type.
        if name.lower().count(".") > 1:
            parts = name.lower().split(".")
            if len(parts) > 2 and f".{parts[-1]}" in RISKY:
                findings.append(Finding(3, f"Double extension: {name}",
                    "The name hides the real file type.",
                    "invoice.pdf.exe shows as invoice.pdf when extensions are hidden, "
                    "which is the Windows default."))


def analyze(path):
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    findings = []
    check_sender(msg, findings)
    check_authentication(msg, findings)
    check_links(msg, findings)
    check_attachments(msg, findings)

    score = sum(f.weight for f in findings)
    return msg, findings, score


def verdict(score):
    if score == 0:  return "NOTHING FOUND", "No indicators. Not proof it's safe."
    if score <= 3:  return "LOW",     "Minor indicators. Worth a second look."
    if score <= 7:  return "MEDIUM",  "Several indicators. Treat as suspicious."
    return              "HIGH",       "Strong indicators. Report it, don't click it."


def report(path, msg, findings, score):
    label, advice = verdict(score)

    print(f"\n  {path.name}")
    print(f"  {'─' * 60}")
    print(f"  From     {msg.get('From', '(none)')}")
    print(f"  Subject  {msg.get('Subject', '(none)')}")
    print(f"\n  VERDICT  {label}   (score {score})")
    print(f"  {advice}\n")

    if not findings:
        print("  No indicators matched.\n")
        return

    for f in sorted(findings, key=lambda x: -x.weight):
        mark = {3: "HIGH", 2: "MED ", 1: "LOW "}[f.weight]
        print(f"  [{mark}] {f.title}")
        print(f"         {f.detail}")
        print(f"         Why: {f.teaches}\n")


def main():
    ap = argparse.ArgumentParser(description="Analyze an email for phishing indicators.")
    ap.add_argument("file", nargs="?", type=Path)
    ap.add_argument("--folder", type=Path, help="analyze every .eml in a folder")
    args = ap.parse_args()

    if args.folder:
        files = sorted(args.folder.glob("*.eml"))
        if not files:
            sys.exit(f"phishcheck: no .eml files in {args.folder}")
        for f in files:
            msg, findings, score = analyze(f)
            report(f, msg, findings, score)
        print(f"  {len(files)} message(s) analyzed.\n")
    elif args.file:
        if not args.file.is_file():
            sys.exit(f"phishcheck: no such file: {args.file}")
        report(args.file, *analyze(args.file))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
