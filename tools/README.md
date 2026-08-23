# IT automation tools

Five small command-line tools I built while working through an A.A.S. in
Information Technology and preparing for CompTIA Network+. Each one solves
a problem I've watched a help desk actually deal with.

These are learning projects. I can walk through every line of them, which
matters more to me than making them look bigger than they are.

## The tools

| Folder | What it does |
|---|---|
| `phishcheck/` | Reads a suspicious email and reports what's wrong with it |
| `lockout-lens/` | Reads auth logs, spots brute-force patterns, writes firewall rules |
| `passforge/` | Generates and scores passwords by real entropy |
| `lockbox/` | Encrypts a file before it's sent, detects tampering |
| `sentinel-auth/` | A login flow with password hashing, 2FA, and lockout |

## Running them

```bash
pip install -r requirements.txt

python3 phishcheck/phishcheck.py phishcheck/samples/phish.eml
python3 lockout-lens/lockout_lens.py --scan lockout-lens/sample.log
python3 passforge/passforge.py -n 5
python3 lockbox/lockbox.py lock somefile.pdf
cd sentinel-auth && python3 app.py
```

## Tests

```bash
pytest test_all.py -v      # 26 tests
```

The tests that matter are the ones proving things *fail* correctly:
tampered files rejected, wrong passwords rejected, lockouts triggered,
allowlisted addresses never banned.

## Known limitations

Stated plainly, because they're real:

- **Lockout Lens is not an antivirus.** It filters by source address
  based on log behaviour. It does not inspect files or detect malware.
- **Sentinel Auth has no password reset flow**, which in a real system is
  usually the weakest part of authentication.
- **PassForge's breach list is small.** It demonstrates the check rather
  than providing real coverage.
- These are single-user learning tools, not production software.
