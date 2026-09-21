# Hash Collision Analyzer

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

Two educational cybersecurity tools that demonstrate **hash collisions**, the
**birthday paradox** and the **avalanche effect** — the same concepts at two
very different complexity levels.

Written in Python 3 with **zero third-party dependencies**.

---

## ⚠ Honesty statement

These tools **never break a real hash function.**

Every collision experiment runs against a **deliberately truncated digest**
(8–32 bits). The two colliding inputs share only the first *n* bits of the
digest; their complete MD5 / SHA-1 / SHA-256 / SHA-512 hashes remain different,
and both programs print and verify that fact on every result.

* ❌ Wrong: "I found a SHA-256 collision."
* ✅ Right: "I found a collision in a **16-bit truncation** of SHA-256."

Neither tool creates malicious colliding executables, certificates,
authentication tokens or signed documents. The advanced version can *verify* a
known harmless collision pair supplied to it, which is a read-only check.

---

## Three ways in

| | **Simple** | **Advanced** | **Dashboard** |
|---|---|---|---|
| Folder | [`hash-collision-simple/`](hash-collision-simple/) | [`hash-collision-pro/`](hash-collision-pro/) | [`hash-collision-web/`](hash-collision-web/) |
| Entry point | `hash_collision.py` | `collision_analyzer.py` | `index.html` |
| Size | 1 file, ~290 lines | 8 modules, ~2,200 lines | 1 file, no dependencies |
| Interface | Terminal menu | 9-subcommand CLI **+** interactive menu | Browser |
| Algorithms | MD5, SHA-256 | MD5, SHA-1, SHA-256, SHA-512 | MD5, SHA-1, SHA-256, SHA-512 |
| Files | — | Chunked hashing, file comparison | — |
| Statistics | Attempts, time | min / max / average / median / stdev + theory ratio | Attempts vs birthday bound |
| Reports | — | JSON, CSV, TXT | — |
| Tests | — | 48 unit tests | 9 MD5 test vectors verified |
| Best for | Learning and explaining the concept | Project demo, portfolio, presentation | Showing someone, live |

All three implement the **same** core experiment: generate random strings,
truncate their digests to *n* bits, store `truncated → input` in a dictionary,
and stop when a value repeats with a *different* input.

---

## The dashboard

A single self-contained HTML page — no build step, no server, no libraries.
Open it in a browser and everything runs locally; nothing is uploaded.

```bash
cd hash-collision-web
xdg-open index.html
```

If your browser blocks the Web Crypto API on `file://` URLs, serve the folder
instead and open `http://localhost:8000`:

```bash
python3 -m http.server 8000
```

Five instruments:

| Tab | What it does |
|-----|--------------|
| **Digest** | Type anything, see MD5, SHA-1, SHA-256 and SHA-512 at once, with the first 16 bits highlighted and a truncation table for 8/12/16/20/24 bits |
| **Compare** | Two texts, two pasted digests, or **verify** that a candidate text produces a digest you were given — with the shared leading bits counted |
| **Identify** | Paste a digest and it works out which algorithm fits its length, and flags the broken ones |
| **Collision lab** | Runs the birthday search live in the browser, then shows both inputs, both full digests, and the shared prefix highlighted |
| **Avalanche** | A 256-cell grid of the digest, one square per bit, copper where the bit flipped |

The avalanche and truncation figures match the Python tools exactly — `hello`
vs `Hello` gives 125 of 256 bits changed (48.83 %) in both.

MD5 is implemented in the page itself, because the Web Crypto API deliberately
omits it; that implementation is checked against all nine RFC 1321 test vectors
plus the 55/56/64-byte padding boundaries.

---

## Quick start

### Kali Linux / Debian / Ubuntu

```bash
sudo apt update
sudo apt install python3 git -y
git clone https://github.com/kk4sh2/hash-collision-analyzer.git
cd hash-collision-analyzer
```

**Simple version:**

```bash
cd hash-collision-simple
python3 hash_collision.py
```

**Advanced version:**

```bash
cd hash-collision-pro
chmod +x install.sh
./install.sh
python3 collision_analyzer.py --help
```

---

## One launcher for everything

`hca` wraps every part of the project so you don't retype long commands.

```bash
chmod +x hca
./hca help
```

Put it on your PATH once and it works from any directory:

```bash
sudo ln -s "$PWD/hca" /usr/local/bin/hca
```

| Command | Does |
|---------|------|
| `hca demo` | The full teacher demonstration — six steps, paused between each so you can talk. `--auto` removes the pauses |
| `hca collision 16` | Collision experiment at 16 bits |
| `hca bench 20` | 20-run benchmark |
| `hca avalanche` | Avalanche on `hello` / `Hello` |
| `hca hash "text"` | Hash some text |
| `hca file PATH` | Hash a file |
| `hca compare A B` | Compare two texts |
| `hca algos` | Algorithm comparison table |
| `hca report 20` | Benchmark straight to a timestamped JSON report |
| `hca web` | Serve the dashboard on <http://localhost:8000> |
| `hca menu` / `hca simple` | Interactive menus for the advanced / beginner tool |
| `hca install` / `hca test` | Run the installer / the 48 unit tests |
| `hca clean` | Remove `__pycache__` and generated reports |
| `hca raw ...` | Pass anything straight through to `collision_analyzer.py` |

It finds a working Python 3 itself, so it also runs under Git Bash on Windows
where `python3` may be a non-functional Microsoft Store stub.

---

## Advanced version at a glance

```bash
python3 collision_analyzer.py hash-text "hello" --algorithm md5
python3 collision_analyzer.py hash-file example.txt --algorithm sha256
python3 collision_analyzer.py compare-text "hello" "world" --algorithm sha256
python3 collision_analyzer.py compare-files file1.txt file2.txt --algorithm sha256
python3 collision_analyzer.py collision-demo --algorithm sha256 --bits 16
python3 collision_analyzer.py benchmark --algorithm sha256 --bits 16 --runs 20
python3 collision_analyzer.py avalanche "hello" "Hello" --algorithm sha256
python3 collision_analyzer.py algorithms
python3 collision_analyzer.py interactive
```

Sample output:

```
[!] COLLISION FOUND

Input A:
PjN0MEQ7

Input B:
T5GOBUSZ

Full Hash A:
564c1758dde87b15200a95440e693024e3d3f61036fd683da6fef59df039083d

Full Hash B:
564c198b68e3c95e4fc93ec68f6b22fec429222f5e48eeb95e9dd464b597f9c6

Truncated Hash A:
564C

Truncated Hash B:
564C

Attempts:
109

Expected birthday-bound:
~256 attempts  (2^(16/2); precise expectation 321)

------------------------------------------------------------
NOTE:
The COMPLETE SHA-256 hashes are different.

This experiment intentionally shortened the hash to 16 bits so that
the birthday-collision principle can be demonstrated on normal hardware.
This is NOT a break of SHA-256.
------------------------------------------------------------
```

Both digests start `564c1…` and then diverge — only the first 16 bits match.

---

## The mathematics

For an n-bit hash there are `2^n` possible digests, but a collision becomes
likely after only about `2^(n/2)` random inputs, because every new input is
compared against **all** previous ones.

| Hash size | Possible outputs | Birthday bound `2^(n/2)` |
|-----------|-----------------:|-------------------------:|
| 8 bits | 256 | ~16 attempts |
| 16 bits | 65,536 | ~256 attempts |
| 24 bits | 16,777,216 | ~4,096 attempts |
| 128 bits (MD5) | 3.4 × 10³⁸ | ~2⁶⁴ |
| 256 bits (SHA-256) | 1.2 × 10⁷⁷ | ~2¹²⁸ |

Measured over 20 runs at 16 bits: min 122, max 743, average 364.9, median
356.5 — against a theoretical expectation of 320.85 (ratio 1.14).

### Correct bit truncation

One hex character is 4 bits, so slicing hex characters only works for multiples
of 4. Both tools shift the digest integer instead, which is exact for any bit
count:

```python
digest_int = int.from_bytes(digest, "big")
truncated  = digest_int >> (digest_size - requested_bits)
```

---

## Collision vs preimage — three different problems

| Attack | Attacker controls | Ideal cost (n bits) | SHA-256 |
|--------|-------------------|--------------------:|--------:|
| Preimage — given `h`, find `x` with `H(x) = h` | nothing | 2^n | 2²⁵⁶ |
| Second preimage — given `x`, find `y ≠ x` with `H(y) = H(x)` | one input | 2^n | 2²⁵⁶ |
| Collision — find any `x ≠ y` with `H(x) = H(y)` | **both** inputs | 2^(n/2) | 2¹²⁸ |

MD5 and SHA-1 are broken **for collisions** by differential mathematics (SHA-1
publicly, in 2017 — *SHAttered*), not by the brute force these tools perform.
Their preimage resistance is far less damaged. "MD5 is broken" does **not** mean
an MD5 digest can be reversed into a password.

---

## Documentation

* [`hash-collision-simple/README.md`](hash-collision-simple/README.md) — code
  walkthrough, theory, and a 3–5 minute demonstration script.
* [`hash-collision-pro/README.md`](hash-collision-pro/README.md) — full command
  reference, report format, safety limits, test coverage, and an 8-minute
  technical demonstration script.

---

## Tests

```bash
cd hash-collision-pro
python3 -m unittest discover -s tests -v
```

```
Ran 48 tests in 0.084s

OK
```

Covering known-answer digests, bit-exact truncation (including the
non-multiple-of-4 case where hex slicing fails), the birthday formulas, chunked
file hashing, every error path, report export, every CLI subcommand — and a test
asserting that the two full digests in any collision result are always
different, so the tool can never overstate what it found.

---

## Ethics

Educational and defensive use only. These tools generate random strings and
truncate digests; they contain no differential-collision implementation for MD5
or SHA-1 and cannot forge documents, certificates, tokens or executables. Use
hashing tools only on data you own or are authorised to test.

When presenting results, always state the truncation size.

---

## License

MIT — see [LICENSE](LICENSE).
