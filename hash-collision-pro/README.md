# Hash Collision Analyzer Pro

A modular, professional-grade **educational** cybersecurity tool for Kali Linux
that demonstrates hash collisions, the birthday paradox and the avalanche
effect across MD5, SHA-1, SHA-256 and SHA-512.

Pure Python 3 standard library. No third-party dependencies.

```
python3 collision_analyzer.py collision-demo --algorithm sha256 --bits 16
```

---

## ⚠ Scope and honesty statement

This tool **never breaks a real hash function.**

Every collision experiment runs against a **deliberately truncated digest**
(8–32 bits). The two colliding inputs share only the first *n* bits; their
complete MD5/SHA-1/SHA-256/SHA-512 digests remain different, and the tool
prints and verifies that fact on every report.

* ❌ Wrong: "I found a SHA-256 collision."
* ✅ Right: "I found a collision in a **16-bit truncation** of SHA-256."

The tool does **not** create malicious colliding executables, certificates,
authentication tokens or signed documents. It can *verify* a known harmless
collision pair supplied to it (`compare-files`), which is a read-only check.

---

## Contents

1. [Features](#1-features)
2. [Project structure](#2-project-structure)
3. [Installation on Kali Linux](#3-installation-on-kali-linux)
4. [Command reference](#4-command-reference)
5. [Interactive mode](#5-interactive-mode)
6. [Reports](#6-reports)
7. [How the collision search works](#7-how-the-collision-search-works)
8. [Correct bit truncation](#8-correct-bit-truncation)
9. [Birthday paradox mathematics](#9-birthday-paradox-mathematics)
10. [Avalanche effect](#10-avalanche-effect)
11. [Algorithm information](#11-algorithm-information)
12. [Security concepts](#12-security-concepts)
13. [Safety limits and error handling](#13-safety-limits-and-error-handling)
14. [Tests](#14-tests)
15. [Teacher demonstration script](#15-teacher-demonstration-script)
16. [Ethics](#16-ethics)

---

## 1. Features

| Area | Capability |
|------|-----------|
| Hashing | Text, files, MD5 / SHA-1 / SHA-256 / SHA-512 |
| Files | Chunked (64 KiB) streaming — constant memory on multi-GB files |
| Comparison | Two texts, two files, identical-digest detection, real-collision detection |
| Collisions | Birthday search on truncated digests (8/12/16/20/24 bits, up to 32) |
| Mathematics | Birthday bound `2^(n/2)`, precise expectation `√(πN/2)`, 50 % point, probability at *k* attempts |
| Benchmark | N automated runs; min / max / average / median / stdev attempts, per-run and total timing, observed-vs-theory ratio |
| Avalanche | Changed-bit count, percentage, deviation from the ideal 50 %, optional bit map |
| Reports | JSON, CSV and TXT export from every command |
| Interfaces | Full argparse CLI plus a menu-driven interactive mode |
| Engineering | Type hints, docstrings, dataclasses, 48 unit tests, installer, zero dependencies |
| Safety | `--max-attempts`, run caps, truncation cap, clean error messages, no tracebacks |

---

## 2. Project structure

```
hash-collision-pro/
│
├── collision_analyzer.py          CLI entry point and interactive mode
├── modules/
│   ├── __init__.py                package exports and version
│   ├── hashing.py                 algorithms, digests, bit-exact truncation
│   ├── collision.py               birthday search + collision mathematics
│   ├── benchmark.py               repeated experiments and statistics
│   ├── avalanche.py               bit-difference measurement
│   ├── file_hasher.py             chunked file hashing and comparison
│   └── reporting.py               terminal rendering and JSON/CSV/TXT export
│
├── reports/                       generated reports land here
├── samples/                       sample files for the file commands
├── tests/
│   └── test_collision_analyzer.py 48 unit tests
│
├── install.sh
├── requirements.txt
└── README.md
```

Dependency direction (no cycles):

```
collision_analyzer.py
        │
        ├── reporting ──┬── collision ── hashing
        │               ├── benchmark ── collision
        │               └── avalanche ──┬── hashing
        │                               └── file_hasher ── hashing
        └── (same modules directly)
```

---

## 3. Installation on Kali Linux

```bash
sudo apt update
sudo apt install python3 -y
```

```bash
cd hash-collision-pro
chmod +x install.sh
./install.sh
```

The installer checks the Python version (3.8+), creates `reports/` and
`samples/`, makes the entry point executable and runs the test suite.

Manual route:

```bash
cd hash-collision-pro
python3 collision_analyzer.py --help
```

Optional alias:

```bash
echo "alias hca='python3 $PWD/collision_analyzer.py'" >> ~/.bashrc
source ~/.bashrc
```

---

## 4. Command reference

Global flags (accepted before **or** after the subcommand):

```
--version      print the version
--no-color     disable ANSI colour
-o, --output   write a report (extension selects the format)
--format       force json / csv / txt
```

### hash-text

```bash
python3 collision_analyzer.py hash-text "hello" --algorithm md5
python3 collision_analyzer.py hash-text "hello" --algorithm sha256 --bits 16
```

### hash-file

```bash
python3 collision_analyzer.py hash-file samples/sample1.txt --algorithm sha256
python3 collision_analyzer.py hash-file big.iso --algorithm sha512 --chunk-size 1048576
```

### compare-text

```bash
python3 collision_analyzer.py compare-text "hello" "world" --algorithm sha256
```

### compare-files

```bash
python3 collision_analyzer.py compare-files samples/sample1.txt samples/sample2.txt --algorithm sha256
python3 collision_analyzer.py compare-files samples/sample1.txt samples/sample1_copy.txt
```

The tool distinguishes three outcomes: different digests, identical digests
with identical bytes (copies — **not** a collision), and identical digests with
different bytes (**a real collision**).

### collision-demo

```bash
python3 collision_analyzer.py collision-demo --algorithm sha256 --bits 16
python3 collision_analyzer.py collision-demo --algorithm md5 --bits 24 --max-attempts 500000
python3 collision_analyzer.py collision-demo --bits 16 --seed 7      # reproducible
```

Real output:

```
[*] Searching for a 16-bit truncated collision in SHA-256 (expected ~256 attempts)...

============================================================
                    COLLISION EXPERIMENT
============================================================

Algorithm: SHA-256
Full digest size: 256 bits
Effective hash size: 16 bits
Search space: 2^16 = 65,536 values

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

Collision probability at this attempt count:
8.59%

Elapsed time:
0.000466 seconds

Throughput:
233,805 hashes/second

------------------------------------------------------------
NOTE:
The COMPLETE SHA-256 hashes are different.

This experiment intentionally shortened the hash to 16 bits so that
the birthday-collision principle can be demonstrated on normal hardware.
This is NOT a break of SHA-256.
------------------------------------------------------------
[+] Verified: the two full digests differ, so this is a truncated-hash collision only.
```

Note the two full digests both start `564c1…` / `564c1…` — the first 16 bits
(`564C`) match, and everything after diverges.

### benchmark

```bash
python3 collision_analyzer.py benchmark --algorithm sha256 --bits 16 --runs 20
python3 collision_analyzer.py benchmark --algorithm sha256 --bits 16 --runs 20 --output reports/report.json
python3 collision_analyzer.py benchmark --bits 20 --runs 50 --quiet --seed 1
```

### avalanche

```bash
python3 collision_analyzer.py avalanche "hello" "Hello" --algorithm sha256
python3 collision_analyzer.py avalanche "hello" "Hello" --bitmap
python3 collision_analyzer.py avalanche a.txt b.txt --files --algorithm sha256
```

### algorithms

```bash
python3 collision_analyzer.py algorithms
```

### interactive

```bash
python3 collision_analyzer.py interactive
```

---

## 5. Interactive mode

```
========================================
       HASH COLLISION ANALYZER PRO
========================================

[1] Hash text
[2] Hash file
[3] Compare text
[4] Compare files
[5] Collision demonstration
[6] Collision benchmark
[7] Avalanche test
[8] Algorithm information
[9] Export report
[0] Exit

Choice:
```

Every prompt shows a default in brackets; pressing Enter accepts it. Option
`[9]` exports the most recent result, or runs a fresh benchmark if nothing has
been computed yet.

---

## 6. Reports

Any command accepts `--output PATH`; the extension chooses the format, or
`--format` forces one.

```bash
python3 collision_analyzer.py benchmark \
  --algorithm sha256 \
  --bits 16 \
  --runs 20 \
  --output reports/report.json
```

A benchmark report records:

| Field | Meaning |
|-------|---------|
| `date` | ISO-8601 timestamp with timezone |
| `algorithm`, `digest_size_bits` | e.g. SHA-256, 256 |
| `effective_size_bits`, `search_space` | e.g. 16, 65536 |
| `runs_requested`, `runs_completed`, `failed_runs` | experiment counts |
| `attempts_per_run`, `runs_detail` | raw data per run |
| `minimum_attempts`, `maximum_attempts` | extremes |
| `average_attempts`, `median_attempts`, `stdev_attempts` | statistics |
| `execution_times`, `total_seconds`, `average_seconds`, `median_seconds` | timing |
| `birthday_bound_simple`, `birthday_bound_precise`, `attempts_for_50_percent` | theory |
| `observed_over_theory` | experiment ÷ theory (≈1.0 confirms the model) |
| `is_full_hash_collision` | always `false`, with an explanatory `note` |

**JSON** — machine readable, full structure.
**CSV** — a `metric,value` summary block, a blank line, then a
`run,attempts,elapsed_seconds` table (opens cleanly in LibreOffice Calc).
**TXT** — the exact terminal report with ANSI colour stripped, ideal for
pasting into a lab write-up.

---

## 7. How the collision search works

`modules/collision.py::find_collision` is a textbook birthday attack:

```python
seen: Dict[int, str] = {}          # truncated digest -> original input

while attempts < max_attempts:
    attempts += 1
    candidate = generate_random_string(input_length, rng)   # 1. generate
    digest    = digest_text(candidate, algorithm)           # 2. hash
    truncated = truncate_digest(digest, bits)               # 3. truncate

    previous = seen.get(truncated)                          # 4. look up
    if previous is not None:
        if previous != candidate:                           # 5. verify distinct
            return CollisionResult(...)                     # 6. report
    else:
        seen[truncated] = candidate                         # 5b. store
```

Why a dictionary rather than comparing every pair:

| Candidates | All-pairs comparisons | Dictionary lookups |
|-----------:|----------------------:|-------------------:|
| 256 | 32,640 | 256 |
| 4,096 | 8,386,560 | 4,096 |
| 65,536 | 2,147,450,880 | 65,536 |

Dictionary lookup is O(1), so the search is **O(n)** instead of **O(n²)**.

The check `previous != candidate` matters: a PRNG can emit the same string
twice, and one input hashing to its own digest is not a collision.

---

## 8. Correct bit truncation

One hexadecimal character is 4 bits, so slicing hex characters can only express
multiples of 4. Truncation is therefore done on the integer value:

```python
digest_int = int.from_bytes(digest, "big")
truncated  = digest_int >> (digest_size - requested_bits)
```

Worked example with the digest prefix `A8 3F …` (`1010 1000 0011 1111 …`):

| Requested bits | Binary kept | Value | Displayed |
|---------------:|-------------|-------|-----------|
| 4  | `1010` | 0xA | `A` |
| 8  | `1010 1000` | 0xA8 | `A8` |
| 10 | `1010 1000 00` | 0x2A0 | `2A0` |
| 12 | `1010 1000 0011` | 0xA83 | `A83` |
| 16 | `1010 1000 0011 1111` | 0xA83F | `A83F` |

The 10-bit case is exactly where naive hex slicing breaks — and it is covered
by `test_truncation_is_bit_exact`.

Supported sizes: **8, 12, 16, 20, 24** (the course set), any value 1–32 is
accepted; above 32 bits the tool refuses for resource safety.

---

## 9. Birthday paradox mathematics

For an n-bit hash there are `2^n` possible outputs, but a collision becomes
likely after only about `2^(n/2)` random inputs, because every new input is
compared against **all** previous ones — the number of pairs grows as
`k(k-1)/2`.

Probability of at least one collision after *k* draws from `N = 2^n` values:

```
P(collision) ≈ 1 - e^(-k(k-1) / 2N)
```

Key quantities the tool reports:

| Quantity | Formula | 16-bit value |
|----------|---------|-------------:|
| Search space `N` | `2^n` | 65,536 |
| Classroom bound | `2^(n/2)` | 256 |
| Expected first repeat | `√(πN/2) ≈ 1.2533·√N` | 320.9 |
| 50 % probability point | `√(2 ln2 · N) ≈ 1.1774·√N` | 301.4 |

| Hash size | Possible outputs | Birthday bound |
|-----------|-----------------:|---------------:|
| 8 bits | 256 | ~16 attempts |
| 12 bits | 4,096 | ~64 attempts |
| 16 bits | 65,536 | ~256 attempts |
| 20 bits | 1,048,576 | ~1,024 attempts |
| 24 bits | 16,777,216 | ~4,096 attempts |
| 128 bits (MD5) | 3.4 × 10³⁸ | ~2⁶⁴ |
| 256 bits (SHA-256) | 1.2 × 10⁷⁷ | ~2¹²⁸ |

Theory versus experiment, from a real 20-run benchmark at 16 bits:

```
Minimum attempts  122
Maximum attempts  743
Average attempts  364.90
Median attempts   356.50
Birthday bound    256          (2^(16/2))
Precise expect.   320.85       (√(πN/2))
Observed / theory 1.137
```

The distribution is wide (122 → 743 in the same experiment), which is why the
benchmark reports median and standard deviation alongside the mean, and why a
single run proves nothing on its own.

---

## 10. Avalanche effect

```bash
python3 collision_analyzer.py avalanche "hello" "Hello" --algorithm sha256
```

```
Input bits changed:
1 bit(s)

Hash A:
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

Hash B:
185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969

Changed bits:
125 / 256

Percentage:
48.83%

Ideal:
50.00% (deviation -1.17 points)
```

`'h'` is `0x68`, `'H'` is `0x48` — a single flipped bit in the input changes
**125 of the 256 output bits**, 48.83 %.

The measurement is a Hamming distance:

```python
xor = int.from_bytes(digest_a, "big") ^ int.from_bytes(digest_b, "big")
changed = bin(xor).count("1")
```

Cryptographic hashes are designed so each output bit flips with probability
1/2 for any input change. Without this property an attacker could learn
information about the input from the digest, and similar inputs would produce
similar hashes — which would make password hashes and integrity checks useless.

`--bitmap` prints which of the 256 bits flipped.

---

## 11. Algorithm information

```bash
python3 collision_analyzer.py algorithms
```

```
Algorithm  Output Size  Generic Collision Security  Status  CLI flag
------------------------------------------------------------------------------
MD5        128 bits     Broken                      BROKEN  --algorithm md5
SHA-1      160 bits     Broken                      BROKEN  --algorithm sha1
SHA-256    256 bits     ~2^128                      SECURE  --algorithm sha256
SHA-512    512 bits     ~2^256                      SECURE  --algorithm sha512
```

* **MD5** (128-bit) — practical collisions since 2004; chosen-prefix collisions
  are cheap today. Broken for any security purpose.
* **SHA-1** (160-bit) — publicly broken in 2017 (*SHAttered*: two PDFs with the
  same SHA-1). Removed from TLS certificates and deprecated for signatures.
* **SHA-256** / **SHA-512** — no practical known full collision attack. The
  generic birthday cost of 2¹²⁸ / 2²⁵⁶ operations is out of reach of any
  existing or foreseeable hardware.

Important nuance: MD5 and SHA-1 are broken **for collisions** by mathematical
(differential) attacks, not by the brute force this tool performs. Their
*preimage* resistance is much less damaged — a different and harder problem.

---

## 12. Security concepts

**Hash** — a function `H` mapping arbitrary-length input to a fixed-length
digest. Deterministic, fast to compute, infeasible to invert.

**Collision** — two different inputs with the same digest:

```
x != y   and   H(x) = H(y)
```

Collisions must exist (pigeonhole principle: infinite inputs, finite digests).
Collision *resistance* means nobody can find one efficiently.

**Preimage attack** — given a digest `h`, find any `x` with `H(x) = h`.
You do not control the target. Cost for an ideal n-bit hash: `2^n`.

**Second-preimage attack** — given a *specific* `x`, find `y != x` with
`H(y) = H(x)`. The first input is fixed for you. Cost: `2^n`.

**Collision attack** — find *any* pair `x != y` with `H(x) = H(y)`. The
attacker chooses **both** inputs, which is why the birthday paradox applies.
Cost: `2^(n/2)`.

| Attack | Attacker controls | Ideal cost (n bits) | SHA-256 |
|--------|-------------------|--------------------:|--------:|
| Preimage | nothing (target given) | 2^n | 2²⁵⁶ |
| Second preimage | one input (other given) | 2^n | 2²⁵⁶ |
| Collision | both inputs | 2^(n/2) | 2¹²⁸ |

These are **different problems**. "MD5 is broken" means collisions are easy —
it does *not* mean you can reverse an MD5 digest back to a password. Conversely,
a hash can be collision-broken while remaining preimage-resistant.

Why it matters in practice: digital signatures sign a *hash*, so a collision
lets an attacker get a benign document signed and transplant the signature onto
a malicious one with the same digest. That is exactly the attack SHA-1's break
enabled, and why certificate authorities moved to SHA-256.

---

## 13. Safety limits and error handling

| Limit | Value | Why |
|-------|-------|-----|
| `MAX_TRUNCATION_BITS` | 32 | Bigger searches can exhaust RAM/time |
| `DEFAULT_MAX_ATTEMPTS` | 2,000,000 | Keeps a single demo interactive |
| `ABSOLUTE_MAX_ATTEMPTS` | 20,000,000 | Hard ceiling on the `seen` dictionary |
| `MAX_RUNS` | 1,000 | Caps benchmark duration |
| `CHUNK_SIZE` | 65,536 bytes | Constant memory when hashing files |
| `--max-attempts` | user-set | Per-run override inside the hard ceiling |

Errors are reported as one clean line and a non-zero exit code — never a
traceback:

```bash
$ python3 collision_analyzer.py hash-file nope.txt
[x] File does not exist: nope.txt        # exit code 1

$ python3 collision_analyzer.py hash-file samples
[x] A directory was supplied instead of a file: samples

$ python3 collision_analyzer.py hash-text hi --algorithm rot13
collision_analyzer.py: error: argument -a/--algorithm: invalid choice: 'rot13'
```

Handled: missing file, directory instead of file, permission denied, unreadable
special file, oversized file, unsupported algorithm, out-of-range bits/runs/
attempts, unwritable report path, unsupported report format, Ctrl+C (exit 130),
broken pipe.

Exit codes: `0` success, `1` handled error, `2` bad arguments or no collision
found within the ceiling, `130` interrupted.

---

## 14. Tests

```bash
python3 -m unittest discover -s tests -v
python3 tests/test_collision_analyzer.py
```

```
Ran 48 tests in 0.084s

OK
```

Coverage: known-answer digests for all four algorithms, bit-exact truncation
(including the non-nibble 10-bit case), truncation limits, birthday formulas,
collision search success, reproducibility by seed, attempt ceilings, **the
guarantee that full digests differ**, benchmark statistics ordering,
report-payload keys, Hamming distance, avalanche bounds, chunked file hashing
(tiny vs default chunks), file error paths, copies-are-not-collisions, JSON/CSV/
TXT export, disclaimer presence in every rendered report, and every CLI
subcommand end to end.

---

## 15. Teacher demonstration script

About 8 minutes. Run from the project directory.

**Step 0 — the structure (30 s)**

```bash
tree hash-collision-pro    # or: ls -R
```

> "The project is modular: hashing, collision search, benchmarking, avalanche
> testing, file hashing and reporting are separate modules, with a CLI on top
> and a unit-test suite underneath. Nothing outside the standard library."

**Step 1 — hash text (45 s)**

```bash
python3 collision_analyzer.py hash-text "cybersecurity" --algorithm sha256
```

> "A hash function maps any input to a fixed-length fingerprint — 256 bits,
> 64 hex characters, always. It is deterministic and one-way: trivial to
> compute forwards, infeasible to reverse."

**Step 2 — avalanche (90 s)**

```bash
python3 collision_analyzer.py avalanche "cybersecurity" "Cybersecurity" --algorithm sha256
```

> "I changed one letter — 'c' to 'C', which is a single bit in ASCII. The tool
> confirms 1 input bit changed, and reports 134 of the 256 output bits
> flipped — 52.34 %. That is the avalanche effect. A good hash makes every
> output bit flip with probability one half, so the digest reveals nothing
> about the input and similar inputs do not get similar hashes."

Add `--bitmap` if they want to see which bits moved.

**Step 3 — collision demo (2 min)**

```bash
python3 collision_analyzer.py collision-demo --algorithm sha256 --bits 16
```

> "Now the core experiment. I compute full SHA-256, then keep only the first
> 16 bits — 65,536 possible values. I generate random strings, store each
> truncated digest in a dictionary as `truncated → input`, and stop as soon as
> a value repeats with a different input. The dictionary makes this O(n)
> instead of comparing every pair, which would be O(n²).
>
> It found a collision in a few hundred attempts, not 65,536 — that is the
> birthday paradox: collisions appear after about the square root of the space,
> 2^(n/2).
>
> Look at the two full hashes on screen: **they are different.** Only the first
> 16 bits match. I have not broken SHA-256 — breaking it would take about 2¹²⁸
> operations. I shortened the hash deliberately so the principle is
> demonstrable on a laptop."

**Step 4 — benchmark (2 min)**

```bash
python3 collision_analyzer.py benchmark --algorithm sha256 --bits 16 --runs 20
```

> "One run proves nothing, so this repeats the experiment 20 times and reports
> minimum, maximum, average, median and standard deviation, next to the
> theoretical prediction. The average lands close to the expected value of about
> 321, giving an observed-over-theory ratio near 1.0 — the mathematics predicts
> reality. Notice the spread: the distribution is heavily skewed, which is
> exactly why I report the median and the standard deviation too."

**Step 5 — reports (45 s)**

```bash
python3 collision_analyzer.py benchmark --algorithm sha256 --bits 16 --runs 20 --output reports/report.json
cat reports/report.json | head -30
```

> "Every command can export JSON, CSV or TXT, with the full parameter set and
> raw per-run data, so the experiment is reproducible and the numbers can go
> straight into a lab report or a spreadsheet. `--seed` makes a run
> bit-for-bit repeatable."

**Step 6 — algorithm comparison (45 s)**

```bash
python3 collision_analyzer.py algorithms
```

> "MD5 and SHA-1 are broken for collisions — by clever differential
> mathematics, not by the brute force I just showed. SHA-1 fell publicly in
> 2017 with two PDFs sharing one digest. SHA-256 and SHA-512 have no practical
> collision attack. And collision resistance is not the same as preimage
> resistance: those are separate problems with separate costs."

**Step 7 — engineering (45 s)**

```bash
python3 -m unittest discover -s tests -q
```

> "48 unit tests: known-answer digests, the truncation mathematics including
> the tricky non-multiple-of-4 case, the birthday formulas, the file error
> paths, every CLI subcommand — and a test that asserts the two full digests
> in a collision result are always different, so the tool can never overstate
> what it found."

**Likely questions**

*"Could this break a real password hash?"*
> "No. It searches a truncated digest. Full SHA-256 needs about 2¹²⁸
> operations — more than all computers on Earth could do. And password
> cracking is a preimage problem, not a collision problem."

*"Why 16 bits?"*
> "It is the sweet spot: 65,536 possibilities, a collision in a fraction of a
> second, and 256 is a memorable birthday bound. `--bits 24` takes a few
> thousand attempts and still runs instantly; `--bits 32` is the safety cap."

*"Is MD5 faster to collide here?"*
> "At the same truncation, no — the attempt count is identical, because the
> truncated space is the same size. MD5's real weakness is mathematical, and
> this tool deliberately does not implement that attack."

---

## 16. Ethics

Educational and defensive use only. The tool generates random strings and
truncates digests; it does not forge documents, certificates, tokens or
executables, and it contains no differential-collision implementation for MD5
or SHA-1. Use hashing tools only on data you own or are authorised to test.

When presenting results, always state the truncation size. Describing a
truncated-hash collision as a full MD5/SHA-256 collision is factually wrong and
the tool is built to make that mistake hard to make.
