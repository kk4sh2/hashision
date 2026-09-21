# Hashision Lite

A small, beginner-friendly Python 3 program that demonstrates **hash collisions**
for a cybersecurity class. One file, no external libraries, ~350 lines including
comments.

---

## 1. What this program does

| # | Feature |
|---|---------|
| 1 | Hash text with **MD5** or **SHA-256** |
| 2 | Compare two texts and their hashes |
| 3 | Search for a **shortened-hash collision** (8, 12 or 16 bits) |
| 4 | Explain hashes, collisions and the birthday paradox |
| 5 | Exit |

---

## 2. Honesty note (read this before your demo)

This program **does not break MD5 or SHA-256**.

It computes the full hash, then deliberately keeps only the **first 8, 12 or 16
bits** and searches for two different random strings that share those few bits.
The complete hashes always remain different.

> Never say "I found a SHA-256 collision".
> Say: "I found a collision in a **16-bit truncation** of SHA-256."

That is the honest, correct description, and it is exactly how the birthday
bound is taught.

---

## 3. Requirements

* Python 3.6 or newer (Kali Linux already ships with Python 3)
* No third-party packages — only `hashlib`, `random`, `string`, `time`

---

## 4. Installation and running on Kali Linux

```bash
sudo apt update
sudo apt install python3 -y
```

```bash
cd hashision-simple
python3 hashision_lite.py
```

Optional — make it executable so you can run `./hashision_lite.py`:

```bash
chmod +x hashision_lite.py
```

---

## 5. Example session

```
===============================
 HASHISION LITE
===============================

1. Hash text
2. Compare two texts
3. Find a shortened-hash collision
4. Explain hash collisions
5. Exit

Select: 1

Enter text: hello

Algorithm:
1. MD5
2. SHA-256
Select: 1

Hash:
5d41402abc4b2a76b9719d911017c592
```

Collision experiment:

```
Select: 3

Choose collision size:

1. 8 bits
2. 12 bits
3. 16 bits
Select: 3

Algorithm:
1. MD5
2. SHA-256
Select: 2

Searching for collision...

Collision found!

String 1:
xT92QaLm

String 2:
Lm81PkRv

Short hash:
A83F

Full hash 1:
a83f1c...

Full hash 2:
a83f9e...

Attempts:
241

Time:
0.003 seconds

Expected attempts (birthday bound, about 2^(bits/2)):
256

The full hashes are NOT the same.

The program intentionally compared only the first 16 bits.

This allows us to demonstrate the concept of a hash collision
without needing unrealistic computing power.
```

---

## 6. How the code is organised

| Function | Job |
|----------|-----|
| `hash_text(text, algorithm)` | Return the hex digest of a string |
| `generate_random_string(length)` | Build a random string like `xT92QaLm` |
| `shorten_hash(full_hash, bits)` | Keep only the first *n* bits of a digest |
| `find_collision(algorithm, bits)` | The experiment — random strings + a dictionary |
| `compare_text()` | Menu option 2 |
| `explain_collisions()` | Menu option 4, the theory |
| `show_menu()` / `main()` | The menu loop |

### The two important lines

```python
# This dictionary stores hashes that we have already seen.
seen_hashes = {}
```

```python
# If this shortened hash already exists,
# we have found two inputs producing the same shortened hash.
if short_hash in seen_hashes:
```

A dictionary lookup is **O(1)**, so the program never compares every string to
every other string. With 256 strings, all-pairs comparison would be 32,640
comparisons; the dictionary does it in 256 lookups.

### Correct bit truncation

1 hex character = 4 bits, so cutting hex characters only works for multiples
of 4. The mathematically correct way is to shift:

```python
total_bits = len(full_hash) * 4          # 64 hex chars -> 256 bits
value = int(full_hash, 16)               # hex text -> one big integer
short_value = value >> (total_bits - bits)   # keep only the top 'bits' bits
```

---

## 7. The theory you must be able to explain

**Hash** — a function that turns arbitrary input into a fixed-length digest.
SHA-256 always outputs 256 bits, whether the input is `"a"` or a 4 GB film.

**Collision** — two different inputs `x != y` with `H(x) = H(y)`.
Collisions must exist: infinitely many inputs, finitely many digests
(pigeonhole principle).

**Preimage attack** — given a digest `h`, find any `x` with `H(x) = h`.
(You do not get to choose the target.)

**Second-preimage attack** — given a specific `x`, find `y != x` with
`H(y) = H(x)`. (The first input is fixed for you.)

These are three **different** problems. A collision attack is the easiest,
because the attacker chooses *both* inputs. For an ideal n-bit hash:

| Attack | Cost |
|--------|------|
| Preimage | 2^n |
| Second preimage | 2^n |
| Collision (birthday) | 2^(n/2) |

**Birthday paradox** — in a room of 23 people there is a ~50 % chance two share
a birthday, because you compare every *pair*, not every person to one fixed
person. Same for hashes:

| Hash size | Possible outputs | Birthday bound ≈ 2^(n/2) |
|-----------|------------------|--------------------------|
| 8 bits  | 256 | ~16 attempts |
| 12 bits | 4,096 | ~64 attempts |
| 16 bits | 65,536 | ~256 attempts |
| 24 bits | 16,777,216 | ~4,096 attempts |
| 128 bits (MD5) | 3.4 × 10^38 | ~2^64 |
| 256 bits (SHA-256) | 1.2 × 10^77 | ~2^128 |

`2^128` operations is not achievable with any existing or foreseeable hardware,
which is why SHA-256 is still considered collision-resistant.

**Why MD5 and SHA-1 are "broken"** — not by this brute force, but by
mathematical *differential* attacks that find collisions far faster than
2^(n/2). MD5 collisions take seconds on a laptop; SHA-1 was broken publicly in
2017 ("SHAttered"). Use SHA-256 or SHA-512 instead.

---

## 8. 3–5 minute teacher demonstration

**Step 1 — What is hashing? (30 s)**
> "A hash function takes any input and produces a fixed-size fingerprint.
> It is one-way: easy to compute forwards, infeasible to reverse."

**Step 2 — Hash `hello` (30 s)** — menu `1`, text `hello`, algorithm MD5.
> "`hello` always produces `5d41402abc4b2a76b9719d911017c592`. Same input,
> same output, every time, on every machine."

**Step 3 — Hash `Hello` (30 s)** — menu `1` again with a capital H.
> "I changed one bit of one letter."

**Step 4 — Show the difference (30 s)**
> "The digest is completely different. That is the **avalanche effect**:
> a tiny change to the input scrambles roughly half the output bits.
> It makes it impossible to guess the input from the hash."

**Step 5 — Run a 16-bit collision (60 s)** — menu `3`, option `3`, SHA-256.
> "I am keeping only the first 16 bits of SHA-256. There are 2^16 = 65,536
> possible values. Watch how fast two different random strings collide."

**Step 6 — Why so fast? (60 s)**
> "It took about 256 tries, not 65,536. That is the birthday paradox:
> collisions appear after roughly the square root of the space, 2^(n/2).
> Every new string is compared against everything seen so far, so the number
> of pairs grows quadratically."

**Step 7 — Be honest about the limit (60 s)**
> "The FULL SHA-256 hashes on screen are different. Real SHA-256 needs about
> 2^128 attempts — more work than all the computers on Earth could do.
> I shortened the hash so the principle can be demonstrated on a laptop.
> This is a teaching model, not a break of SHA-256."

**Likely question — "So is SHA-256 unsafe?"**
> "No. MD5 and SHA-1 are unsafe because of mathematical shortcuts. SHA-256 has
> no practical collision attack. The lesson here is that hash *length* is what
> decides brute-force cost, and that the cost is 2^(n/2), not 2^n."

---

## 9. Files

```
hashision-simple/
├── hashision_lite.py
└── README.md
```

---

## 10. Ethics

This tool generates random strings and truncates digests for teaching. It does
**not** create malicious colliding files, certificates, tokens or signed
documents. Only use hashing tools on data you own or are authorised to test.
