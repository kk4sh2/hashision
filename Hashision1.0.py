#!/usr/bin/env python3
"""
Hashision1.0 - generate and verify truncated hash collisions.

    python3 Hashision1.0.py generate
    python3 Hashision1.0.py generate --algorithm sha256 --bits 20
    python3 Hashision1.0.py check "hello" "world" --algorithm sha256

A truncated collision is a real collision in the compared prefix only. It says
nothing about the full digest, and this tool never claims otherwise.
"""

import argparse
import hashlib
import math
import secrets
import string
import sys
import time

TOOL = "Hashision1.0"
HEADER = "========== HASHISION1.0 =========="
FOOTER = "=" * len(HEADER)

# algorithm -> (display name, digest size in bits)
ALGORITHMS = {
    "md5": ("MD5", 128),
    "sha1": ("SHA-1", 160),
    "sha256": ("SHA-256", 256),
    "sha512": ("SHA-512", 512),
}

SUGGESTED_BITS = (8, 12, 16, 20, 24)
MAX_SEARCH_BITS = 32  # past this, a birthday search stops being a demonstration

ALPHABET = string.ascii_letters + string.digits
INPUT_LENGTH = 8
PROGRESS_EVERY = 10_000

HASHES_PER_SECOND = 150_000  # measured rate of the loop below, one CPU core
BYTES_PER_ENTRY = 250  # one seen_hashes entry: dict slot plus two short strings
SECONDS_PER_YEAR = 365.25 * 24 * 60 * 60
UNIVERSE_YEARS = 1.4e10


# --- hashing ----------------------------------------------------------------

def digest_bytes(algorithm, text):
    """Full raw digest of text."""
    return hashlib.new(algorithm, text.encode("utf-8")).digest()


def truncate(raw, bits):
    """The leading `bits` bits of a digest, rendered as hex."""
    value = int.from_bytes(raw, "big") >> (len(raw) * 8 - bits)
    return format(value, "0{}x".format(-(-bits // 4)))


def random_input():
    """A fresh random input drawn from a cryptographically secure source."""
    return "".join(secrets.choice(ALPHABET) for _ in range(INPUT_LENGTH))


def birthday_attempts(bits):
    """Expected number of hashes before two of them collide in `bits` bits."""
    return math.sqrt(math.pi / 2) * 2 ** (bits / 2)


def big(value):
    """Readable form for counts that can span many orders of magnitude."""
    return "{:,.0f}".format(value) if value < 1e9 else "{:.2e}".format(value)


def human_time(seconds):
    """Seconds in whichever unit keeps the number meaningful."""
    for unit, size in (("years", SECONDS_PER_YEAR), ("days", 86400.0),
                       ("hours", 3600.0), ("minutes", 60.0)):
        if seconds >= size:
            return "{} {}".format(big(seconds / size), unit)
    return "{:.1f} seconds".format(seconds)


def human_bytes(count):
    """Memory in whichever unit keeps the number meaningful."""
    for unit, size in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6)):
        if count >= size:
            return "{:,.0f} {}".format(count / size, unit)
    return "{:,.0f} bytes".format(count)


def article(number):
    """'a' or 'an', for numbers read aloud (8, 11, 18, 80-89 take 'an')."""
    return "an" if number in (8, 11, 18) or 80 <= number <= 89 else "a"


# --- reporting --------------------------------------------------------------

def field(label, value):
    print("{}:\n{}\n".format(label, value))


def show_full_digests(label, raw1, raw2):
    print("Full {} #1:\n{}\n".format(label, raw1.hex()))
    print("Full {} #2:\n{}\n".format(label, raw2.hex()))


def refuse_search(algorithm, bits):
    """Explain, with real numbers, why a search this wide is not run."""
    label, size = ALGORITHMS[algorithm]
    attempts = birthday_attempts(bits)
    seconds = attempts / HASHES_PER_SECOND
    infeasible = seconds >= SECONDS_PER_YEAR

    print()
    print(HEADER)
    print()
    print("      COLLISION NOT ATTEMPTED")
    print()
    print("Algorithm: {}".format(label))
    print("Requested bits: {}{}".format(
        bits, " (the full digest)" if bits == size else ""))
    print("Search limit: {} bits".format(MAX_SEARCH_BITS))
    print()
    print("A birthday search over {} bits needs about {} hashes, and a".format(
        bits, big(attempts)))
    print("table holding that many of them: roughly {} of memory.".format(
        human_bytes(attempts * BYTES_PER_ENTRY)))
    print("At this loop's measured {:,} hashes per second, the search".format(
        HASHES_PER_SECOND))
    print("alone would take about {}.".format(human_time(seconds)))
    print()
    if infeasible:
        if seconds / SECONDS_PER_YEAR > UNIVERSE_YEARS:
            print("For scale, the universe is roughly {} years old.".format(
                big(UNIVERSE_YEARS)))
            print()
        print("That is computationally infeasible here, so {} does not".format(TOOL))
        print("attempt it and will not print a fabricated result.")
        print()
        if algorithm in ("md5", "sha1"):
            print("Full {} collisions do exist in the real world, but they come".format(label))
            print("from cryptanalysis (chosen-prefix attacks), never from a")
            print("brute-force loop like this one.")
        else:
            print("No full {} collision has ever been found by anyone.".format(label))
    else:
        print("The table, not the hashing, is the wall: every seen hash is")
        print("held in memory, so {} stops at {} compared bits.".format(
            TOOL, MAX_SEARCH_BITS))
    print()
    print("Pick a demonstration size instead: {} (maximum {}).".format(
        ", ".join(str(b) for b in SUGGESTED_BITS), MAX_SEARCH_BITS))
    print()
    print(FOOTER)
    print()


# --- generate ---------------------------------------------------------------

def generate(algorithm, bits):
    label, size = ALGORITHMS[algorithm]

    if bits > MAX_SEARCH_BITS:
        refuse_search(algorithm, bits)
        return 2

    seen_hashes = {}
    attempts = 0
    started = time.perf_counter()

    while True:
        candidate = random_input()
        attempts += 1
        short = truncate(digest_bytes(algorithm, candidate), bits)

        previous = seen_hashes.get(short)
        if previous is not None and previous != candidate:
            elapsed = time.perf_counter() - started
            break
        seen_hashes[short] = candidate

        if attempts % PROGRESS_EVERY == 0:
            print("[*] {}: {:,} attempts...".format(TOOL, attempts),
                  file=sys.stderr, flush=True)

    raw1 = digest_bytes(algorithm, previous)
    raw2 = digest_bytes(algorithm, candidate)

    print()
    print(HEADER)
    print()
    print("        COLLISION GENERATED")
    print()
    field("Input 1", previous)
    field("Input 2", candidate)
    field("Hash 1", truncate(raw1, bits))
    field("Hash 2", truncate(raw2, bits))
    print("Algorithm: {}".format(label))
    print("Compared bits: {}".format(bits))
    print("Attempts: {:,}".format(attempts))
    print("Time: {:.2f} seconds".format(elapsed))
    print()
    print("SUCCESS:")
    print("Two DIFFERENT inputs generated the SAME compared hash.")
    print()
    show_full_digests(label, raw1, raw2)
    print("This is {} {}-bit truncated {} collision.".format(article(bits), bits, label))
    print("It is NOT a full {} collision.".format(label))
    print("The full {}-bit digests above differ past the first {} bits.".format(size, bits))
    print()
    print(FOOTER)
    print()
    return 0


# --- check ------------------------------------------------------------------

def check(algorithm, bits, first, second):
    label, size = ALGORITHMS[algorithm]

    raw1 = digest_bytes(algorithm, first)
    raw2 = digest_bytes(algorithm, second)
    short1 = truncate(raw1, bits)
    short2 = truncate(raw2, bits)

    same_input = first == second
    collided = short1 == short2 and not same_input

    print()
    print(HEADER)
    print()
    print("         COLLISION CHECK")
    print()
    field("Input 1", first)
    field("Input 2", second)
    field("Hash 1", short1)
    field("Hash 2", short2)
    print("Algorithm: {}".format(label))
    print("Compared bits: {} of {}".format(bits, size))
    print()
    print("RESULT:")
    if same_input:
        print("The two inputs are IDENTICAL, so equal hashes are expected.")
        print("That is not a collision.")
    elif collided:
        print("COLLISION: two DIFFERENT inputs share the SAME compared hash.")
    else:
        print("NO COLLISION: the compared hashes differ.")
    print()
    show_full_digests(label, raw1, raw2)
    if collided:
        if bits == size:
            print("The full digests match. Verify this independently before")
            print("believing it - a full {} collision would be major news.".format(label))
        else:
            print("This is {} {}-bit truncated {} collision.".format(
                article(bits), bits, label))
            print("It is NOT a full {} collision.".format(label))
        print()
    print(FOOTER)
    print()
    return 0 if collided else 1


# --- command line -----------------------------------------------------------

def add_common(parser, searching):
    parser.add_argument(
        "-a", "--algorithm", default="sha256",
        type=lambda value: value.lower(), choices=sorted(ALGORITHMS),
        metavar="ALGO", help="md5, sha1, sha256 or sha512 (default: sha256)")
    parser.add_argument(
        "-b", "--bits", default=16, type=int, metavar="N",
        help="leading bits to compare (default: 16; "
             + ("practical sizes {}, maximum {})".format(
                 ", ".join(str(b) for b in SUGGESTED_BITS), MAX_SEARCH_BITS)
                if searching else "up to the full digest)"))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="Hashision1.0.py",
        description="{} - demonstrate hash collisions honestly.".format(TOOL),
        epilog="check exits 0 on a collision and 1 when the hashes differ.")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    gen = commands.add_parser(
        "generate", help="search for two random inputs with the same truncated hash")
    add_common(gen, searching=True)

    chk = commands.add_parser(
        "check", help="hash two supplied inputs and compare their truncated hashes")
    chk.add_argument("input1", help="first input")
    chk.add_argument("input2", help="second input")
    add_common(chk, searching=False)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    label, size = ALGORITHMS[args.algorithm]
    if args.bits < 4:
        parser.error("--bits must be at least 4")
    if args.bits > size:
        parser.error("--bits cannot exceed {}, the {} digest size".format(size, label))

    try:
        if args.command == "generate":
            return generate(args.algorithm, args.bits)
        return check(args.algorithm, args.bits, args.input1, args.input2)
    except KeyboardInterrupt:
        print("\n[!] {}: stopped by user, no collision found.".format(TOOL),
              file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
