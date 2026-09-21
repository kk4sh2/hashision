#!/usr/bin/env python3
"""
Hashision Lite
==========================

An educational program for cybersecurity students.

What it does:
  1. Hashes text with MD5 or SHA-256.
  2. Compares two texts.
  3. Finds a "shortened hash" collision (8, 12 or 16 bits).
  4. Explains the birthday paradox.

IMPORTANT (honesty note):
  This program NEVER breaks MD5 or SHA-256.
  It only keeps the FIRST few bits of the hash and searches for two
  different strings that share those few bits. The full hashes stay
  different. That is enough to demonstrate the idea of a collision.

Run it with:  python3 hashision_lite.py
"""

import hashlib   # gives us md5() and sha256()
import random    # used to build random strings
import string    # gives us the list of letters and digits
import time      # used to measure how long the search takes


# ---------------------------------------------------------------------------
# 1. HASHING
# ---------------------------------------------------------------------------

def hash_text(text, algorithm):
    """
    Return the hash of 'text' as a hexadecimal string.

    text      -> the string we want to hash, for example "hello"
    algorithm -> "md5" or "sha256"
    """
    # A hash function works on bytes, not on text, so we encode it first.
    data = text.encode("utf-8")

    if algorithm == "md5":
        return hashlib.md5(data).hexdigest()
    else:
        return hashlib.sha256(data).hexdigest()


def generate_random_string(length=8):
    """Return a random string such as 'xT92QaLm'."""
    # The "alphabet" we pick random characters from: a-z, A-Z, 0-9
    alphabet = string.ascii_letters + string.digits

    # Pick 'length' random characters and glue them together.
    return "".join(random.choice(alphabet) for _ in range(length))


def shorten_hash(full_hash, bits):
    """
    Keep only the FIRST 'bits' bits of a hash and return them as hex text.

    Why not just cut hex characters?
    Because 1 hex character = 4 bits. Cutting characters only works when the
    number of bits divides by 4. Converting to a number and shifting works
    for ANY number of bits, so it is the correct way to do it.
    """
    # How many bits does the whole hash have? Each hex char is 4 bits.
    total_bits = len(full_hash) * 4

    # Turn the hexadecimal text into one very big integer.
    value = int(full_hash, 16)

    # Shifting right by (total_bits - bits) throws away everything
    # except the leading 'bits' bits.
    short_value = value >> (total_bits - bits)

    # Print it as hex, padded with zeros so it always has the same width.
    hex_characters = (bits + 3) // 4     # 8 bits -> 2 chars, 12 bits -> 3 chars
    return format(short_value, "0" + str(hex_characters) + "X")


# ---------------------------------------------------------------------------
# 2. COLLISION SEARCH
# ---------------------------------------------------------------------------

def find_collision(algorithm, bits, max_attempts=5000000):
    """
    Look for two DIFFERENT random strings whose shortened hashes are equal.

    Returns a tuple:
        (string1, string2, short_hash, attempts, seconds)
    or None if nothing was found before 'max_attempts'.
    """
    # This dictionary stores hashes that we have already seen.
    # The key is the shortened hash, the value is the string that produced it.
    seen_hashes = {}

    attempts = 0
    start_time = time.time()

    while attempts < max_attempts:
        attempts += 1

        # Step 1: make a new random string and hash it.
        candidate = generate_random_string()
        full_hash = hash_text(candidate, algorithm)

        # Step 2: keep only the first 'bits' bits of that hash.
        short_hash = shorten_hash(full_hash, bits)

        # If this shortened hash already exists,
        # we have found two inputs producing the same shortened hash.
        if short_hash in seen_hashes:
            previous = seen_hashes[short_hash]

            # Make sure the two inputs really are different strings.
            # (Random generation can produce the same string twice, and the
            #  same string hashing to the same value is NOT a collision.)
            if previous != candidate:
                seconds = time.time() - start_time
                return (previous, candidate, short_hash, attempts, seconds)
        else:
            # Not seen before -> remember it and keep searching.
            seen_hashes[short_hash] = candidate

    # We ran out of attempts.
    return None


# ---------------------------------------------------------------------------
# 3. MENU ACTIONS
# ---------------------------------------------------------------------------

def ask_algorithm():
    """Ask the user for MD5 or SHA-256 and return 'md5' or 'sha256'."""
    print()
    print("Algorithm:")
    print("1. MD5")
    print("2. SHA-256")
    choice = input("Select: ").strip()

    if choice == "1":
        return "md5"
    return "sha256"      # anything else defaults to the safer option


def do_hash_text():
    """Menu option 1: hash one piece of text."""
    print()
    text = input("Enter text: ")
    algorithm = ask_algorithm()

    print()
    print("Hash:")
    print(hash_text(text, algorithm))


def compare_text():
    """Menu option 2: hash two texts and say whether they match."""
    print()
    text1 = input("Enter first text:  ")
    text2 = input("Enter second text: ")
    algorithm = ask_algorithm()

    hash1 = hash_text(text1, algorithm)
    hash2 = hash_text(text2, algorithm)

    print()
    print("Hash 1:")
    print(hash1)
    print()
    print("Hash 2:")
    print(hash2)
    print()

    if hash1 == hash2:
        if text1 == text2:
            # Same input -> of course the same hash. This is normal.
            print("The hashes match because the two texts are identical.")
        else:
            # Different input, same full hash = a real collision (very rare!).
            print("The texts are DIFFERENT but the hashes match: a real collision!")
    else:
        print("The hashes are different, so the texts are different.")


def do_collision_experiment():
    """Menu option 3: run the shortened-hash collision experiment."""
    print()
    print("Choose collision size:")
    print()
    print("1. 8 bits")
    print("2. 12 bits")
    print("3. 16 bits")
    choice = input("Select: ").strip()

    if choice == "1":
        bits = 8
    elif choice == "2":
        bits = 12
    else:
        bits = 16

    algorithm = ask_algorithm()

    print()
    print("Searching for collision...")

    result = find_collision(algorithm, bits)

    if result is None:
        print("No collision found. Try again.")
        return

    string1, string2, short_hash, attempts, seconds = result

    print()
    print("Collision found!")
    print()
    print("String 1:")
    print(string1)
    print()
    print("String 2:")
    print(string2)
    print()
    print("Short hash:")
    print(short_hash)
    print()
    print("Full hash 1:")
    print(hash_text(string1, algorithm))
    print()
    print("Full hash 2:")
    print(hash_text(string2, algorithm))
    print()
    print("Attempts:")
    print(attempts)
    print()
    print("Time:")
    print(str(round(seconds, 3)) + " seconds")
    print()
    print("Expected attempts (birthday bound, about 2^(bits/2)):")
    print(int(2 ** (bits / 2)))
    print()
    print("The full hashes are NOT the same.")
    print()
    print("The program intentionally compared only the first "
          + str(bits) + " bits.")
    print()
    print("This allows us to demonstrate the concept of a hash collision")
    print("without needing unrealistic computing power.")


def explain_collisions():
    """Menu option 4: print the theory."""
    print()
    print("WHAT IS A HASH?")
    print("A hash function turns any input into a fixed-length digest.")
    print("Example: SHA-256 always produces 256 bits (64 hex characters),")
    print("no matter whether the input is one letter or a whole movie.")
    print()
    print("WHAT IS A COLLISION?")
    print("Two DIFFERENT inputs x and y with H(x) = H(y).")
    print("Collisions must exist, because there are infinitely many inputs")
    print("and only a finite number of possible digests.")
    print()
    print("OTHER ATTACKS (not the same thing!)")
    print("Preimage attack        : given h, find x with H(x) = h.")
    print("Second-preimage attack : given x, find y != x with H(y) = H(x).")
    print("Collision attack       : find ANY pair x != y with H(x) = H(y).")
    print("A collision attack is the easiest of the three, because the")
    print("attacker is free to choose BOTH inputs.")
    print()
    print("THE BIRTHDAY PARADOX")
    print("In a room of only 23 people, there is a ~50% chance that two of")
    print("them share a birthday. That feels wrong, but you are not comparing")
    print("one person to the rest, you are comparing every PAIR of people.")
    print()
    print("Hashes behave the same way. For an n-bit hash:")
    print("  possible outputs = 2^n")
    print("  collisions become likely after about 2^(n/2) attempts")
    print()
    print("  8-bit  hash : 2^8  = 256 possibilities        -> ~16 attempts")
    print("  12-bit hash : 2^12 = 4,096 possibilities      -> ~64 attempts")
    print("  16-bit hash : 2^16 = 65,536 possibilities     -> ~256 attempts")
    print("  24-bit hash : 2^24 = 16,777,216 possibilities -> ~4,096 attempts")
    print()
    print("REAL LIFE")
    print("Full MD5 is 128 bits and full SHA-256 is 256 bits.")
    print("MD5 and SHA-1 are broken by clever mathematical attacks, not by")
    print("the brute force used here. SHA-256 and SHA-512 have no practical")
    print("known collision attack today.")
    print()
    print("That is why this program shortens the hash on purpose.")


def show_menu():
    """Print the main menu."""
    print()
    print("===============================")
    print(" HASHISION LITE")
    print("===============================")
    print()
    print("1. Hash text")
    print("2. Compare two texts")
    print("3. Find a shortened-hash collision")
    print("4. Explain hash collisions")
    print("5. Exit")
    print()


# ---------------------------------------------------------------------------
# 4. MAIN PROGRAM
# ---------------------------------------------------------------------------

def main():
    """Show the menu again and again until the user chooses Exit."""
    while True:
        show_menu()
        choice = input("Select: ").strip()

        if choice == "1":
            do_hash_text()
        elif choice == "2":
            compare_text()
        elif choice == "3":
            do_collision_experiment()
        elif choice == "4":
            explain_collisions()
        elif choice == "5":
            print()
            print("Goodbye.")
            break
        else:
            print()
            print("Please type a number from 1 to 5.")


# This line means: only run main() when the file is started directly,
# not when it is imported by another program.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # The user pressed Ctrl+C. Exit quietly instead of showing an error.
        print()
        print("Stopped by user.")
    except EOFError:
        # There is no more input (for example the program was run with a
        # pipe). Exit quietly instead of showing a long error message.
        print()
        print("No more input. Exiting.")
