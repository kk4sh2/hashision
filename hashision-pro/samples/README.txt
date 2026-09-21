Sample files for Hashision Pro
============================================

sample1.txt       the five bytes "hello"
sample2.txt       the five bytes "world"
sample1_copy.txt  an identical copy of sample1.txt

Try:

  python3 hashision.py hash-file samples/sample1.txt --algorithm sha256
  python3 hashision.py compare-files samples/sample1.txt samples/sample2.txt
  python3 hashision.py compare-files samples/sample1.txt samples/sample1_copy.txt

The last command reports matching digests with IDENTICAL content. That is a
duplicate file, not a collision: a collision needs DIFFERENT inputs producing
the same digest.

If your instructor supplies a known harmless collision pair (for example the
two "shattered" SHA-1 PDFs published in 2017), drop them in this folder and run:

  python3 hashision.py compare-files samples/shattered-1.pdf samples/shattered-2.pdf --algorithm sha1
  python3 hashision.py compare-files samples/shattered-1.pdf samples/shattered-2.pdf --algorithm sha256

SHA-1 will report a REAL COLLISION; SHA-256 will report different digests.
This tool only verifies such files, it never creates malicious colliding files.
