## E tests: a secret that does not show itself, compared without telling
## how much of it matched (README; SEC-01..03).

import std/[strutils, unittest]
import nim_secret

suite "SEC-01: a secret does not show itself":
  test "Given a secret When turned into text, as by echo or string interpolation Then a mask, not the secret":
    # SPEC: SEC-01
    let s = SecretString("sk_live_abc")
    check $s == "********"
    check "sk_live" notin ("key=" & $s)

  test "Given a secret When revealed Then the secret itself — the one place it is read":
    # SPEC: SEC-01
    check SecretString("sk_live_abc").reveal == "sk_live_abc"
    check SecretString("").reveal == ""

suite "SEC-02: comparing secrets":
  test "Given the same bytes When compared Then equal; one byte different anywhere, not":
    # SPEC: SEC-02
    let a = "a-shared-secret-of-24-chars-or-more"
    check constantTimeEquals(a, a)
    for i in [0, a.len div 2, a.len - 1]:
      var b = a
      b[i] = char(ord(b[i]) xor 1)
      check not constantTimeEquals(a, b)

  test "Given different lengths, a prefix, or the empty string When compared Then not equal; two empty ones are":
    # SPEC: SEC-02 — the length is not the secret
    let a = "a-shared-secret-of-24-chars-or-more"
    check not constantTimeEquals(a, a[0 ..< 10])
    check not constantTimeEquals(a, a & "x")
    check not constantTimeEquals(a, "")
    check constantTimeEquals("", "")

  test "Given bytes When compared Then the same rule (an AEAD tag, a MAC)":
    # SPEC: SEC-02
    let tag = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    var other = tag
    other[15] = 0
    check constantTimeEquals(tag, tag)
    check not constantTimeEquals(tag, other)
    check not constantTimeEquals(tag, tag[0 ..< 15])

  test "Given bytes that differ only in the first byte When compared Then not equal":
    # SPEC: SEC-02 — every byte is looked at, the first included
    let tag = [1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    var other = tag
    other[0] = 0
    check not constantTimeEquals(tag, other)

  test "Given a revealed secret and a presented one When compared Then the secret need not be copied to text first":
    # SPEC: SEC-02
    let s = SecretString("a-shared-secret-of-24-chars-or-more")
    check constantTimeEquals(s, "a-shared-secret-of-24-chars-or-more")
    check not constantTimeEquals(s, "a-shared-secret-of-24-chars-or-morX")

suite "SEC-03: wiping a secret":
  test "Given a secret When wiped Then its bytes are zero where they were, and it is empty":
    # SPEC: SEC-03 — a copy zeroed elsewhere would leave the secret in memory
    # Filled at run time, in its own buffer — as a secret read from the environment or a
    # file is. (A literal's bytes are in the program file and cannot be wiped.)
    var s = SecretString(newString(16))
    for i in 0 ..< 16: string(s)[i] = char(ord('a') + i)
    let length = s.reveal.len
    let where = cast[ptr UncheckedArray[char]](unsafeAddr string(s)[0])
    s.wipe()
    for i in 0 ..< length:
      check where[i] == '\0'
    check s.reveal.len == 0
    check $s == "********"

  test "Given a one-byte secret When wiped Then that byte is zero where it was":
    # SPEC: SEC-03 — the shortest secret is wiped like any other
    var s = SecretString(newString(1))
    string(s)[0] = 'k'
    let where = cast[ptr UncheckedArray[char]](unsafeAddr string(s)[0])
    s.wipe()
    check where[0] == '\0'
    check s.reveal.len == 0

  test "Given a secret made from a string literal When wiped Then it is empty and the literal is untouched":
    # SPEC: SEC-03 — a literal's storage is read-only; wiping must not write into it
    var s = SecretString("sk_live_literal")
    s.wipe()
    check s.reveal.len == 0
    check "sk_live_literal".len == 15
    check "sk_live_literal"[0] == 's'

  test "Given a secret and a copy of it When one is wiped Then the other still holds the secret":
    # SPEC: SEC-03 — wiping one secret must not zero another's bytes
    var a = SecretString(newString(8))
    for i in 0 ..< 8: string(a)[i] = char(ord('a') + i)
    let b = a
    a.wipe()
    check a.reveal.len == 0
    check b.reveal == "abcdefgh"

  test "Given an empty secret When wiped Then nothing happens":
    # SPEC: SEC-03
    var s = SecretString("")
    s.wipe()
    check s.reveal == ""
