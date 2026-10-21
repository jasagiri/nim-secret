## E tests: a secret that does not show itself, compared without telling
## how much of it matched (README; SEC-01..04).

import std/[strutils, unittest]
import nim_secret

proc filled(n: int): SecretString =
  ## A secret filled at run time, in its own buffer — as a secret read from
  ## the environment or a file is. (A literal's bytes are in the program file
  ## and cannot be wiped.)
  var s = newString(n)
  for i in 0 ..< n: s[i] = char(ord('a') + i)
  toSecret(s)

proc bytesAt(s: SecretString): ptr UncheckedArray[char] =
  withRevealed(s, plain):
    result = cast[ptr UncheckedArray[char]](unsafeAddr plain[0])

suite "SEC-01: a secret does not show itself":
  test "Given a secret When turned into text, as by echo or string interpolation Then a mask, not the secret":
    # SPEC: SEC-01
    let s = toSecret("sk_live_abc")
    check $s == "********"
    check "sk_live" notin ("key=" & $s)

  test "Given a secret When shown with repr, alone or inside an object, a seq or a tuple Then a mask":
    # SPEC: SEC-01 — repr is what a debug line prints
    type Config = object
      name: string
      key: SecretString
    let s = toSecret("sk_live_abc")
    check repr(s) == "********"
    check "sk_live" notin repr(Config(name: "svc", key: s))
    check "sk_live" notin repr(@[s])
    check "sk_live" notin repr((key: s, n: 1))

suite "SEC-04: a secret is read only where the code says so":
  test "Given a secret When revealed Then the secret itself, as a copy":
    # SPEC: SEC-04
    check toSecret("sk_live_abc").reveal == "sk_live_abc"
    check toSecret("").reveal == ""

  test "Given a secret When read with withRevealed Then its own bytes, not a copy":
    # SPEC: SEC-04 — C code can read the key without one more copy to wipe
    var s = filled(8)
    var seen = ""
    withRevealed(s, plain):
      for c in plain: seen.add c
    check seen == "abcdefgh"
    let where = s.bytesAt
    s.wipe()
    check where[0] == '\0'

  test "Given a secret When converted to string or its field is named Then it does not compile":
    # SPEC: SEC-04 — `reveal` and `withRevealed` are the only ways in, so a
    # search for "reveal" finds every place a secret is read
    let s = toSecret("sk_live_abc")
    check not compiles(string(s))
    check not compiles(s.value)

  test "Given a secret When asked its length Then the length; the length is not the secret":
    # SPEC: SEC-04
    check toSecret("sk_live_abc").len == 11
    check toSecret("").len == 0

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

  test "Given a secret and a presented one When compared Then the secret need not be copied to text first":
    # SPEC: SEC-02
    let s = toSecret("a-shared-secret-of-24-chars-or-more")
    check constantTimeEquals(s, "a-shared-secret-of-24-chars-or-more")
    check not constantTimeEquals(s, "a-shared-secret-of-24-chars-or-morX")

  test "Given two secrets When compared with == Then it does not compile":
    # SPEC: SEC-02 — `==` stops at the first difference; only the constant-time
    # comparison is offered
    let a = toSecret("x")
    let b = toSecret("x")
    check not compiles(a == b)

suite "SEC-03: wiping a secret":
  test "Given a secret When wiped Then its bytes are zero where they were, and it is empty":
    # SPEC: SEC-03 — a copy zeroed elsewhere would leave the secret in memory
    var s = filled(16)
    let length = s.len
    let where = s.bytesAt
    s.wipe()
    for i in 0 ..< length:
      check where[i] == '\0'
    check s.len == 0
    check $s == "********"

  test "Given a one-byte secret When wiped Then that byte is zero where it was":
    # SPEC: SEC-03 — the shortest secret is wiped like any other
    var s = filled(1)
    let where = s.bytesAt
    s.wipe()
    check where[0] == '\0'
    check s.len == 0

  test "Given a secret made from a string literal When wiped Then it is empty and the literal is untouched":
    # SPEC: SEC-03 — a literal's storage is read-only; wiping must not write into it
    var s = toSecret("sk_live_literal")
    s.wipe()
    check s.len == 0
    check "sk_live_literal".len == 15
    check "sk_live_literal"[0] == 's'

  test "Given a secret and a copy of it When one is wiped Then the other still holds the secret":
    # SPEC: SEC-03 — wiping one secret must not zero another's bytes
    var a = filled(8)
    let b = a
    a.wipe()
    check a.len == 0
    check b.reveal == "abcdefgh"

  test "Given an empty secret When wiped Then nothing happens":
    # SPEC: SEC-03
    var s = toSecret("")
    s.wipe()
    check s.reveal == ""
