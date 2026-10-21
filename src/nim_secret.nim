## nim-secret — a secret that does not show itself, compared without telling
## how much of it matched.
##
## - `SecretString`: a string whose `$` and `repr` are a mask, so a log line
##   or an error message that interpolates it shows `********`. `reveal` (a
##   copy) and `withRevealed` (its own bytes) are the only ways to read it —
##   searchable.
## - `constantTimeEquals`: equality that looks at every byte whatever the
##   first difference, so the time it takes does not tell an attacker how
##   long a prefix they guessed right. The length is not treated as secret.
## - `wipe`: zero the secret's bytes where they are, then empty it.
##
## Taken out of a payment service on 2026-10-15. mcp-nim-sdk and three other
## repositories, which wrote out the same comparison, use it too.

type
  SecretString* = object
    # Not a `distinct string`: `string(s)` would turn one back into text from
    # any module, past `reveal`.
    value: string

proc toSecret*(s: sink string): SecretString {.raises: [].} =
  ## The secret takes over `s`'s buffer when `s` is not used afterwards.
  SecretString(value: s)

proc `$`*(s: SecretString): string {.raises: [].} = "********"

proc repr*(s: SecretString): string {.raises: [].} =
  ## Also inside an object, a seq or a tuple with ARC/ORC. refc's `repr`
  ## of a container does not call this and shows the bytes.
  "********"

proc len*(s: SecretString): int {.raises: [].} =
  ## The length is not the secret.
  s.value.len

proc reveal*(s: SecretString): string {.raises: [].} =
  ## A copy of the secret: one more string to wipe when it is no longer needed.
  s.value

proc ownBytes(s: SecretString): lent string {.inline, raises: [].} = s.value

template withRevealed*(s: SecretString; plain, body: untyped) =
  ## Runs `body` with `plain` naming the secret's own bytes, without a copy:
  ## `plain.len`, `plain[i]`, `unsafeAddr plain[0]` for C code that reads it.
  block:
    template plain: untyped = ownBytes(s)
    body

proc `==`*(a, b: SecretString): bool {.error: "compare secrets with constantTimeEquals".}
  ## `==` stops at the first difference, so the time tells how much matched.

proc wipe*(s: var SecretString) {.raises: [].} =
  ## Zero the secret's bytes in place, then make it empty. (Zeroing a copy
  ## and assigning it back, as the original `clear` did, leaves the original
  ## bytes where they were.) A secret that came from a string literal is
  ## also in the program file; that copy cannot be wiped.
  if s.value.len > 0:
    # A string from a literal is shared and read-only until it is made this
    # one's own; writing through a pointer before that is a bus error.
    prepareMutation(s.value)
    zeroMem(addr s.value[0], s.value.len)
  s.value.setLen(0)

func constantTimeEquals*(a, b: openArray[char]): bool {.raises: [].} =
  ## Whether `a` and `b` are the same bytes. Every byte is looked at, so the
  ## time does not depend on where they first differ. Different lengths are
  ## answered at once: the length is not the secret.
  if a.len != b.len: return false
  var difference = 0
  for i in 0 ..< a.len:
    difference = difference or (ord(a[i]) xor ord(b[i]))
  difference == 0

func constantTimeEquals*(a, b: openArray[byte]): bool {.raises: [].} =
  ## The same, for bytes (an AEAD tag, a MAC).
  if a.len != b.len: return false
  var difference = 0'u8
  for i in 0 ..< a.len:
    difference = difference or (a[i] xor b[i])
  difference == 0

func constantTimeEquals*(secret: SecretString, presented: openArray[char]): bool {.raises: [].} =
  ## A secret against what a caller presented, without turning the secret
  ## into text first.
  constantTimeEquals(secret.value.toOpenArray(0, secret.value.len - 1), presented)
