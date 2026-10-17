## nim-secret — a secret that does not show itself, compared without telling
## how much of it matched.
##
## - `SecretString`: a string whose `$` is a mask, so a log line or an
##   error message that interpolates it shows `********`. `reveal` is the
##   one place it is read — searchable.
## - `constantTimeEquals`: equality that looks at every byte whatever the
##   first difference, so the time it takes does not tell an attacker how
##   long a prefix they guessed right. The length is not treated as secret.
## - `wipe`: zero the secret's bytes where they are, then empty it.
##
## Taken out of a payment service on 2026-10-15. mcp-nim-sdk and three other
## repositories, which wrote out the same comparison, use it too.

type
  SecretString* = distinct string

proc `$`*(s: SecretString): string {.raises: [].} = "********"

proc reveal*(s: SecretString): string {.raises: [].} = string(s)

proc wipe*(s: var SecretString) {.raises: [].} =
  ## Zero the secret's bytes in place, then make it empty. (Zeroing a copy
  ## and assigning it back, as the original `clear` did, leaves the original
  ## bytes where they were.) A secret that came from a string literal is
  ## also in the program file; that copy cannot be wiped.
  if string(s).len > 0:
    # A string from a literal is shared and read-only until it is made this
    # one's own; writing through a pointer before that is a bus error.
    prepareMutation(string(s))
    zeroMem(addr string(s)[0], string(s).len)
  string(s).setLen(0)

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
  constantTimeEquals(string(secret).toOpenArray(0, string(secret).len - 1), presented)
