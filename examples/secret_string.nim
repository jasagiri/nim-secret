import nim_secret

proc main() =
  var credential = toSecret("example-only-credential")
  defer: credential.wipe()

  echo "Credential: ", credential
  doAssert $credential == "********"

  # Metadata such as the length is available without revealing the plaintext.
  echo "Consumer received credential metadata (length: ", credential.len, ")"

  # Code that needs the plaintext borrows it for one block, without a copy.
  credential.withRevealed(plain):
    doAssert plain.len == credential.len

  doAssert constantTimeEquals(credential, "example-only-credential")

main()
