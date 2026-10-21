# Package
version       = "0.2.0"
author        = "GodsGolemInc"
description   = "A secret string that masks itself in text, constant-time equality for secrets and tags, and wiping in place"
license       = "Apache-2.0"
srcDir        = "src"

requires "nim >= 2.0.0"

task test, "Run tests":
  exec "nim c -r --hints:off tests/test_secret.nim"
