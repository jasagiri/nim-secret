# nim-secret

秘密を、表に出さず、比べた時間で中身を漏らさずに扱う。

```nim
import nim_secret

let key = SecretString(getEnv("GMO_SHOP_PASS"))
echo "using ", key                       # using ********
send(key.reveal)                         # 読むのは reveal だけ (grep で探せる)

if constantTimeEquals(configured, presented): admit()   # 一致した長さを、かかった時間で教えない
var k = SecretString(readFile(path)); defer: k.wipe()   # その場でゼロにしてから空にする
```

| | |
|---|---|
| `SecretString` | `$` が `********` を返す。ログや例外の文に埋め込まれても中身が出ない |
| `constantTimeEquals` | 文字列どうし、バイト列どうし (AEAD の tag、MAC)、`SecretString` と提示された文字列。最初の違いがどこでも、全部のバイトを見る。長さが違えば、すぐ false (長さは秘密としない) |
| `wipe` | 秘密のバイトを、その場でゼロにしてから空にする。文字列リテラルから作った秘密は、プログラムのファイルにも残っていて、そちらは消せない |

時間が一定であることは、ソースの上で「途中で抜けない」ことまでしか保証しない。C コンパイラがどう訳すかは確かめていない。

## 出どころ

2026-10-15 に、決済サービスの実装から切り出した。元の実装の `clear` は、秘密のコピーをゼロにして代入し直していたので、元のバイトが残っていた。`wipe` はその場で消す。

同じ比べ方を書いていた mcp-nim-sdk (`protocol/hmac`) ほか 3 つのリポジトリも、同じ日にこれを使うよう替えた。

## テスト

```sh
nimble test
```

仕様 ID: SEC-01 秘密は自分を表に出さない / SEC-02 秘密を比べる / SEC-03 秘密を消す。

確かめていないこと: 変異検査 (`docs/quality/g2-unmeasured.md`)、時間が一定であることの実測。
