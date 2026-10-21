# nim-secret

秘密を、表に出さず、比べた時間で中身を漏らさずに扱う。

```nim
import nim_secret

let key = toSecret(getEnv("GMO_SHOP_PASS"))
echo "using ", key                       # using ********
send(key.reveal)                         # 読むのは reveal と withRevealed だけ (grep で探せる)
withRevealed(key, plain):                # コピーを作らずに読む (C へポインタを渡すとき)
  sign(unsafeAddr plain[0], plain.len)

if constantTimeEquals(configured, presented): admit()   # 一致した長さを、かかった時間で教えない
var k = toSecret(readFile(path)); defer: k.wipe()   # その場でゼロにしてから空にする
```

| | |
|---|---|
| `SecretString` | `toSecret` で作る。`$` と `repr` が `********` を返す。ログや例外の文、デバッグの `repr` に埋め込まれても中身が出ない。`string(s)` では取り出せず、`==` はコンパイルエラーになる (`constantTimeEquals` を使う) |
| `reveal` / `withRevealed` | 秘密を読む方法はこの 2 つだけ。`reveal` はコピーを返す (使い終わったら、そのコピーも消す)。`withRevealed` はコピーを作らず、秘密そのもののバイトを `plain` という名前で読ませる |
| `len` | 長さ (長さは秘密としない) |
| `constantTimeEquals` | 文字列どうし、バイト列どうし (AEAD の tag、MAC)、`SecretString` と提示された文字列。最初の違いがどこでも、全部のバイトを見る。長さが違えば、すぐ false (長さは秘密としない) |
| `wipe` | 秘密のバイトを、その場でゼロにしてから空にする。文字列リテラルから作った秘密は、プログラムのファイルにも残っていて、そちらは消せない |

時間が一定であることは、ソースの上で「途中で抜けない」ことまでしか保証しない。C コンパイラがどう訳すかは確かめていない。

守れないこと:

- `cast` で型を変えれば中身を読める (明示的に安全でない操作であり、grep で探せる)。
- `--mm:refc` では、秘密を含む object・seq・tuple の `repr` が中身を表示する。refc の `repr` は、要素の型に定義した `repr` を呼ばないため。ARC/ORC (Nim 2 の既定) では伏せ字になる。
- `reveal` が返したコピーや、代入で作られたコピーは、それぞれ `wipe` しない限りメモリに残る。

## 0.1 からの変更

0.1 の `SecretString` は `distinct string` で、`string(s)` によって、どのモジュールからでも中身を取り出せた。「読むのは `reveal` だけ」という説明は実装と合っていなかった。0.2 で、中身を非公開のフィールドに持つ object に替えた。

| 0.1 | 0.2 |
|---|---|
| `SecretString(s)` | `toSecret(s)` |
| `string(s)` で読む | `s.reveal` (コピー) か `withRevealed(s, plain): ...` (コピーなし) |
| `string(s).len` | `s.len` |
| `unsafeAddr string(s)[0]` | `withRevealed(s, plain): ... unsafeAddr plain[0] ...` |

## 出どころ

2026-10-15 に、決済サービスの実装から切り出した。元の実装の `clear` は、秘密のコピーをゼロにして代入し直していたので、元のバイトが残っていた。`wipe` はその場で消す。

同じ比べ方を書いていた mcp-nim-sdk (`protocol/hmac`) ほか 3 つのリポジトリも、同じ日にこれを使うよう替えた。

## テスト

```sh
nimble test
```

仕様 ID: SEC-01 秘密は自分を表に出さない / SEC-02 秘密を比べる / SEC-03 秘密を消す / SEC-04 秘密を読むのは、そう書いた所だけ。

確かめていないこと: 0.2 で変えたコードの変異検査 (`docs/quality/g2-nim_secret.md` に未測定と書いた)、時間が一定であることの実測。
