# G2 (変異検査): `src/nim_secret.nim`

## 0.2.0 の測定

- 測定日: 2026-10-21
- ツール: nim-muter 0.2.11
- コミット: 378ce379
- 結果: killed 33 / survived 0 / timeout 0 / compileErr 0 (score 100%)

0.2.0 で `SecretString` を object に替え、`toSecret`・`repr`・`len`・`withRevealed`・`==` (コンパイルエラー) を足した後の測定。生き残りはない。

## 0.1.0 の測定

- 測定日: 2026-10-17
- ツール: nim-muter 0.2.10
- ジョブ: `tests/mutation/nim_secret.json` (リポジトリのルートから `../nim-muter/bin/nim-muter run --config tests/mutation/nim_secret.json`)

### 結果

| | killed | survived | score |
|---|---|---|---|
| 追加前 | 31 | 3 | 91.2% |
| 追加後 | 34 | 0 | 100% |

### 残った生き残り

なし (0 件)。

### 追加前の生き残りと、それを殺すテスト

| 行 | mutator | 原 → 変異 | 殺すテスト (tests/test_secret.nim) |
|---|---|---|---|
| 27 | CVR | `len > 0` の `0` → `1` | SEC-03 「one-byte secret」: 1 バイトの秘密を wipe すると、元の場所のバイトが 0 になる。変異では 1 バイトの秘密が消されずに残る |
| 30 | SDL | `prepareMutation(string(s))` → `discard` | SEC-03 「string literal」: 文字列リテラル由来の秘密を wipe できる。変異ではリテラルの読み取り専用領域へ書いて落ちる (bus error) ため、テスト実行が失敗する |
| 48 | CVR | byte 版の `0 ..< a.len` の `0` → `1` | SEC-02 「differ only in the first byte」: 先頭バイトだけが違う 2 つのタグは等しくない。変異では先頭を見ないので等しいと答える |

### 追加したテスト

1. SEC-02: 先頭バイトだけが違うバイト列は等しくない (行 48 を殺す)
2. SEC-03: 1 バイトの秘密を wipe するとそのバイトは 0 (行 27 を殺す)
3. SEC-03: 文字列リテラル由来の秘密を wipe できる (行 30 を殺す)
4. SEC-03: 秘密のコピーの一方を wipe しても他方は残る (生き残りを殺すためではなく、「共有された記憶域を壊さない」という利用者が頼る振る舞いの確認)
