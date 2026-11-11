# http-digest-auth-minimal

HTTPダイジェスト認証（RFC 7616、`qop=auth`）のやり取りを、1往復ずつ読むための最小サンプルです。Pythonの標準ライブラリだけで書いたサーバーと、途中の値（HA1、HA2、response）を表示するクライアントが入っています。

Qiitaの記事「[401から始まる認証 ― HTTPダイジェスト認証のやり取りを、自作サーバーで1往復ずつ読む](https://qiita.com/okakousuke1124/items/dc963a1c41f8248176de)」の確認に使ったコードです。

> **学習用です。実運用には使わないでください。** パスワードを平文で持ち、HTTPSではなく、`nonce` をメモリにだけ持ちます。

## 作った背景

ダイジェスト認証のかかったAPIを呼ぶと、最初の要求には401が返り、そのあとの要求で通ります。ログに401が並んでいるとき、どこまでが正常でどこからが異常なのかを判断できるように、401から200までのやり取りを自分の手で確かめるために作りました。

## ファイル

| ファイル | 役割 | 依存 |
| --- | --- | --- |
| `server.py` | ダイジェスト認証をかけた最小のHTTPサーバー | 標準ライブラリのみ |
| `client_manual.py` | 401を受け、HA1・HA2・responseを表示しながら認証する | 標準ライブラリのみ |
| `client_requests.py` | `requests` の `HTTPDigestAuth` に任せたときの往復回数を表示する | `requests` |

ユーザー名は `demo`、パスワードは `demo-pass`、`realm` は `demo-realm` で固定です。サーバーは `127.0.0.1` だけで待ち受けます。

## 使い方

```shell
# サーバー（既定はMD5、nonceの期限300秒）
python server.py --port 8765

# 別の端末で：1往復ずつ読む
python client_manual.py

# 通ったヘッダを、そのままもう一度送る（ncの確認）
python client_manual.py --replay

# curlで見る
curl -v --digest -u demo:demo-pass http://127.0.0.1:8765/api/status
```

`client_requests.py` だけ `requests` が要ります。

```shell
pip install -r requirements.txt
python client_requests.py --count 3
```

### nonceの期限切れ（stale=true）を見る

```shell
python server.py --port 8766 --nonce-ttl 3
python client_manual.py --port 8766 --wait 5
python client_requests.py --port 8766 --count 2 --interval 5
```

### SHA-256で出題する

```shell
python server.py --port 8767 --algorithm SHA-256
python client_manual.py --port 8767
```

SSPIを有効にしたWindows向けの `curl` は、SHA-256の出題に応答しません（`curl --version` の `Features` に `SSPI` があるビルド）。`curl` の既知の問題に記載があります。WSLなど、SSPIを使わない `curl` では通ります。

### ncを確認しないサーバーにする

```shell
python server.py --port 8765 --no-nc-check
python client_manual.py --replay    # 同じヘッダが2回とも通る
```

## サーバーのオプション

| オプション | 既定値 | 意味 |
| --- | --- | --- |
| `--port` | `8765` | 待ち受けるポート |
| `--algorithm` | `MD5` | `MD5` か `SHA-256` |
| `--nonce-ttl` | `300` | `nonce` の有効秒数 |
| `--no-nc-check` | 無効 | `nc` が進んでいるかを確認しない |

## 動作確認環境

2026年11月に、次の環境で確認しました。

| 項目 | 版 |
| --- | --- |
| OS | Windows 11。サーバーはWSLのUbuntuでも起動を確認 |
| Python | 3.12.10（Windows）、3.14.4（WSL） |
| requests | 2.34.2 |
| curl | 8.21.0（Windowsに付属）、8.18.0（WSLのUbuntu） |

## 公開範囲

このリポジトリのコードは、公開用にゼロから書いたものです。実在の機器・サービスのAPI、アドレス、認証情報、ログは含みません。

実装しているのは、RFC 7616のうち `GET` と `qop=auth` だけです。次のものは入っていません。

- `qop=auth-int`
- 末尾に `-sess` が付くアルゴリズム、SHA-512/256
- `opaque`、`userhash`、`Authentication-Info` ヘッダ
- 複数の `algorithm` を並べた出題
- `GET` 以外のメソッド、プロキシの認証

## 参考資料

- [RFC 7616: HTTP Digest Access Authentication](https://datatracker.ietf.org/doc/html/rfc7616)
- [curl: Known Bugs](https://curl.se/docs/knownbugs.html)（SHA-256 digest not supported in Windows SSPI builds）

## ライセンス

MIT License。[LICENSE](LICENSE) を参照してください。
