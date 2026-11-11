"""HTTPダイジェスト認証のやり取りを、1往復ずつ手で追うクライアント。

標準ライブラリだけで動く。計算の途中の値（HA1、HA2、response）を表示する。

    python client_manual.py                  # 401を受けて、計算して、もう一度送る
    python client_manual.py --wait 5         # 2回目を送る前に5秒待つ（nonceの期限切れを見る）
    python client_manual.py --replay         # 同じAuthorizationヘッダをもう一度送る
"""
import argparse
import hashlib
import http.client
import secrets
import time

HASHERS = {"MD5": hashlib.md5, "SHA-256": hashlib.sha256}


def parse_challenge(value):
    scheme, _, rest = value.partition(" ")
    assert scheme.lower() == "digest", value
    params, key, buf, in_quote = {}, None, "", False
    for ch in rest + ",":
        if ch == '"':
            in_quote = not in_quote
        elif ch == "=" and key is None and not in_quote:
            key, buf = buf.strip(), ""
        elif ch == "," and not in_quote:
            if key is not None:
                params[key] = buf.strip()
            key, buf = None, ""
        else:
            buf += ch
    return params


def request(host, port, path, authorization=None):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    headers = {"Authorization": authorization} if authorization else {}
    conn.request("GET", path, headers=headers)
    res = conn.getresponse()
    body = res.read().decode("utf-8")
    challenge = res.getheader("WWW-Authenticate")
    conn.close()
    print(f"  < HTTP {res.status}")
    if challenge:
        print(f"  < WWW-Authenticate: {challenge}")
    print(f"  < {body}")
    return res.status, challenge


def build_authorization(user, password, method, path, ch, nc, show=True):
    h = lambda text: HASHERS[ch.get("algorithm", "MD5")](text.encode("utf-8")).hexdigest()
    cnonce = secrets.token_hex(8)
    nc_text = f"{nc:08x}"
    ha1 = h(f'{user}:{ch["realm"]}:{password}')
    ha2 = h(f"{method}:{path}")
    response = h(f'{ha1}:{ch["nonce"]}:{nc_text}:{cnonce}:auth:{ha2}')
    if show:
        print(f'  HA1      = H("{user}:{ch["realm"]}:{password}")')
        print(f"           = {ha1}")
        print(f'  HA2      = H("{method}:{path}")')
        print(f"           = {ha2}")
        print(f'  response = H("HA1:{ch["nonce"]}:{nc_text}:{cnonce}:auth:HA2")')
        print(f"           = {response}")
    return (
        f'Digest username="{user}", realm="{ch["realm"]}", nonce="{ch["nonce"]}", '
        f'uri="{path}", algorithm={ch.get("algorithm", "MD5")}, qop=auth, '
        f'nc={nc_text}, cnonce="{cnonce}", response="{response}"'
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--path", default="/api/status")
    ap.add_argument("--user", default="demo")
    ap.add_argument("--password", default="demo-pass")
    ap.add_argument("--wait", type=float, default=0.0, help="2回目を送る前に待つ秒数")
    ap.add_argument("--replay", action="store_true", help="同じヘッダをもう一度送る")
    args = ap.parse_args()

    print("[1] 認証情報なしで送る")
    status, challenge = request(args.host, args.port, args.path)
    ch = parse_challenge(challenge)

    print("[2] 受け取ったnonceで response を計算する")
    auth = build_authorization(args.user, args.password, "GET", args.path, ch, nc=1)

    if args.wait:
        print(f"    （{args.wait:g}秒待つ）")
        time.sleep(args.wait)

    print("[3] Authorizationヘッダを付けて送る")
    print(f"  > Authorization: {auth}")
    status, challenge = request(args.host, args.port, args.path, auth)

    if status == 401 and challenge and "stale=true" in challenge.lower():
        print("[4] stale=true なので、新しいnonceで計算し直して送る（パスワードは聞き直さない）")
        ch = parse_challenge(challenge)
        auth = build_authorization(args.user, args.password, "GET", args.path, ch, nc=1, show=False)
        print(f"  > Authorization: {auth}")
        status, challenge = request(args.host, args.port, args.path, auth)

    if args.replay:
        print("[5] まったく同じAuthorizationヘッダを、もう一度送る")
        request(args.host, args.port, args.path, auth)


if __name__ == "__main__":
    main()
