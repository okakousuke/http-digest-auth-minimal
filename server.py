"""HTTPダイジェスト認証（RFC 7616、qop=auth）の最小サーバー。

学習用。標準ライブラリだけで動く。実運用には使わないこと
（パスワードを平文で持つ、HTTPSではない、nonceをメモリにだけ持つ）。

    python server.py --port 8765 --algorithm MD5 --nonce-ttl 300
"""
import argparse
import hashlib
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REALM = "demo-realm"
USERS = {"demo": "demo-pass"}  # 学習用の固定値
HASHERS = {"MD5": hashlib.md5, "SHA-256": hashlib.sha256}


def parse_digest_header(value):
    """`Digest k1="v1", k2=v2, ...` を辞書にする。"""
    scheme, _, rest = value.partition(" ")
    if scheme.lower() != "digest":
        return None
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


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    algorithm = "MD5"
    nonce_ttl = 300.0
    check_nc = True
    nonces = {}  # nonce -> {"issued": 発行時刻, "last_nc": 最後に受け付けたnc}

    def h(self, text):
        return HASHERS[self.algorithm](text.encode("utf-8")).hexdigest()

    def log_message(self, fmt, *args):
        pass  # 既定のアクセスログは出さず、下の log() にまとめる

    def log(self, text):
        print(f"[{time.strftime('%H:%M:%S')}] {self.command} {self.path} -> {text}", flush=True)

    def challenge(self, reason, stale=False):
        nonce = secrets.token_hex(16)
        self.nonces[nonce] = {"issued": time.monotonic(), "last_nc": 0}
        parts = [
            f'realm="{REALM}"',
            'qop="auth"',
            f"algorithm={self.algorithm}",
            f'nonce="{nonce}"',
        ]
        if stale:
            parts.append("stale=true")
        body = json.dumps({"status": "unauthorized"}).encode("utf-8")
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Digest " + ", ".join(parts))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.log(f"401 ({reason})" + (" stale=true" if stale else ""))

    def do_GET(self):
        header = self.headers.get("Authorization")
        if header is None:
            return self.challenge("Authorizationヘッダが無い")
        p = parse_digest_header(header)
        if p is None:
            return self.challenge("Digest以外の方式")
        required = ("username", "realm", "nonce", "uri", "response", "qop", "nc", "cnonce")
        if any(k not in p for k in required):
            return self.challenge("必要なパラメータが足りない")
        password = USERS.get(p["username"])
        if password is None or p["realm"] != REALM or p["uri"] != self.path or p["qop"] != "auth":
            return self.challenge("username・realm・uri・qopのどれかが合わない")

        ha1 = self.h(f'{p["username"]}:{REALM}:{password}')
        ha2 = self.h(f"{self.command}:{p['uri']}")
        expected = self.h(f'{ha1}:{p["nonce"]}:{p["nc"]}:{p["cnonce"]}:auth:{ha2}')
        if not secrets.compare_digest(expected, p["response"]):
            return self.challenge("responseが一致しない")

        # ここまで来たら、計算は正しい。残りはnonceの鮮度と使い回しの確認。
        state = self.nonces.get(p["nonce"])
        if state is None:
            return self.challenge("知らないnonce", stale=True)
        if time.monotonic() - state["issued"] > self.nonce_ttl:
            del self.nonces[p["nonce"]]
            return self.challenge("nonceの期限切れ", stale=True)
        nc = int(p["nc"], 16)
        if self.check_nc and nc <= state["last_nc"]:
            return self.challenge(f"ncが進んでいない（受信 {nc}、前回 {state['last_nc']}）")
        state["last_nc"] = nc

        body = json.dumps({"status": "ok", "user": p["username"]}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.log(f"200 (nc={p['nc']})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--algorithm", choices=sorted(HASHERS), default="MD5")
    ap.add_argument("--nonce-ttl", type=float, default=300.0, help="nonceの有効秒数")
    ap.add_argument("--no-nc-check", action="store_true", help="ncが進んでいるかを確認しない（使い回しを見るため）")
    args = ap.parse_args()
    Handler.algorithm = args.algorithm
    Handler.nonce_ttl = args.nonce_ttl
    Handler.check_nc = not args.no_nc_check
    print(f"listen 127.0.0.1:{args.port} algorithm={args.algorithm} nonce-ttl={args.nonce_ttl}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
