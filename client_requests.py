"""requests の HTTPDigestAuth に任せたとき、実際に何往復しているかを見る。

    pip install requests
    python client_requests.py --count 3
    python client_requests.py --count 2 --interval 5    # 途中でnonceの期限を切らす
"""
import argparse
import time

import requests
from requests.auth import HTTPDigestAuth


def short(header):
    """Authorizationヘッダから、見たい項目だけを抜き出す。"""
    if not header:
        return "(なし)"
    keep = []
    for part in header.replace("Digest ", "").split(", "):
        if part.split("=")[0] in ("nonce", "nc"):
            keep.append(part)
    return ", ".join(keep)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--interval", type=float, default=0.0)
    args = ap.parse_args()

    url = f"http://127.0.0.1:{args.port}/api/status"
    session = requests.Session()
    session.auth = HTTPDigestAuth("demo", "demo-pass")

    for i in range(1, args.count + 1):
        if i > 1 and args.interval:
            print(f"    （{args.interval:g}秒待つ）")
            time.sleep(args.interval)
        res = session.get(url, timeout=10)
        print(f"get() {i}回目: 最終結果 {res.status_code}")
        for n, r in enumerate(list(res.history) + [res], start=1):
            stale = "stale=true" in r.headers.get("WWW-Authenticate", "").lower()
            print(f"    往復{n}: {r.status_code}{' stale=true' if stale else ''}  送ったAuthorization: {short(r.request.headers.get('Authorization'))}")


if __name__ == "__main__":
    main()
