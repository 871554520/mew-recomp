#!/usr/bin/env python3
"""分块下载 GitHub Actions artifact（直连常被掐断，这里用 Range 续传）。

用法：
    python3 tools/fetch_artifact.py <artifact_id> <out.zip> [--repo owner/name]

token 从环境变量取，顺序：GH_TOKEN → GITHUB_TOKEN → DSH_SECRET_GITHUB_WORKFLOW_TOKEN。

为什么需要这个：本机对 `api.github.com/.../artifacts/<id>/zip` 的直连和
nightly.link 都会在 30–120 秒内超时（0 字节）。分块 + 重试是唯一稳定路径。
"""
import argparse
import os
import sys
import time
import urllib.error
import urllib.request

CHUNK = 1 << 20


def token() -> str:
    for name in ("GH_TOKEN", "GITHUB_TOKEN", "DSH_SECRET_GITHUB_WORKFLOW_TOKEN"):
        v = os.environ.get(name)
        if v:
            return v
    sys.exit("no token in env (GH_TOKEN / GITHUB_TOKEN / DSH_SECRET_GITHUB_WORKFLOW_TOKEN)")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: ANN001
        return None


def api(url: str, tok: str, timeout: int = 60):
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + tok,
        "Accept": "application/vnd.github+json",
        "User-Agent": "mew-fetch-artifact",
    })
    return urllib.request.urlopen(req, timeout=timeout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("artifact_id", type=int)
    ap.add_argument("out")
    ap.add_argument("--repo", default="871554520/mew-recomp")
    args = ap.parse_args()

    tok = token()
    meta = api(f"https://api.github.com/repos/{args.repo}/actions/artifacts/{args.artifact_id}", tok)
    import json
    m = json.load(meta)
    want = int(m["size_in_bytes"])
    print(f"artifact {args.artifact_id} name={m.get('name')} size={want}", flush=True)

    opener = urllib.request.build_opener(NoRedirect)
    loc = None
    for i in range(8):
        try:
            opener.open(urllib.request.Request(
                f"https://api.github.com/repos/{args.repo}/actions/artifacts/{args.artifact_id}/zip",
                headers={"Authorization": "Bearer " + tok,
                         "Accept": "application/vnd.github+json",
                         "User-Agent": "mew-fetch-artifact"}), timeout=60)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                loc = e.headers.get("Location")
                break
        except Exception as e:  # noqa: BLE001
            print(f"  meta retry {i}: {type(e).__name__}", flush=True)
        time.sleep(2)
    if not loc:
        print("failed to get signed url", file=sys.stderr)
        return 2

    buf = bytearray()
    fails = 0
    while len(buf) < want:
        off = len(buf)
        end = min(off + CHUNK - 1, want - 1)
        got = None
        for _ in range(30):
            try:
                b = urllib.request.urlopen(urllib.request.Request(
                    loc, headers={"Range": f"bytes={off}-{end}",
                                  "User-Agent": "mew-fetch-artifact"}), timeout=120).read()
                if len(b) == end - off + 1:
                    got = b
                    break
            except Exception:  # noqa: BLE001
                time.sleep(1)
        if got is None:
            fails += 1
            print(f"  chunk fail at {off} ({fails})", flush=True)
            if fails > 8:
                break
            continue
        buf += got
        if len(buf) % (8 * CHUNK) == 0 or len(buf) == want:
            print(f"  {len(buf)}/{want}", flush=True)

    with open(args.out, "wb") as f:
        f.write(buf)
    print(f"wrote {args.out} ({len(buf)}/{want} bytes)")
    return 0 if len(buf) == want else 1


if __name__ == "__main__":
    sys.exit(main())
