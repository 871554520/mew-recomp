#!/usr/bin/env python3
"""等某个 iOS IPA run 完成，用 nightly.link 取 artifact，按 CI 报告的 sha256 校验，
然后放进工作区。用法: python3 fetch_ipa.py <run_id> [版本号]"""
import base64, hashlib, http.client, json, os, re, sys, time, urllib.request, zipfile, io

REPO = '871554520/mew-recomp'

def api(url, tries=6):
    for _ in range(tries):
        buf = b''
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'dsh', 'Accept': 'application/vnd.github+json'})
            with urllib.request.urlopen(req, timeout=45) as f:
                while True:
                    c = f.read(1 << 16)
                    if not c:
                        break
                    buf += c
            return json.loads(buf.decode())
        except http.client.IncompleteRead as e:
            buf += e.partial
            try:
                return json.loads(buf.decode())
            except Exception:
                pass
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError('api 取不到: ' + url)

def diag_for(run_id):
    run = api('https://api.github.com/repos/%s/actions/runs/%s' % (REPO, run_id))
    sha = run['head_sha']
    crs = api('https://api.github.com/repos/%s/commits/%s/check-runs' % (REPO, sha))
    for c in crs.get('check_runs', []):
        anns = api('https://api.github.com/repos/%s/check-runs/%s/annotations' % (REPO, c['id']))
        for a in anns:
            if (a.get('title') or '').startswith('diag-b64'):
                return base64.b64decode(a['message']).decode('utf-8', 'replace')
    return None

def download(url, label):
    buf = b''
    total = None
    for _ in range(60):
        hdr = {'User-Agent': 'dsh'}
        if buf:
            hdr['Range'] = 'bytes=%d-' % len(buf)
        try:
            req = urllib.request.Request(url, headers=hdr)
            with urllib.request.urlopen(req, timeout=120) as r:
                if total is None:
                    total = int(r.headers.get('Content-Length') or 0)
                while True:
                    c = r.read(1 << 16)
                    if not c:
                        break
                    buf += c
        except http.client.IncompleteRead as e:
            buf += e.partial
        except Exception as e:
            print('  重试', type(e).__name__, str(e)[:60], flush=True)
            time.sleep(2)
        if total and len(buf) >= total:
            break
    print('%s: %d / %s' % (label, len(buf), total), flush=True)
    return buf

def main():
    run_id = sys.argv[1]
    ver = sys.argv[2] if len(sys.argv) > 2 else None
    # 1) 等完成
    for _ in range(90):
        d = api('https://api.github.com/repos/%s/actions/runs/%s' % (REPO, run_id))
        st = d['status']
        print(time.strftime('%H:%M:%S'), 'run', run_id, st, d.get('conclusion'), flush=True)
        if st == 'completed':
            if d.get('conclusion') != 'success':
                print('run 没成功，退出'); return 1
            break
        time.sleep(60)
    # 2) 从 annotation 拿 CI 报告的 ipa 名字与 sha256
    txt = diag_for(run_id) or ''
    m_name = re.search(r'(Mewgenics-relink-v[\w.\-]+-unsigned\.ipa)', txt)
    m_sha = re.search(r'\b([0-9a-f]{64})\b', txt)
    name = m_name.group(1) if m_name else ('Mewgenics-relink-v%s-unsigned.ipa' % ver if ver else None)
    want = m_sha.group(1) if m_sha else None
    print('CI 报告: name=%s sha256=%s' % (name, (want or '?')[:16]), flush=True)
    # 3) 取 artifact
    art = 'ios-ipa-linux-%s' % run_id
    url = 'https://nightly.link/%s/actions/runs/%s/%s.zip' % (REPO, run_id, art)
    blob = download(url, 'artifact')
    z = zipfile.ZipFile(io.BytesIO(blob))
    ipa = [i for i in z.infolist() if i.filename.endswith('.ipa')]
    if not ipa:
        print('artifact 里没有 ipa:', [i.filename for i in z.infolist()]); return 1
    data = z.read(ipa[0].filename)
    got = hashlib.sha256(data).hexdigest()
    print('下载到 %s: %d B sha256=%s' % (ipa[0].filename, len(data), got[:16]), flush=True)
    ok = (want is None) or (got == want)
    print('sha256 与 CI 报告一致:', ok, flush=True)
    if not ok:
        print('校验失败，不落盘'); return 1
    dst = '/home/dsh/.dsh/bot/workspace/%s' % (name or ipa[0].filename)
    open(dst, 'wb').write(data)
    print('已写入', dst, os.path.getsize(dst), flush=True)
    return 0

sys.exit(main())
