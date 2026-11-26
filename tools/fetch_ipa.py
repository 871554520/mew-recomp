#!/usr/bin/env python3
"""等某个 iOS IPA run 完成，用 nightly.link 取 artifact，校验后放进工作区。

用法: python3 tools/fetch_ipa.py <run_id> [版本号]

设计要点（匿名 API 只有 60 次/小时，经常被打满）：
- API 只用来「等完成 + 读 CI 报告的 sha256」，拿不到就直接跳过（--no-api / 自动降级）；
- artifact 是否存在改用 nightly.link 的 Range 探针判断（不耗 API 配额）；
- sha256 优先对 CI 报告，其次对 artifact 内 assemble_report.txt，两者都没有就只报实测值；
- 落盘后自动跑 ios_port/verify_bundle.py 装前门禁。
"""
import base64, hashlib, http.client, json, os, re, subprocess, sys, time, urllib.request, urllib.error, zipfile, io

REPO = '871554520/mew-recomp'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTDIR = '/home/dsh/.dsh/bot/workspace'


def api(url, tries=3):
    last = None
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
                last = e
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (403, 429):
                break          # 配额用尽，别重试
        except Exception as e:
            last = e
        time.sleep(2)
    raise RuntimeError('api 取不到(%s): %s' % (type(last).__name__, url))


def artifact_url(run_id):
    return 'https://nightly.link/%s/actions/runs/%s/ios-ipa-linux-%s.zip' % (REPO, run_id, run_id)


def probe_artifact(run_id):
    """不耗 API 配额：artifact 已生成就返回 True。"""
    try:
        req = urllib.request.Request(artifact_url(run_id), headers={'User-Agent': 'dsh', 'Range': 'bytes=0-1023'})
        with urllib.request.urlopen(req, timeout=45) as r:
            return r.status in (200, 206)
    except urllib.error.HTTPError as e:
        return e.code in (200, 206)
    except Exception:
        return False


def diag_for(run_id):
    try:
        run = api('https://api.github.com/repos/%s/actions/runs/%s' % (REPO, run_id))
        sha = run['head_sha']
        crs = api('https://api.github.com/repos/%s/commits/%s/check-runs' % (REPO, sha))
        for c in crs.get('check_runs', []):
            anns = api('https://api.github.com/repos/%s/check-runs/%s/annotations' % (REPO, c['id']))
            for a in anns:
                if (a.get('title') or '').startswith('diag-b64'):
                    return base64.b64decode(a['message']).decode('utf-8', 'replace')
    except Exception as e:
        print('  (读不到 CI 诊断: %s)' % str(e)[:70], flush=True)
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
                    if r.status == 206 and '/' in (r.headers.get('Content-Range') or ''):
                        total = int(r.headers['Content-Range'].split('/')[-1])
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
    no_api = '--no-api' in sys.argv

    # 1) 等完成：API 可用就用，配额打满就退化成 nightly.link 探针继续等
    deadline = time.time() + 90 * 60
    api_ok = not no_api
    ready = False
    while time.time() < deadline:
        if api_ok:
            try:
                d = api('https://api.github.com/repos/%s/actions/runs/%s' % (REPO, run_id))
                print(time.strftime('%H:%M:%S'), 'run', run_id, d['status'], d.get('conclusion'), flush=True)
                if d['status'] == 'completed':
                    if d.get('conclusion') != 'success':
                        print('run 没成功，退出')
                        return 1
                    ready = True
                    break
                time.sleep(60)
                continue
            except Exception as e:
                print('API 不可用（多半是匿名配额 0/60），改用 nightly.link 探针:', str(e)[:60], flush=True)
                api_ok = False
        if probe_artifact(run_id):
            print(time.strftime('%H:%M:%S'), 'artifact 已生成', flush=True)
            ready = True
            break
        print(time.strftime('%H:%M:%S'), 'artifact 还没好，等 60s', flush=True)
        time.sleep(60)
    if not ready:
        print('等了 90 分钟还没出包，退出')
        return 1

    # 2) CI 报告的 sha256（拿不到就退化为只用包内报告）
    txt = '' if no_api else (diag_for(run_id) or '')
    m_sha = re.search(r'\b([0-9a-f]{64})\b', txt)
    want = m_sha.group(1) if m_sha else None
    print('CI 报告 sha256:', (want or '?')[:16], flush=True)

    # 3) 取 artifact
    blob = download(artifact_url(run_id), 'artifact')
    z = zipfile.ZipFile(io.BytesIO(blob))
    ipa = [i for i in z.infolist() if i.filename.endswith('.ipa')]
    if not ipa:
        print('artifact 里没有 ipa:', [i.filename for i in z.infolist()])
        return 1
    data = z.read(ipa[0].filename)
    got = hashlib.sha256(data).hexdigest()
    print('下载到 %s: %d B sha256=%s' % (ipa[0].filename, len(data), got), flush=True)

    # 包内报告里的 sha256 作为第二来源
    inside = None
    for i in z.infolist():
        if i.filename.endswith('.txt') and 'report' in i.filename.lower():
            body = z.read(i.filename).decode('utf-8', 'replace')
            m = re.search(r'\b([0-9a-f]{64})\b', body)
            if m:
                inside = m.group(1)
                print('包内 %s sha256=%s' % (i.filename, inside[:16]), flush=True)
            break

    verdicts = []
    if want:
        verdicts.append(('CI 报告', got == want))
    if inside:
        verdicts.append(('包内报告', got == inside))
    for label, ok in verdicts:
        print('  %s 一致: %s' % (label, ok), flush=True)
    if any(not ok for _, ok in verdicts):
        print('校验失败，不落盘')
        return 1

    # 4) 落盘（文件名与版本号同源）
    name = 'Mewgenics-v%s-unsigned.ipa' % ver if ver else ipa[0].filename.replace('-relink', '')
    dst = os.path.join(OUTDIR, name)
    with open(dst, 'wb') as f:
        f.write(data)
    print('已写入 %s (%d B)' % (dst, os.path.getsize(dst)), flush=True)

    # 5) 装前门禁
    r = subprocess.run([sys.executable, os.path.join(ROOT, 'ios_port/verify_bundle.py'), dst],
                       capture_output=True, text=True)
    tail = (r.stdout + r.stderr).strip().splitlines()
    print('--- verify_bundle 门禁 (exit %d) ---' % r.returncode, flush=True)
    for line in tail[-25:]:
        print('   ', line, flush=True)
    print('GATE:', 'PASS' if r.returncode == 0 else 'FAIL', flush=True)
    return 0 if r.returncode == 0 else 6


if __name__ == '__main__':
    sys.exit(main())
