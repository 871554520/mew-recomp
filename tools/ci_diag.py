#!/usr/bin/env python3
"""从公开的 check-runs/annotations 接口取 CI 诊断摘要（base64 notice）。

用法: python3 ci_diag.py <run_id 或 sha>
"""
import base64, json, sys, urllib.request

REPO = '871554520/mew-recomp'
def api(url, tries=4):
    import http.client, time
    last = None
    for _ in range(tries):
        try:
            req = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json',
                                                       'User-Agent': 'dsh-lead'})
            buf = b''
            try:
                with urllib.request.urlopen(req, timeout=60) as f:
                    while True:
                        c = f.read(1 << 16)
                        if not c:
                            break
                        buf += c
            except http.client.IncompleteRead as e:
                buf += e.partial
            return json.loads(buf.decode('utf-8'))
        except Exception as e:
            last = e
            time.sleep(2)
    raise last

arg = sys.argv[1]
sha = arg
if arg.isdigit():
    run = api('https://api.github.com/repos/%s/actions/runs/%s' % (REPO, arg))
    sha = run['head_sha']
    print('run %s: %s %s sha=%s' % (arg, run['name'], run['conclusion'], sha[:8]))
crs = api('https://api.github.com/repos/%s/commits/%s/check-runs' % (REPO, sha))
found = 0
for c in crs.get('check_runs', []):
    anns = api('https://api.github.com/repos/%s/check-runs/%s/annotations' % (REPO, c['id']))
    for a in anns:
        t = a.get('title') or ''
        if t.startswith('diag-b64'):
            found += 1
            print('\n===== %s / %s =====' % (c['name'], t))
            try:
                print(base64.b64decode(a['message']).decode('utf-8', 'replace'))
            except Exception as e:
                print('解码失败:', e, a['message'][:100])
    if c['conclusion'] not in ('success', 'skipped', None) and not anns:
        print('[%s] %s（无注解）' % (c['name'], c['conclusion']))
print('\n找到 %d 条 diag annotation' % found)
