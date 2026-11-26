#!/usr/bin/env bash
# 在 Linux 上组装 IPA：不需要 macOS、不需要 Xcode。
#
# 前提：三件「只能由 macOS 编出来」的产物已经在 out/products/ 里：
#   out/products/MewHost
#   out/products/libbionic_shim.dylib
#   out/products/SDL3.framework/            （整个目录）
# 加上 Ubuntu 侧刚产出的 out/libmew_relinked.dylib 与仓库里的 Info.plist，
# 就能组出结构完整的 .app 并压成 .ipa。
#
# 签名：装到真机时 TrollStore / AltStore / Sideloadly 都会重新签名，所以这里
# **不强制** codesign。如果环境里有 ldid，就顺手做一次 ad-hoc 签名；没有就
# 产出未签名包并在报告里写明。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-${ROOT}/out}"
PROD="${OUT}/products"
REPORT="${OUT}/assemble_report.txt"
mkdir -p "$OUT"
: > "$REPORT"
say() { echo "==> [$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }
num() { echo "    $*" | tee -a "$REPORT"; }

DYLIB="${OUT}/libmew_relinked.dylib"
HOST="${PROD}/MewHost"
SHIM="${PROD}/libbionic_shim.dylib"
SDLFW="${PROD}/SDL3.framework"
PLIST="${ROOT}/ios_port/ios_app/Info.plist"

for f in "$DYLIB" "$HOST" "$SHIM"; do
    [ -f "$f" ] || { echo "缺少必需产物: $f" | tee -a "$REPORT"; exit 2; }
    num "$(basename "$f") $(stat -c%s "$f" 2>/dev/null || stat -f%z "$f") bytes"
done
[ -d "$SDLFW" ] || { echo "缺少 SDL3.framework: $SDLFW" | tee -a "$REPORT"; exit 2; }

# 硬门禁：旧版 MewHost（裸 main、无日志）绝不允许再被打包成 v0.3.0
say "MewHost 门禁（SDL_RunApp + mew.log）"
STRINGS="$(command -v strings || true)"
check_str() {
    if [ -n "$STRINGS" ]; then "$STRINGS" "$1" | grep -q "$2"; else
        python3 - "$1" "$2" <<'PY'
import sys
needle = sys.argv[2].encode()
data = open(sys.argv[1], 'rb').read()
sys.exit(0 if needle in data else 1)
PY
    fi
}
check_str "$HOST" "SDL_RunApp" || { echo "::error::MewHost 缺少 SDL_RunApp（会是白屏），拒绝打包" | tee -a "$REPORT"; exit 3; }
check_str "$HOST" "mew.log"    || { echo "::error::MewHost 缺少 mew.log（不会有日志），拒绝打包" | tee -a "$REPORT"; exit 4; }
num "SDL_RunApp ✓  mew.log ✓"
[ -f "$PLIST" ] || { echo "缺少 Info.plist: $PLIST" | tee -a "$REPORT"; exit 2; }

# ldid 可选
LDID="$(command -v ldid || true)"
if [ -n "$LDID" ]; then
    say "找到 ldid: $LDID（会做 ad-hoc 签名）"
else
    say "没有 ldid，产出未签名包（侧载工具会重签）"
fi

APP="${OUT}/Mewgenics.app"
say "组 .app"
rm -rf "$APP"
mkdir -p "$APP/Frameworks"
cp "$HOST" "$APP/MewHost"
cp "$PLIST" "$APP/Info.plist"
cp "$DYLIB" "$APP/Frameworks/libmew_relinked.dylib"
cp "$SHIM" "$APP/Frameworks/libbionic_shim.dylib"
cp -R "$SDLFW" "$APP/Frameworks/"

# 图标（iOS 要求放在 .app 根目录，文件名与 CFBundleIconFiles 对应）
ICONDIR="${ROOT}/ios_port/ios_app/icons"
if [ -d "$ICONDIR" ]; then
    cp "$ICONDIR"/*.png "$APP/" 2>/dev/null || true
    num "图标 $(ls "$ICONDIR" | wc -l | tr -d ' ') 个"
fi

# SDL3.framework 的 Info.plist 如果缺失就补一个
if [ ! -f "$APP/Frameworks/SDL3.framework/Info.plist" ]; then
    python3 - "$APP/Frameworks/SDL3.framework/Info.plist" <<'PY'
import sys, plistlib
plistlib.dump({
    'CFBundleIdentifier': 'org.libsdl.SDL3',
    'CFBundleName': 'SDL3',
    'CFBundleExecutable': 'SDL3',
    'CFBundlePackageType': 'FMWK',
    'CFBundleShortVersionString': '3.2.0',
    'CFBundleVersion': '1',
    'MinimumOSVersion': '15.0',
}, open(sys.argv[1], 'wb'))
print('    SDL3.framework/Info.plist 已补')
PY
fi

# 只给「小文件」做 ldid 签名。
# 实测坑：ldid 给 78 MB 的 libmew_relinked.dylib 签名后会把它截成 77,245,008 B，
# 导致 __LINKEDIT 覆盖不到 export trie，dyld 报
#   "LINKEDIT content 'exports trie' extends beyond end of segment"
# 侧载工具（TrollStore/AltStore/Sideloadly）本来就会重签，所以大文件跳过完全没问题。
LDID_MAX_BYTES=$((8 * 1024 * 1024))
if [ -n "$LDID" ]; then
    say "ad-hoc 签名（ldid，仅 ≤8MB 的文件）"
    for f in "$APP/Frameworks/SDL3.framework/SDL3" "$APP/Frameworks/libbionic_shim.dylib" "$APP/MewHost"; do
        sz=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")
        if [ "$sz" -le "$LDID_MAX_BYTES" ]; then
            "$LDID" -S "$f" 2>&1 | tee -a "$REPORT" || true
            num "ldid $(basename "$f") ($sz B)"
        else
            num "跳过 ldid：$(basename "$f") ($sz B > 8MB)"
        fi
    done
    num "跳过 ldid：libmew_relinked.dylib（大文件会被 ldid 截断）"
else
    say "没有 ldid，产出未签名包（侧载工具会重签）"
fi

# 结构自检：必须是 Payload/Mewgenics.app 且可执行位在 MewHost 上
chmod +x "$APP/MewHost"
say "结构自检"
test -x "$APP/MewHost" && num "MewHost 可执行 ✓"
test -f "$APP/Info.plist" && num "Info.plist ✓"
test -f "$APP/Frameworks/libmew_relinked.dylib" && num "libmew_relinked.dylib ✓"
test -f "$APP/Frameworks/libbionic_shim.dylib" && num "libbionic_shim.dylib ✓"
test -f "$APP/Frameworks/SDL3.framework/SDL3" && num "SDL3.framework ✓"
python3 - "$APP/Info.plist" <<'PY' | tee -a "$REPORT"
import sys, plistlib
p = plistlib.load(open(sys.argv[1], 'rb'))
for k in ('CFBundleExecutable', 'CFBundleIdentifier', 'UIFileSharingEnabled',
          'LSSupportsOpeningDocumentsInPlace'):
    print('    %-34s %s' % (k, p.get(k)))
PY

say "打包 .ipa"
PAY="${OUT}/Payload"
rm -rf "$PAY"
mkdir -p "$PAY"
cp -R "$APP" "$PAY/"
IPA="${OUT}/Mewgenics-relink-v0.3.0-unsigned.ipa"
rm -f "$IPA"
if command -v zip >/dev/null; then
    (cd "$OUT" && zip -qry "$IPA" Payload)
else
    # 容器里没有 zip 时用 Python 兜底（保留可执行位与符号链接语义）
    python3 - "$OUT" "$IPA" <<'PY'
import os, sys, zipfile
root, ipa = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(ipa, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
    for base, _dirs, files in os.walk(os.path.join(root, 'Payload')):
        for f in files:
            full = os.path.join(base, f)
            rel = os.path.relpath(full, root)
            st = os.stat(full)
            zi = zipfile.ZipInfo(rel)
            zi.external_attr = (0o100000 | (st.st_mode & 0o777)) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(full, 'rb') as fh:
                z.writestr(zi, fh.read())
print('    python zipfile 打包完成')
PY
fi
num "app $(du -sm "$APP" | cut -f1) MB"
num "ipa $(stat -c%s "$IPA" 2>/dev/null || stat -f%z "$IPA") bytes"
say "打包后完整性校验"
python3 - "$IPA" "$DYLIB" <<'PY'
import sys, zipfile, struct
ipa, src = sys.argv[1], sys.argv[2]
z = zipfile.ZipFile(ipa)
name = 'Payload/Mewgenics.app/Frameworks/libmew_relinked.dylib'
d = z.read(name)
src_size = len(open(src, 'rb').read())
print('    包内 dylib %d B / 源文件 %d B' % (len(d), src_size))
assert len(d) == src_size, '包内 dylib 被改动过（ldid 截断？）'

ncmds = struct.unpack_from('<I', d, 16)[0]
o = 32
link = None
ex = None
for _ in range(ncmds):
    cmd, csz = struct.unpack_from('<II', d, o)
    if cmd == 0x19:
        nm = d[o+8:o+24].rstrip(b'\0').decode()
        vm, vs, fo, fs = struct.unpack_from('<QQQQ', d, o+24)
        if nm == '__LINKEDIT':
            link = (fo, fs)
    if cmd == 0x80000022:
        f = struct.unpack_from('<10I', d, o+8)
        ex = (f[8], f[9])
    o += csz
assert link and ex, '找不到 __LINKEDIT 或 dyld_info'
ex_off, ex_sz = ex
fo, fs = link
end = ex_off + ex_sz
print('    export trie [0x%x, 0x%x)  __LINKEDIT [0x%x, 0x%x)' % (ex_off, end, fo, fo+fs))
assert end <= fo + fs, 'export trie 超出 __LINKEDIT（dyld 会拒绝加载）'
print('    LINKEDIT 覆盖 export trie ✓')
PY
# ldid 安全性探针：在副本上签名，看新顺序（STRTAB 在最末）是否还会被截断。
# 只探测、不影响产物；结果进报告，方便以后决定要不要给大文件签名。
if [ -n "$LDID" ]; then
    cp "$DYLIB" /tmp/ldid_probe.dylib
    before=$(stat -c%s /tmp/ldid_probe.dylib 2>/dev/null || stat -f%z /tmp/ldid_probe.dylib)
    "$LDID" -S /tmp/ldid_probe.dylib >/dev/null 2>&1 || true
    after=$(stat -c%s /tmp/ldid_probe.dylib 2>/dev/null || stat -f%z /tmp/ldid_probe.dylib)
    if [ "$before" = "$after" ]; then
        num "ldid 探针：新顺序下签名后大小不变（$after B）→ 以后可以给大文件签名"
    else
        num "ldid 探针：签名后 $before -> $after B（仍会改文件→继续跳过大文件签名）"
    fi
fi

say "完成：$IPA"
