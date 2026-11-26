#!/usr/bin/env bash
# 在 Linux 上编出 libmewcompat.dylib（arm64 / iOS 15）——不需要 Xcode、不需要 SDK。
#
# 它只补两个符号（原因见 ios_port/compat/mewcompat.c 头注释）：
#   _bionic_tlsdesc_resolver   ← TLSDESC 14 条强绑定
#   _SDL_StretchSurface        ← SDL 3.4 API，3.2.0 里没有
#
# 依赖 SDL3.framework/SDL3：SDL_BlitSurfaceScaled 从它来（链接期记录
# LC_LOAD_DYLIB = @rpath/SDL3.framework/SDL3），其余 libSystem 符号走
# -undefined dynamic_lookup，运行时由已加载的 libSystem 提供。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-${ROOT}/out}"
PROD="${OUT}/products"
REPORT="${OUT}/build_compat_linux.txt"
SDLFW="${SDLFW:-${PROD}/SDL3.framework}"
mkdir -p "$OUT" "$PROD"
: > "$REPORT"
say() { echo "==> [$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }
num() { echo "    $*" | tee -a "$REPORT"; }

CC="${CC:-clang}"
if [ -z "${LD64:-}" ]; then
    CC_BIN="$(dirname "$(command -v "$CC")")"
    for c in "$(command -v ld64.lld 2>/dev/null)" \
             "$CC_BIN/ld64.lld" \
             /usr/lib/llvm-*/bin/ld64.lld \
             /usr/bin/ld64.lld; do
        if [ -n "$c" ] && [ -x "$c" ]; then LD64="$c"; break; fi
    done
fi
LD64="${LD64:-ld64.lld}"

say "前置检查"
[ -f "$SDLFW/SDL3" ] || { echo "::error::缺少 SDL3 二进制：$SDLFW/SDL3（先解 Release 资产）"; exit 2; }
num "SDL3 = $SDLFW/SDL3 ($(stat -c%s "$SDLFW/SDL3" 2>/dev/null || stat -f%z "$SDLFW/SDL3") B)"
$CC --version | head -1 | tee -a "$REPORT"
"$LD64" --version 2>&1 | head -1 | tee -a "$REPORT" || true

say "编译（arm64-apple-ios15.0，无 SDK 头）"
# -nostdlibinc + 编译器内置头目录：只用 <stdint.h> 一类的 freestanding 头，
# 两个源文件实际上都不 include 任何头（原型自己声明）。
$CC -target arm64-apple-ios15.0 -O2 -fno-stack-protector -fno-builtin \
    -nostdlibinc -isystem "$($CC -print-resource-dir)/include" \
    -c "$ROOT/ios_port/compat/mewcompat.c" -o /tmp/mewcompat.o 2>&1 | tee -a "$REPORT"
# TLSDESC 的寄存器保全壳子直接复用 shim 里那份汇编（x1..x18 / q0..q31 必须原样返回）
$CC -target arm64-apple-ios15.0 -c "$ROOT/ios_port/shim/bionic_tlsdesc.S" -o /tmp/mewcompat_resolver.o 2>&1 | tee -a "$REPORT"
num "mewcompat.o $(stat -c%s /tmp/mewcompat.o) B  resolver.o $(stat -c%s /tmp/mewcompat_resolver.o) B"

say "链接（ld64.lld -> dylib）"
"$LD64" -arch arm64 \
    -platform_version ios 15.0 15.0 \
    -dylib \
    -install_name @rpath/libmewcompat.dylib \
    -undefined dynamic_lookup \
    -o "$PROD/libmewcompat.dylib" \
    /tmp/mewcompat.o /tmp/mewcompat_resolver.o "$SDLFW/SDL3" 2>&1 | tee -a "$REPORT"
num "libmewcompat.dylib $(stat -c%s "$PROD/libmewcompat.dylib") B"

say "产物自检（filetype / 导出符号 / 依赖）"
python3 - "$PROD/libmewcompat.dylib" 2>&1 | tee -a "$REPORT" <<'PY'
import struct, sys
path = sys.argv[1]
d = open(path, 'rb').read()
magic, cpu, sub, ft, ncmds = struct.unpack_from('<IIIII', d, 0)
print('    magic=0x%x cpu=%d filetype=%d(MH_DYLIB=6) ncmds=%d' % (magic, cpu, ft, ncmds))
assert magic == 0xFEEDFACF, '不是 64 位 Mach-O'
assert ft == 6, 'filetype 不是 MH_DYLIB'
assert cpu == 0x0100000C, 'CPU 不是 arm64'
o = 32
deps = []
trie = None
for _ in range(ncmds):
    cmd, csz = struct.unpack_from('<II', d, o)
    if cmd in (0xC, 0x80000018, 0x8000001F):
        x = struct.unpack_from('<I', d, o + 8)[0]
        deps.append(d[o + x:].split(b'\0')[0].decode())
    elif cmd == 0x80000033:
        trie = struct.unpack_from('<II', d, o + 8)
    elif cmd == 0x80000022:
        f = struct.unpack_from('<10I', d, o + 8)
        if f[8] and f[9] and trie is None:
            trie = (f[8], f[9])
    o += csz
print('    依赖: %s' % ', '.join(deps))
assert '@rpath/SDL3.framework/SDL3' in deps, '没有记录到 SDL3 依赖'
assert trie, '没有 export trie'
exports = set()
def uleb(p):
    v = 0; s = 0
    while True:
        b = d[p]; p += 1
        v |= (b & 0x7F) << s; s += 7
        if not b & 0x80:
            return v, p
def rec(off, prefix):
    p = trie[0] + off
    v, p = uleb(p)
    if v:
        exports.add(prefix); p += v
    n = d[p]; p += 1
    for _ in range(n):
        e = p
        while d[e]:
            e += 1
        nm = d[p:e].decode('utf-8', 'replace'); p = e + 1
        v, p = uleb(p)
        rec(v, prefix + nm)
rec(0, '')
print('    导出 %d 个' % len(exports))
for need in ('_bionic_tlsdesc_resolver', '_SDL_StretchSurface'):
    assert need in exports, '缺少导出 %s' % need
    print('    ✓ %s' % need)
PY

say "完成：$PROD/libmewcompat.dylib"
