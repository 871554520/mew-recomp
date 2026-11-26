#!/usr/bin/env python3
"""把 resources.gpak 里的 shader 转成 GLSL ES 3.00，生成 ios_port/shader_es3.h。

为什么要这么做：游戏里所有 shader 都是**桌面版 OpenGL** 的
    #version 150
（还有个 `#version 430 core`），而 iOS 上只有 OpenGL ES 3.0，对应
    #version 300 es
真机日志里就是一片
    [msgbox] WARNING: Error while compiling default.shader
    ERROR: One or more attached shaders not successfully compiled
桌面 GLSL 150 在 ES 上下文里第一条指令就过不去。

好消息是这套 shader 的语法本来就是「现代」写法：没有 texture2D/gl_FragColor/
varying/attribute，`in`/`out`/`texture()`/`flat`/`round()`/`dFdx()` 在 ES 3.00
里全都有。所以改写只有两步：
  1) 版本行 -> `#version 300 es`
  2) 补精度声明（ES 3.00 的片元着色器**必须**声明 float 精度，桌面版不需要）

用法：
    python3 tools/gen_shader_es3.py <resources.gpak> [-o ios_port/shader_es3.h]
"""
import argparse
import struct
import sys

HEADER = """// 由 tools/gen_shader_es3.py 生成，不要手改。
// 来源：resources.gpak 里的 %d 个 .shader（桌面 GLSL -> GLSL ES 3.00）
#pragma once

typedef struct {
    const char* name;   // 相对路径，例如 "shaders/default.shader"
    const char* src;    // 改写后的源码
} mew_es3_shader;

static const mew_es3_shader kMewEs3Shaders[] = {
"""


def read_gpak(path):
    """gpak：u32 条目数 + 每条 (u16 名长, 名, u32 大小) 的索引，之后数据顺序存放。"""
    f = open(path, 'rb')
    n = struct.unpack('<I', f.read(4))[0]
    ents = []
    for _ in range(n):
        ln = struct.unpack('<H', f.read(2))[0]
        name = f.read(ln).decode('utf-8', 'replace')
        size = struct.unpack('<I', f.read(4))[0]
        ents.append([name, size, 0])
    base = f.tell()
    for e in ents:
        e[2] = base
        base += e[1]
    out = {}
    for name, size, off in ents:
        f.seek(off)
        out[name] = f.read(size)
    f.close()
    return out


def to_es3(src):
    """桌面 GLSL -> GLSL ES 3.00。返回 (新源码, 改动说明列表)。"""
    notes = []
    text = src.decode('utf-8', 'replace').replace('\r\n', '\n').replace('\r', '\n')
    lines = text.split('\n')
    if not lines:
        return text, notes

    # 1) 版本行：必须在第一行（GLSL 规定 #version 只能是第一段非注释内容）
    first = lines[0].strip()
    if first.startswith('#version'):
        if '300 es' not in first:
            lines[0] = '#version 300 es'
            notes.append('version:%s' % first)
        else:
            notes.append('version:already-es')
    else:
        # 没有版本行的（include 片段）不动，它会被拼进有版本行的 shader 里
        notes.append('version:none')
        return text, notes

    # 2) 精度声明：ES 3.00 片元着色器没有默认 float 精度，必须显式声明。
    #    顶点着色器里声明同样的东西是合法的，所以无条件加，顶点/片元两条分支都覆盖。
    prec = [
        'precision highp float;',
        'precision highp int;',
        'precision highp sampler2D;',
        'precision highp samplerCube;',
    ]
    if not any(l.strip().startswith('precision ') for l in lines[1:6]):
        lines[1:1] = [''] + prec
        notes.append('precision:+4')
    else:
        notes.append('precision:already')

    return '\n'.join(lines), notes


def c_literal(s):
    out = ['"']
    for ch in s:
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '\n':
            out.append('\\n"\n        "')
        elif ch == '\t':
            out.append('\\t')
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append('\\x%02x' % (ord(ch) & 0xff))
    out.append('"')
    return ''.join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('gpak')
    ap.add_argument('-o', '--out', default='ios_port/shader_es3.h')
    a = ap.parse_args()

    files = read_gpak(a.gpak)
    shaders = {k: v for k, v in files.items() if k.endswith('.shader')}
    if not shaders:
        print('包里没有 .shader'); return 1

    conv = {}
    stats = {}
    for name in sorted(shaders):
        new, notes = to_es3(shaders[name])
        conv[name] = new
        for n in notes:
            key = n.split(':')[0] + ':' + n.split(':')[1] if ':' in n else n
            stats[key] = stats.get(key, 0) + 1

    with open(a.out, 'w') as o:
        o.write(HEADER % len(conv))
        for name in sorted(conv):
            o.write('    { %s,\n      %s },\n' % (c_literal(name), c_literal(conv[name])))
        o.write('    { 0, 0 }\n};\n')

    print('生成 %s' % a.out)
    print('  shader %d 个，原始 %d 字节，改写后 %d 字节'
          % (len(conv), sum(len(v) for v in shaders.values()),
             sum(len(v.encode()) for v in conv.values())))
    for k in sorted(stats):
        print('  %-22s %d' % (k, stats[k]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
