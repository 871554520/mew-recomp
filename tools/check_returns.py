#!/usr/bin/env python3
"""无编译器环境下的兜底静态检查：非 void 函数里的裸 `return;`。

背景：这台机器上没有任何 C/C++ 编译器（iOS 沙箱），所有编译都在 GitHub Actions。
所以「把函数返回类型从 void 改成 uint64_t，却忘了同步函数体里的 `return;`」这种
错误只能等 CI 的语法门禁（约 1 分钟）报回来，一来一回就是一次 round trip。
这个脚本用大括号配平 + 函数签名扫描，把这类错误在本地先抓出来。

用法：
    python3 tools/check_returns.py runtime/src/*.cpp lifter/src/*.cpp shims/*.cpp

退出码 0 表示没发现问题，1 表示有（会列出来源行）。
"""
import re
import sys

# 粗略但够用的函数定义匹配：返回类型 + 名字 + 参数列表 + '{'
BARE_RETURN = re.compile(r'\breturn\s*;')
# 先剥掉字符串 / 字符字面量和 // 注释，否则 `e.out << "... return;\n"` 这种
# 「发代码文本」的行会被误报（实际报过 24 条这种假阳性）。
STR_LIT = re.compile(r'"(?:\\.|[^"\\])*"')
CHR_LIT = re.compile(r"'(?:\\.|[^'\\])*'")

# lambda（[&](...) { ... } 或 [=](...) { ... }）按 void 处理，否则它的裸
# return; 会被算到外层函数名下（实际踩过一次假阳性）。
LAMBDA_RE = re.compile(r'\[\s*[&=]?\s*\]\s*\([^;{}]*\)\s*(?:->\s*[\w:<>*&\s]+)?\{')

FUNC_RE = re.compile(
    r'^[ \t]*(?:template\s*<[^>]*>\s*)?'
    r'(?P<ret>(?:static\s+|inline\s+|extern\s+|constexpr\s+|virtual\s+)*'
    r'(?:unsigned\s+|signed\s+)?[A-Za-z_][\w:]*(?:\s*<[^;{}()]*>)?(?:\s*[*&]+)?)'
    r'\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*'
    r'(?:const\s*)?(?:noexcept\s*)?\{?\s*$'
)


def scan(path):
    """返回 [(行号, 函数名, 返回类型, 原文)]。"""
    try:
        lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
    except OSError as e:
        print('跳过 %s: %s' % (path, e))
        return []

    problems = []
    # 栈：(函数名, 返回类型, 该函数体的起始大括号深度)
    stack = []
    depth = 0
    for no, line in enumerate(lines, 1):
        stripped = line.strip()
        # 进入一个函数体？
        if LAMBDA_RE.search(line):
            stack.append(('<lambda>', 'void', depth))
        m = FUNC_RE.match(line)
        if m and '{' in line:
            ret = m.group('ret').strip()
            stack.append((m.group('name'), ret, depth))

        probe = STR_LIT.sub('", "', line)
        probe = CHR_LIT.sub("''", probe)
        probe = probe.split('//')[0]
        if BARE_RETURN.search(probe):
            for name, ret, d in reversed(stack):
                base = ret.replace('static', '').replace('inline', '').replace('constexpr', '').strip()
                if base and base != 'void' and not base.endswith('void'):
                    problems.append((no, name, ret, stripped))
                break

        depth += line.count('{') - line.count('}')
        # 深度回到函数起点以下，说明那个函数已经结束
        while stack and depth <= stack[-1][2]:
            stack.pop()
    return problems


def main(argv):
    total = 0
    for path in argv[1:]:
        for no, name, ret, text in scan(path):
            print('%s:%d: 非 void 函数 %s() 里出现裸 `return;`（返回类型 %s）'
                  % (path, no, name, ret))
            total += 1
    if total:
        print('\n共 %d 处：改成 `return <值>;`（通常是 return 0 / false / nullptr）。' % total)
        return 1
    print('检查通过：没发现非 void 函数里的裸 return;')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
