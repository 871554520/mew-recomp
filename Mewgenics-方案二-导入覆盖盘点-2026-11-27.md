# 方案二：PE 导入表 vs 垫片覆盖盘点（2026-11-27）

> 目的：在跑 CI 之前先把「还差多少垫片、下一堵墙在哪」算清楚，避免每轮只靠日志猜。
> 数据：本机直接解析 `Mewgenics.exe`（22,019,072 B，sha256 `4127cd6a…`）的导入目录，
> 与仓库里**强定义**的垫片（`void shim_<DLL>_<name>(X64Ctx*…)`）对照。
> 口径：`[UNIMPL API]` 命中的是**没有强定义**的导入——它们由 lifter 生成的
> `__attribute__((weak))` 占位顶上，打印一行后 `rax=0`。所以「缺」= 一定会在未来某条路径上炸/静默返回 0。

## 1. 总账

| 项 | 数量 |
|---|---|
| 导入符号总数（12 个 DLL） | **455** |
| 有强垫片（真实现） | **111** |
| 只有弱占位（`[UNIMPL API]`） | **344** |

| DLL | 导入 | 已实现 | 缺 |
|---|---:|---:|---:|
| KERNEL32.dll | 211 | 109 | **102** |
| USER32.dll | 138 | 2 | **136** |
| OPENGL32.dll | 27 | 0 | **27** |
| GDI32.dll | 24 | 0 | **24** |
| IMM32.dll | 11 | 0 | **11** |
| ole32.dll | 11 | 0 | **11** |
| SHELL32.dll | 10 | 0 | **10** |
| SETUPAPI.dll | 8 | 0 | **8** |
| steam_api64.dll | 7 | 0 | **7** |
| VERSION.dll | 3 | 0 | **3** |
| ADVAPI32.dll | 3 | 0 | **3** |
| WINMM.dll | 2 | 0 | **2** |

注意：仓库里 239 个 `shim_KERNEL32_*` 强定义，其中约 130 个是 PE **并不导入**的（GetProcAddress 动态取用的那条路），所以「已实现 109/211」不等于「代码只写了一半」。

## 2. 下一堵墙的排序（按「启动必经」判）

1. **CRT/堆/异常**（KERNEL32 内核态那部分）—— 本轮正在打，`HeapReAlloc` 是本轮的主角。
2. **窗口与消息循环（USER32 136 个）**—— 一旦开始建窗口，就会连片撞墙：
   `RegisterClassW/CreateWindowExW/GetMessageW/PeekMessageW/DispatchMessageW/DefWindowProcW/WndProc` 这一串不是「缺一个补一个」能过的，需要一套最小窗口实现。
3. **GL 上下文（GDI32 24 + OPENGL32 27）**—— `ChoosePixelFormat/SetPixelFormat/DescribePixelFormat/SwapBuffers` 与 `wglCreateContext/wglMakeCurrent/wglGetProcAddress` 必须成套；单独补 `glClear` 那类 leaf 没有意义。
4. **工程性外设**（IMM32 / ole32 / SHELL32 / SETUPAPI / VERSION / ADVAPI32）——多半只在「输入法、拖放、注册表读版本、设备枚举」这些冷路径上被调，先补成「如实失败」比补成「假装成功」安全。
5. **steam_api64 7 个**——`SteamAPI_RestartAppIfNecessary` 必须返回 0（不重启），`SteamAPI_Init*` 返回 false 让游戏走单机分支；这几个补起来最便宜、收益最直接。

## 3. 判据（下一轮怎么用这张表）

- CI 的 Stage 5 现在会在退出或 `timeout` 前打 `[UNIMPL API] TABLE`（distinct + total + 按名字）。
- 表里出现的新名字，直接按 §2 的优先级决定补哪个 DLL；**同一张表连跑两轮不变**才说明这条路走到底了。
- 禁止为了「让日志好看」把占位改成「返回非零假装成功」——`HeapReAlloc` 就是反例：它返回 0 时上层把 NULL 存进链表，最后以 `fault=0x10` 的形式在别处炸。

## 4. 本轮已补（对应 P0-2）

| API | 处理 |
|---|---|
| `HeapReAlloc` | 真实现：`lpMem=NULL` 等价 HeapAlloc；最新块原地扩；否则 alloc+memcpy+free；`IN_PLACE_ONLY` 如实拒绝；`ZERO_MEMORY` 只清新增尾部 |
| `HeapSize` | 返回登记的请求字节数 |
| `HeapValidate` / `HeapCompact` / `HeapCreate` / `HeapDestroy` / `HeapSetInformation` / `HeapQueryInformation` | 语义最小实现（不假装能压缩；查询写 0） |
| `FreeEnvironmentStringsW` | 返回 1（与 `GetEnvironmentStringsW` 的常驻块配对） |
| `WideCharToMultiByte` | 真写缓冲区（旧实现只返回长度，调用方读到空串）；第 5/6 参数从栈取；`cchWideChar=-1` 含结尾 NUL |
