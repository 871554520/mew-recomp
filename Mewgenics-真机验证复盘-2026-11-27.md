# Mewgenics iOS 移植 · 真机验证复盘（2026-11-27）

路线 B（把安卓包里的 `lib/arm64-v8a/libmain.so` 重链接成 iOS dylib，由 MewHost 起）已经能在真机上把游戏拉起来，日志里有窗口、有 GL 上下文、在加载资源。当前还剩两个明确的卡点，修复都已提交、等出包验证。

> 本文只记录**有日志或本地实测支撑**的结论。凡是推断，都标了「推断」并给出依据。

---

## 0. 一句话结论

黑屏/闪退不是同一个问题，而是四层叠在一起的：

| 层 | 问题 | 状态 |
| :-- | :-- | :-- |
| 1 | 手动调用 12 个静态构造函数（v0.11.2 引入）→ 一调就 SIGSEGV | 已修（默认跳过），待出包 **v0.11.6** |
| 2 | 存档是 SQLite，存档目录不存在 → `unable to open database file` 直接退出 | 已修（宿主预建目录），含在 **v0.11.5+** |
| 3 | 50 个 shader 是桌面 GLSL `#version 150`，GLES 3.0 编不过 | 已修（改写 ES 3.00 + 散文件覆盖），待出包 **v0.11.7** |
| 4 | 导出表深度 446（dyld 上限 255），出现过一次 `trie too deep > 255` 拒绝加载 | 已修（路径压缩到 22），**但不是主因**，见 §3.1 |

真凶是第 1 层——是我自己在 v0.11.2 加的那段代码。第 4 层只是顺手排掉的真实隐患。

---

## 1. 交付物与真机结果对照

| 版本 | 大小 (B) | sha256（前 16） | 真机结果 |
| :-- | --: | :-- | :-- |
| v0.11.1 | 26,606,782 | — | 能跑：开窗、建 GL、加载 shader，最后死在 SQLite |
| v0.11.2 | 26,607,583 | `bad5a3d1550d5174` | dlopen 后立刻崩在 init_array（新增的手工调用） |
| v0.11.3 | 26,607,814 | `239d257d4b8d4dd2` | 同上（多了崩溃信号日志，比 v0.11.2 大 231 B） |
| v0.11.4 | 26,001,103 | `b87d7d975a0af9f1` | 导出表 446→22；**仍崩在 init_array**（日志已证） |
| v0.11.5 | 26,001,998 | `19118e137ae1c6e2` | 同 v0.11.4 + 预建存档目录；本次日志仍崩在 init_array |
| v0.11.6 | 待出 | — | 默认不调 init_array（`4488b8b`，未推） |
| v0.11.7 | 待出 | — | v0.11.6 + 50 个 shader 改写为 GLSL ES 3.00（`d6bde6f`，未推） |

对照参考：v0.9.0 的 dylib 导出表深度同样是 446 —— 说明这个深度从 v0.9.0 起就存在，**不是新引入的**。

---

## 2. 怎么读这两份日志（很重要）

真机上有两条独立的日志流，混着看会得出错误结论：

| 文件 | 谁写的 | 内容 | 特点 |
| :-- | :-- | :-- | :-- |
| `mew.log` | MewHost 的 `say()`（stderr 重定向） | `[host 0]`…`[host 5]`、`CRASH` | **跨安装累积**，一次启动约 35 行 |
| `runtime.log` | 游戏自己（转译进来的安卓代码） | `[load] [mod] [sdl] [gl] [file] [msgbox] [imp]` | 也是累积的 |

判定一次启动的锚点（按顺序）：

```
[host 0] main() entered          ← 一次启动的开始
[host 2] gpak exists=yes …
[host 3b] dlopen result h=0x… ok
[host 3c] mew_base=… set_base=…
[host 3d] init_array …           ← v0.11.2~v0.11.5 崩在这一行的下一行
[host 4] calling target _SDL_main at 0x…
[host 5] target _SDL_main returned rc=…
```

`[host 5]` 至今一次都没出现过 —— 游戏从来没有正常退出过。

---

## 3. 四层问题逐个说

### 3.1 导出表深度 446 > dyld 上限 255

**现象**：真机有一次报

```
[host 3b] dlopen result h=0x0 dlopen(libmew_relinked.dylib, …):
  … '/…/Mewgenics.app/Frameworks/libmew_relinked.dylib' (trie too deep > 255) …
```

**根因**：转换器 `tools/elf2macho_dylib.py` 的 `_build_trie()` 按**单个字符**建树，树深 = 最长符号名长度。游戏用 C++，mangled 名最长 446 字符，于是深度 446。

**修法**：路径压缩——把「没有终结符且只有一个子节点」的链压成一条多字符边（边的名字本来就允许任意长度），走查语义完全不变。

**实测**：

| 指标 | 修复前 | 修复后 |
| :-- | --: | --: |
| 导出表大小 | 1,466,088 B | 290,126 B |
| trie 节点数 | 205,540 | 9,215 |
| **最大深度** | **446** | **22** |
| 导出符号 | 5,985 | 5,985（全部原样还原） |
| rebase / bind | 76,945 / 1,348 | 76,945 / 1,348（不变） |
| `_SDL_main` | 0x4075e60 | 0x4075e60（不变） |
| dylib 大小 | 78,544,896 B | 77,365,248 B |

**重要澄清**：深度 446 **并不是**黑屏主因 —— 真机上绝大多数启动 dlopen 是成功的（`h=0x… ok`）。只有一次报了 `trie too deep`，推测是那个副本在设备上被侧载工具重签时损坏。所以这一项算「排掉的真实隐患」，不是根因。

顺带修了 `ios_port/verify_macho.py`：它的 trie 走查原来按「一次吃一个字符」写，压缩后立刻误报 `_SDL_main -> None`、`symtab 150/5985`，这就是 run `45897470340` 失败的原因（转换本身没问题）。改成前缀匹配后本地全过。

### 3.2 手动调用 init_array（真凶）

**现象**：`mew.log` 里凡是走到下面这行的启动，**下一行必然是崩溃**：

```
[host 3d] init_array 12 项，开始按序调用（静态构造）
[host] CRASH signal=11 —— 进程在这里被判死，看上一行日志定位
```

**证据链**：
- v0.11.2 / v0.11.3 / v0.11.4 / v0.11.5 每一轮都是这个模式（v0.11.4 的日志里有 4 次启动、4 次同样的崩法）。
- v0.11.4 那份日志里 `[host 3b]` 出现 74 次（37 次启动）、`[host 3d]` 只有 8 次（4 次启动）、`[host 4]` 有 60 次（30 次启动）—— 说明**能继续往下跑的 30 次全部来自没有 `[host 3d]` 这一行的老版本**。
- 老版本（≤ v0.11.1）能一路跑到开窗、建 GL 上下文、加载 shader，最后才死在 SQLite。

**根因**：Mach-O 没有 `__mod_init_func`，dyld 确实不会自动跑这 12 个构造器；但真机上由宿主代跑**必崩**。最可能是 `__cxa_atexit` / `__dso_handle` 这类构造期假设在 iOS（libSystem 的实现与 Android bionic 不同）上不成立。

**修法**：默认不调，只打一行说明；想复现/排查就在 Documents 放一个空文件 `.mew_try_init_array`，那时会逐项打印再调用。

```
[host 3d] init_array 12 项：默认跳过（手工调用会在静态构造里 SIGSEGV）
```

> 结论：这个游戏**不需要**这 12 个构造器也能跑起来（老版本已经证明了），所以跳过是安全的。

### 3.3 SQLite 存档库打不开

**现象**（v0.11.1 时代的日志）：

```
[msgbox] ERROR: unable to open database file
```

紧接着进程退出（用户看到的就是「闪退」）。

**证据**：紧邻的前几行就是线索——

```
[sdl] SDL_GetPrefPath(Glaiel Games, Mewgenics) -> ../pref/Glaiel Games/Mewgenics/
[file] CreateFileW C:\pref\…\76561197960265729\saves\test00.sav
       (../C/pref/Glaiel Games/Mewgenics/76561197960265729/saves/test00.sav) failed 2
```

`failed 2` = ENOENT，连 `saves` 目录本身都不存在。路径映射规律：游戏把 `C:\pref\…` 映射成 `../C/pref/…`（相对 cwd = `Documents/game`），也就是 `Documents/C/pref/…`。

**根因**：存档是 SQLite（游戏里是 `glaiel::SQLSaveFile`，exe 里能搜到 `saves/`、`PRAGMA user_version`、`sqlite_master`）。**SQLite 不会自己创建目录**，而这条链路上的 `CreateDirectoryW` 没真正生效 → 目录不存在 → 打不开库 → 直接退出。

**修法**：MewHost 在 `dlopen` 之前先 `mkdir -p` 一整套可写目录（已有的不动）：

```
<docs>/pref/Glaiel Games/Mewgenics/<steamid>/{saves,logs}
<docs>/C/pref/Glaiel Games/Mewgenics/<steamid>/{saves,logs}
<docs>/Resources/pref/Glaiel Games/Mewgenics/<steamid>/{saves,logs}
<game>/saves、<game>/logs
```

日志会多一行 `[host 3e] 可写目录已预建：…`。

> ⚠️ 这一项**还没有在真机上验证过**：v0.11.5 带着它上机了，但那次启动先崩在 init_array，还没走到存档那一步。

### 3.4 shader 是桌面 GLSL，GLES 编不过

**现象**（v0.11.1 时代的日志）：

```
[msgbox] WARNING: Error while compiling default.shader
ERROR: One or more attached shaders not successfully compiled
[msgbox] WARNING: Error while compiling default_gradient.shader
[msgbox] WARNING: Error while compiling default_full.shader
[msgbox] WARNING: Error while compiling paletted_full.shader
[msgbox] WARNING: Error while compiling to_distortion_map_full.shader
```

**根因**：游戏所有 shader 都是**桌面 OpenGL** 写法 `#version 150`（还有一个 `#version 430 core`），而 iOS 只有 OpenGL ES 3.0 → 对应 `#version 300 es`。桌面 GLSL 在 ES 上下文里连版本指令都过不去。

**语法面体检**（50 个 shader，86,075 字节）：

| 检查项 | 结果 |
| :-- | :-- |
| `texture2D` / `textureCube` | 0 处 |
| `gl_FragColor` / `gl_FragData` | 0 处 |
| `varying` / `attribute` | 0 处 |
| `dFdx` / `dFdy` / `fwidth` | 3 / 3 / 1（ES 3.00 里是核心功能，无需扩展） |
| `flat`、`round()` | 2、3（ES 3.00 都有） |
| `#version 150` | 47 个 |
| `#version 430 core` | 1 个 |
| 无版本行（include 片段） | 2 个 |

所以改写只有两步：版本行 → `#version 300 es`，再补 4 行 `precision`（ES 3.00 的片元着色器**必须**显式声明 float 精度，桌面版不需要）。改完 86,075 → 88,285 字节。

**怎么送到设备**：不用用户拷文件。资源管理器本来就会**先找散文件、找不到才回落 `resources.gpak`**（日志里那一堆 `CreateFileW shaders/*.shader … failed 2` 就是这次探测）。所以宿主在起游戏前把改写版写到 `<cwd>/shaders/`，游戏就会优先用这份：

```
[host 3f] shader 覆盖：写入 50 个 GLSL ES 3.00 版本（失败 0）-> …/game/shaders
```

配套工具：`tools/gen_shader_es3.py`（gpak → 改写 → 生成 C 头 `ios_port/shader_es3.h`，127,809 B）。

---

## 4. 关键数字

**包内布局**

| 项 | 数值 |
| :-- | --: |
| IPA 大小（v0.11.4 / v0.11.5） | 26,001,103 / 26,001,998 B |
| `libmew_relinked.dylib` | 77,365,248 B |
| 导出符号 / bind / rebase | 5,985 / 1,348 / 76,945 |
| 可核 bind（libSystem 除外） | 1,242 条，全部解析成功 |
| `MewHost` | 68,352 B |
| `resources.gpak` | 5,134,616,316 B，19,979 条目 |

**真机环境**：`Apple A19 GPU | OpenGL ES 3.0 Metal - 105 | GLSL ES 3.00`，显示 120 Hz（按 60 Hz 上报给游戏），窗口 `2532x1170`。

**方案二那条线（Windows exe 重编译）**，run `45899175205`（head `42ab30e`）：29 步全过，`UNIMPL FUNC TABLE distinct=0 total=0`（指令层已通），崩溃点从 `fault=0x8` 变成 `fault=0xc06b57238`（frames=23 的野指针），`gpak` 出现 0 次。

---

## 5. 现在到哪一步了

| 提交 | 内容 | 远端状态 |
| :-- | :-- | :-- |
| `b3e1df9` | 导出表路径压缩 + 门禁加深度检查 | 已推 |
| `4c3e754` | 修 stage3 `avx` 命名空间别名（`avx` 嵌在 `sse` 里） | 已推（随下一条） |
| `42ab30e` | 修 `verify_macho` trie 走查（支持多字符边） | 已推 |
| `1a5be08` | 预建存档/偏好目录（SQLite） | 已推 |
| `4488b8b` | **默认不调 init_array** | **未推** |
| `d6bde6f` | 50 个 shader 改写 GLSL ES 3.00 + 宿主落盘 | **未推** |

远端 `main` 目前停在 `1a5be08`，本地已到 `d6bde6f`。

---

## 6. 还没做的（按优先级）

**P0**

1. 出 v0.11.6 / v0.11.7 并在真机上验证三件事：`[host 3d] init_array 默认跳过` → `[host 3e]`/`[host 3f]` 两行到位 → 不再出现 `unable to open database file`。
2. shader 改写后是否真的不再报 `Error while compiling` 还没验证（这一版第一次上机）。
3. 仓库里 27 MB 的 APK 分片合规问题：需要用户提供 `MEW_ASSETS_TOKEN` 迁到私有资产仓。

**P1**

4. 走到 `Starting Game...` 之后的引擎初始化（触摸、音频、ANativeWindow 尺寸）。
5. `resources.gpak` 5.13 GB 的首次解析耗时与 Jetsam 风险未测。
6. 大 dylib 仍未做 ldid 签名（现在跳过大文件签名）。
7. 方案二那条线：野指针崩溃 `fault=0xc06b57238` 待查。

**P2**

8. `SDL_StretchSurface` 是等价实现（转调 `SDL_BlitSurfaceScaled`），不是原函数。
9. 方案二窗口只做到「假窗口 + 有界消息循环」，真 GL（EGL surfaceless）未做。
10. 匿名 GitHub API 只有 60 次/小时，巡检要节制；大文件下载必须 8 MB 分块。

---

## 7. 工具与流程备忘

| 工具 | 用途 |
| :-- | :-- |
| `tools/fetch_ipa.py <run_id> <ver>` | 等出包 → nightly.link 拉 artifact → 校验 sha256 → 落盘 → 跑装前门禁。API 配额耗尽时自动改用探针模式继续等 |
| `ios_port/verify_bundle.py <ipa>` | 装前门禁：依赖闭合 + 每条强绑定符号在所属库导出表里 + trie 深度 ≤ 255 |
| `ios_port/verify_macho.py <dylib>` | 转换器自检：段布局、rebase/bind 流、trie 走查、symtab 全覆盖 |
| `tools/ci_diag.py <run_id>` | 读 GitHub annotation 里的 base64 诊断摘要 |
| `tools/gen_shader_es3.py <gpak>` | 桌面 GLSL → GLSL ES 3.00，生成 `ios_port/shader_es3.h` |

**流程**：本机没有任何编译器（iOS 沙箱），所有构建都在 GitHub Actions；代码归我改，推送只由小炸鱼执行（它是唯一持有 `GITHUB_WORKFLOW_TOKEN` 的 Bot）。大文件（>20 MB）直连必断，要用 8 MB Range 分块或 nightly.link。

---

## 8. 下一步（按序）

1. 小炸鱼推 `4488b8b` + `d6bde6f` → 自动触发 iOS 出包（v0.11.7）。
2. `fetch_ipa.py` 取包 + 门禁 → 交付给用户。
3. 真机看这几行：

   ```
   [host 3b] dlopen result h=0x… ok
   [host 3d] init_array 12 项：默认跳过（…）
   [host 3e] 可写目录已预建：…
   [host 3f] shader 覆盖：写入 50 个 GLSL ES 3.00 版本（失败 0）
   [host 4] calling target _SDL_main at 0x…
   ```

   之后 `runtime.log` 里不该再有 `unable to open database file` 和 `Error while compiling`。
4. 若还有问题，按新日志继续定位；若走到 `Starting Game...`，转入渲染/输入验证阶段。
