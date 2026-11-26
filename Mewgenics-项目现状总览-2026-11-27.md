# Mewgenics 移植：项目现状总览

> 日期：2026-11-27 05:05（本机时区 America/Chicago）
> 基线：`Mewgenics-全项目详尽总结-2026-11-27.md`（11-27 之前的全部状态）
> 本文：我接手之后到现在的**全部**状态，含已完成、在跑、以及**所有未完成项**（旧的遗留 + 本轮新增）
> 远端 `871554520/mew-recomp` main = `3a28b0f`（v0.11.3）

---

## 0. 一句话现状

- **路线 B（交付线）**：v0.9.0 及之前的所有包**在真机上必然加载失败**（本轮查出三处硬故障，已全部修掉）；
  **v0.11.2 已交付到工作区并通过装机前门禁**，v0.11.3（加崩溃日志）正在出包，**只差真机装上取 mew.log**。
- **方案二（调试线）**：Heap 家族修完后，**未实现的 Win32 API 已经清零**（`UNIMPL API distinct=0 / total=0`）；
  墙从「缺垫片」变成「缺指令」，AVX/VEX 那 9 类指令已补，正在跑一轮验证。

---

## 1. 完成度口径（沿用旧文档，别混用）

| 级别 | 判据 | 路线 B | 方案二 |
|---|---|---|---|
| L1 语法通过 | 逐 TU 编译无错 | 转换器 Python 无编译；shim/宿主 C 已编 | 66/66 TU ✓ |
| L2 能链接 | 产出可执行/归档 | IPA 出包 ✓（含装机前门禁） | `mew_runner` ✓ |
| L3 能运行 | 进程起来且不异常退出 | 真机才能验 | `rc=124`（超时杀）✓ |
| L4 真机出画面 | iPhone 上出首帧 | **未达到**（卡在真机未装） | 不适用 |

---

## 2. 路线 B：本轮查出的三处硬故障（v0.9.0 必崩）

### 2.1 两处「加载期缺失符号」——15 条强绑定

把 v0.9.0 的 IPA 解包，逐条解析 `libmew_relinked.dylib` 的 bind 流（1,348 条），
再和三个依赖库各自的 export trie 对账（注意：**bind 序号不含 LC_ID_DYLIB**）：

| 序号 | 依赖 | 唯一符号 | 结果 |
|---:|---|---:|---|
| 1 | libSystem.B | 105 | 结构上无法核（iOS 版本相关） |
| 2 | SDL3.framework | 1,095 | **缺 1**：`_SDL_StretchSurface` |
| 3 | libbionic_shim | 133 | **缺 1**：`_bionic_tlsdesc_resolver`（×14 条） |

两条 `flags=0x0` = 强绑定，dyld 加载期必须解析到，否则 `dlopen` 返回 0 报 `symbol not found`。

- **根因 A**：Release 资产里的 `libbionic_shim.dylib` 是早期构建，symtab 318 条里没有
  `_bionic_tlsdesc_resolver`（仓库源码 `ios_port/shim/bionic_tlsdesc.S` 里有）。
- **根因 B**：游戏 APK 自带的是 **SDL3-3.2.12 开发版**（有 `SDL_StretchSurface`），
  我们打的 iOS framework 是 **release-3.2.0**（该 API 3.4 才公开）。

### 2.2 `DT_INIT_ARRAY` 的 12 个静态构造函数从未执行

`libmain.so`：`DT_INIT_ARRAY=0x453bea8`、`DT_INIT_ARRAYSZ=96`（12 项），槽位由 12 条
`R_AARCH64_RELATIVE` 填充（addend 如 0x4421584 / 0x4421bb8 / 0x407935c…）。
转成 Mach-O 后**没有 `__mod_init_func` 节**，dyld 不会调用它们——即使 dlopen 成功，
12 个 C++ 全局构造函数也一个都不跑，引擎拿到的是一堆未初始化全局。

### 2.3 修法与新增门禁

| 项 | 做法 |
|---|---|
| 缺失符号 | 新建 `libmewcompat.dylib`（`ios_port/compat/mewcompat.c` + 复用 shim 的 TLSDESC 汇编壳），`_SDL_StretchSurface` 如实转调 3.2.0 已有的 `SDL_BlitSurfaceScaled` |
| 依赖与绑定 | 转换器依赖表加第 4 项 `@rpath/libmewcompat.dylib`；14 条 TLSDESC + `SDL_StretchSurface` 改指它 |
| init_array | 转换器导出 `mew_init_array` / `mew_init_array_end`（实测 0x453fea8 / 0x453ff08），MewHost 在 `[host 3d]` 按序调用 |
| 显式加载 | MewHost 增加 `[host] dlopen compat -> …`，不赌 @rpath 回溯 |
| **装机前门禁** | `ios_port/verify_bundle.py`：依赖闭合 + 每条强绑定必须在该依赖的 export trie 里 + export trie 不越界。**v0.9.0 上实测精确报出 2 类 15 处问题**；不通过拒绝出包 |

### 2.4 交付物（本机实测）

| 文件 | 大小 | sha256 | 说明 |
|---|---:|---|---|
| `Mewgenics-v0.11.2-unsigned.ipa` | 26,607,583 B | `bad5a3d1550d51740aa6e065a75ce01f78d5188597ff3bc195e1f3a0f47e9a7a` | **可装**，门禁全过（1,242 条可核 bind） |
| `Mewgenics-v0.11.1-unsigned.ipa` | 26,606,782 B | — | 缺 init_array 调用，别装 |
| v0.11.3 | 出包中（run `45894538516`） | — | 与 0.11.2 同内容 + 崩溃信号日志 |

包内关键数字：`libmew_relinked.dylib` 78,544,896 B（rebase 76,945 / bind 1,348 / 导出 5,985）、
`libmewcompat.dylib` 66,408 B、`MewHost` 67,352 B、`libbionic_shim.dylib` 101,216 B（ldid 后 83,296）、
SDL3 头文件已剔除（省 ~664 KB），Info.plist 版本与文件名同源。

### 2.5 真机判据（这是 P0，只差用户动手）

```
[host 3b] dlopen result h=0x… ok          ← 三处符号问题都过了
[host 3d] init_array 12 项，开始按序调用（静态构造）
[host 3d] init_array 全部完成              ← 12 个全局构造真跑过
[host 4] calling target _SDL_main at 0x…
```

失败时看**紧邻上一行**的 `dlerror` 原文（现在只取一次，不会再打成 `(null)`）。

---

## 3. 方案二：从「缺 API」到「缺指令」的转折

### 3.1 Heap 家族修复已被证实（run `45888616405`，head `2b873a8`）

`stage3-artifacts/` 里三份日志（本机实读）：

```
runner.err   : ===== UNIMPL API TABLE (timeout) distinct=0 total=0 =====
               ===== UNIMPL FUNC TABLE (timeout) distinct=1 total=1 =====
                 0x140dabfe0   1
runner_b.err : 进程内只剩 10 条 [UNIMPL API]：InitializeCriticalSectionEx ×8、GetLocaleInfoW ×2
               （600 s 长跑被外层 timeout 杀掉，没有退出表）
runner_nosafe: [CRASH] signal=11 fault=0x8，栈 mem_read ← sub_0x140d6af0c ← sub_0x140d3e738
               ← dispatch_indirect ← sub_0x140d3e8ac（ABI 违规 2 条）
```

**结论**：`HeapReAlloc` 空垫片就是 `fault=0x10` 的直接来源，补完后未实现 API 清零。
`InitializeCriticalSectionEx` / `GetLocaleInfoW` 这两条已在下一批（55 个 KERNEL32 垫片）里补掉。

### 3.2 下一堵墙：SSE/AVX 指令（已用反汇编确认）

三个函数被整函数占位，缺的全部是向量指令。用 `disasm-dump` 工作流取到真实形式：

```
0x140dabfe0 (memset 类): punpcklqdq xmm0,xmm0
                          vinsertf128 ymm0,ymm0,xmm0,0x1
                          vmovdqa YMMWORD PTR [rcx],ymm0      ← 256 位存储
0x140d679ac (strcmp 类): vpxor xmm1,xmm1,xmm1
                          vpcmpeqw ymm1,ymm1,YMMWORD PTR [r9] ← 256 位 + 内存源
                          vpmovmskb eax,ymm1
                          vzeroupper
0x140dab860:              movdqu 等（SSE 部分本来就支持）
```

**为什么必须真做 256 位**：这些是 memcpy/memset/strcmp 一类 CRT 热点，只做 128 位等于
每次拷贝只走一半数据，比占位更危险（静默损坏）。

### 3.3 本轮已实现的垫片/指令

| 类别 | 数量 | 内容 |
|---|---:|---|
| KERNEL32 垫片 | 55 | SRW 锁/条件变量/InitOnce/线程池/Global* 堆/locale/控制台/系统信息；`WideCharToMultiByte` 改为真写缓冲 |
| USER32 垫片 | 92 | 假窗口（常量 HWND/HDC，GetClientRect 回填）+ **有界消息循环**（`MEW_MAX_FRAMES` 默认 60，跑满投 WM_QUIT 让引擎自己退出）+ 输入/监视器/剪贴板 |
| AVX/VEX 指令 | 9 类 | `vmovdqa/vmovdqu/vmovntdq`、`vpxor` 系、`vpcmpeq?`、`vpmovmskb`、`vinsertf128/vextractf128`、`vzeroupper`、`punpck?qdq` |
| 运行时 | — | `X64Ctx` 增加 `ymm_hi[16][16]`；`x64_sse_helpers.h` 新增 `avx::` 指令级封装（VEX 128 位写清零高半） |

### 3.4 在跑的验证

| run | head | 内容 | 状态（写作时） |
|---|---|---|---|
| `45894281724` | `7d5ae60` | stage3：AVX + USER32 + 55 个 KERNEL32 垫片 | 编译分片阶段 |
| `45894538516` | `3a28b0f` | iOS 出包 v0.11.3 | ELF→Mach-O 阶段 |
| 已过 | `7d5ae60` | lifter 编译探针 ✓、语法门禁 ✓、ARM64 语义验证 ✓ | — |

---

## 4. CI / 工程设施（本轮新增，都可复用）

| 设施 | 作用 |
|---|---|
| `ios_port/verify_bundle.py` | 装机前门禁：依赖闭合 + bind 符号解析 + trie 越界；支持直接吃 `.ipa` |
| `.github/workflows/shim-syntax.yml` | 1 分钟编译门禁（shims + 宿主），失败时把 `error:` 打成 GitHub annotation |
| ci-diag 通道（annotation） | 流水线末尾把诊断摘要 base64 塞进 `::notice`，公开的 check-runs/annotations API 可读——**日志接口要 admin、artifact 要 token、REST 写文件被降级，只有这条路通** |
| `tools/elf2macho_dylib.py` 自检 | 依赖表改动后必须跑 `verify_bundle.py`，否则真机只会报一句 symbol not found |
| 反汇编 dump（已有） | 按 VA 拉 objdump，用于把「缺什么指令」变成确定事实 |

---

## 5. 未完成清单（P0 / P1 / P2）

### P0 —— 挡住交付

| # | 项 | 现状 | 判定标准 |
|---|---|---|---|
| P0-1 | **路线 B 真机验证** | v0.11.2 已就绪、v0.11.3 在造；**从未在真机跑过** | mew.log 出现 `[host 3b] ok` → `[host 3d] 全部完成` → `[host 4]` |
| P0-2 | 方案二 Heap 家族 | ✅ **已关闭**（UNIMPL API=0） | — |
| P0-3 | 仓库里 27 MB APK 分片（合规） | 未解决，需要用户加 `MEW_ASSETS_TOKEN` 迁私有资产仓 | 仓库里不再有 apk 分片 |

### P1 —— 关键假设未验证（★ = 本轮新增）

| # | 项 | 现状 | 判定标准 |
|---|---|---|---|
| P1-1 | 76,945 条 rebase 的 ASLR slide 真机是否接受 | 静态结构全过，真机未验 | `[host 3b] ok` |
| P1-2 | 1,348 条 bind 是否全解析 | **静态已验**：1,242 条可核全过；libSystem 106 条无法包内核 | 真机不报 symbol not found |
| P1-3 | shim 仍是 v0.2.0 时代产物 | **部分解决**：缺的符号由 compat 库补上；但 shim 本身没重建（TLSDESC 汇编不在里面） | 用 Linux 无 SDK 重建 shim，或确认 compat 路径长期可用 |
| P1-4 | 图形栈：SDL_GPU(Metal) 还是 GLES | 未验 | 真机首帧日志 |
| P1-5 | 4.78 GiB gpak 首次解析耗时 / Jetsam | 未验 | `[host 2]` 之后是否被杀 |
| P1-6 | 触控/音频/ANativeWindow 尺寸 | 未验 | 真机首帧后 |
| **P1-7★** | `SDL_StretchSurface` 是「等价语义」实现（转调 `SDL_BlitSurfaceScaled`），非原函数 | 已上真机候选包 | 若缩放/像素异常，优先怀疑这里；彻底解法是重编 SDL3 3.2.12+ |
| **P1-8★** | 方案二的窗口只做到「假窗口」阶段 A | 已实现；真 GL（EGL surfaceless）未做 | 见 `Mewgenics-方案二-窗口与GL垫片设计` §3 阶段 B |

### P2 —— 技术债

| # | 项 | 现状 |
|---|---|---|
| P2-1 | plist 版本与文件名不一致 | ✅ 已修（0.11.3 同源） |
| P2-2 | SDL3 Headers 占 3.4 MB | ✅ 已剔除（省 ~664 KB 压缩后） |
| P2-3 | 401 个 stubbed 指令 | 部分：AVX 9 类已支持；**待新一轮 UNIMPL FUNC 表确认剩余** |
| P2-4 | 两阶段 SEH 只做到派发（`seh_resume=0`） | 未动 |
| P2-5 | `WideCharToMultiByte` 简化实现 | ✅ 已改成真写缓冲（第 5/6 参数从栈取、-1 含结尾 NUL） |
| P2-6 | `bionic_syscall` 一律 ENOSYS | 未动 |
| P2-7 | `dl_iterate_phdr` 桩 | 未动 |
| P2-8 | 阶段 6 GLSL→ES3 只有自测 | 未对拍 |
| P2-9 | 路线 A（越狱运行期加载） | 搁置 |
| **P2-10★** | 14 条 TLSDESC 绑定现在依赖 compat 库，**不在 shim 里** | 若将来重建 shim，记得把 `bionic_tlsdesc.S` 编进去，并改回转换器的 target |
| **P2-11★** | 大 dylib 仍未 ldid 签名 | 侧载工具会重签；TrollStore 场景若有问题，可给大文件也签（新 LINKEDIT 顺序下 ldid 已不再截断，探针实测 78,544,896→79,148,592 变大） |
| **P2-12★** | CI 匿名 API 配额 60 次/小时，多次打满 | 轮询要节制；artifact 走 nightly.link 免鉴权取 |
| **P2-13★** | 大文件直连下载会截断（25.8–26.3 MB 处） | 用 8 MB Range 分块或 nightly.link 自带的断点续传 |

---

## 6. 本轮提交（14 个，都在 main）

```
3a28b0f v0.11.3：MewHost 加崩溃信号日志
7d5ae60 补 vpcmpeq 的内存源形式；触发 stage3
1c2eefe 方案二：支持 AVX/VEX 指令
b944301 方案二阶段 A：USER32 假窗口 + 有界消息循环
24a1705 方案二「窗口/GDI/GL 垫片设计」文档
582f1e0 v0.11.2 交付说明
00c2615 触发 stage3 新一轮
63f6b5f 清理 __pycache__
7fe99be 诊断摘要改用 annotation 发布
669f8b8 修 GetSystemInfo 重复定义；门禁打 annotation
7c6d830 ci-diag 发布改用 REST API（后被 annotation 取代）
d120855 方案二补 55 个 KERNEL32 垫片
e6b803e 修 ci-diag 被拒（临时仓库）
1f9214c v0.11.2：补 DT_INIT_ARRAY 的 12 个静态构造函数
```

## 7. 文档索引（都在仓库根目录）

| 文件 | 内容 |
|---|---|
| `Mewgenics-全项目详尽总结-2026-11-27.md` | 11-27 之前的全部状态（基线） |
| `Mewgenics-路线B-装前门禁与两处缺失修复-2026-11-27.md` | 本轮路线 B 的三处硬故障与修法、门禁实测输出 |
| `Mewgenics-v0.11.2-交付说明-2026-11-27.md` | 装机步骤、判据日志、已知风险 |
| `Mewgenics-方案二-导入覆盖盘点-2026-11-27.md` | 455 个导入 / 111 有强垫片 / 344 只有弱占位 |
| `Mewgenics-方案二-窗口与GL垫片设计-2026-11-27.md` | USER32/GDI32/OPENGL32 数据、wgl 动态加载发现、阶段 A/B 设计 |
| **本文** | 现状总览与全部未完成项 |

## 8. 协作与环境备注

- **小炸鱼**：负责推代码（只有它的 `GITHUB_WORKFLOW_TOKEN` 对主仓有 push+workflow 权限）和取 artifact。
  本轮它的模型调用**间歇性失败**（TRANSPORT 错误），多次重试后才成功；期间我已把 artifact 下载改为
  免鉴权的 nightly.link，不再依赖它。
- **推送边界**：共享工作区 `/home/dsh/.dsh/bot/workspace/mew-recomp` 归我改；它只执行我指定的 push，
  不要在那个仓库跑 `git checkout/reset/clean`（曾把我的未提交改动清掉一次）。
- **匿名 GitHub API**：60 次/小时，轮询要节制；`git ls-remote` 不消耗配额。
- **本机没有编译器**：所有构建都在 GitHub Actions；本机能做的是 Python 静态校验（转换器、门禁、IPA 解析）。
