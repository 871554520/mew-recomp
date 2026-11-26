# Mewgenics v0.11.2 交付说明（真机测试版）

> 日期：2026-11-27
> 基线：v0.9.0（2026-11-26）→ **v0.11.2**（本次）
> 一句话：v0.9.0 及之前的包**在真机上必然加载失败**，v0.11.2 才是第一只「具备加载条件」的包。

## 1. 相对 v0.9.0 修了什么（三处，都是硬故障）

| # | 故障 | 证据 | 修法 |
|---|---|---|---|
| 1 | `_bionic_tlsdesc_resolver` 缺失（14 条强绑定） | Release 里 `libbionic_shim.dylib` 的 symtab 318 条 / export trie 153 条里都没有它 | 新建 `libmewcompat.dylib` 补上；转换器把这 14 条 bind 改指它 |
| 2 | `_SDL_StretchSurface` 缺失（1 条强绑定） | 游戏自带安卓 SDL3 是 **3.2.12**（有）；我们打的是 **3.2.0**（没有，3.4 才公开） | 兼容库实现 = `SDL_BlitSurfaceScaled`（3.2.0 已有的等价入口，同样 5 参数） |
| 3 | `DT_INIT_ARRAY` 的 **12 个静态构造函数**从未执行 | `libmain.so`：`DT_INIT_ARRAY=0x453bea8`、`DT_INIT_ARRAYSZ=96`，12 条 `R_AARCH64_RELATIVE` 填充；Mach-O 没有 `__mod_init_func` 节，dyld 不会调用 | 转换器导出 `mew_init_array` / `mew_init_array_end`，MewHost 在 `[host 3d]` 按序调用 |

配套新增**装机前门禁** `ios_port/verify_bundle.py`：检查依赖闭合、每条强绑定符号是否在所属依赖的
导出表里、export trie 是否越界。它在 v0.9.0 上精确报出上面 2 类共 15 处问题；不通过则拒绝出包。

## 2. 其他变化

- IPA 版本与文件名同源（`IPA_VERSION`，本版 0.11.2 / build 1002），不再出现「文件名 0.9.0、plist 0.1.0」。
- 剔除 `SDL3.framework/Headers`（运行时不需要）：v0.10.0 实测 27,268,635 → 26,604,433 B。
- MewHost 显式 dlopen compat 库（`[host] dlopen compat -> ...`），不依赖 @rpath 回溯。
- ldid 探针改观：新 `__LINKEDIT` 顺序下签名大 dylib 不再截断（78,544,896 → 79,148,592 B，变大），
  但本版仍跳过大文件签名（侧载工具会重签）。

## 3. 装上后看什么（判据）

日志位置：「文件 → 我的 iPhone → MewRelink → mew.log」。期望顺序：

```
[host 0]   main() entered, logs_setup=1
[host 0b]  SDL3=0x... SDL_RunApp=0x...
[host 1]   enter app main: docs=... game=...
[host 2]   gpak exists=yes size=5134616316 dir=Documents/game
[host]     dlopen SDL3  -> 0x... ok
[host]     dlopen shim  -> 0x... ok
[host]     dlopen compat-> 0x... ok        ← 本版新增
[host 3b]  dlopen result h=0x... ok        ← v0.9.0 卡在这里
[host 3c]  mew_base=0x... set_base=0x...
[host 3d]  init_array 12 项，开始按序调用（静态构造）   ← 本版新增
[host 3d]  init_array 全部完成               ← 本版新增
[host 4]   calling target _SDL_main at 0x...
[host 5]   target _SDL_main returned rc=...
```

- **`[host 3b] ... ok`** = 三处符号问题都过了；
- **`[host 3d] ... 全部完成`** = 12 个静态构造函数真跑过了；
- 之后才是引擎自己的日志（`[game]` / `__android_log_print`）。

失败时看**紧邻的上一行**：`dlopen ... 失败：<dlerror 原文>`。`dlerror` 只取一次，不会再打成 `(null)`。

## 4. 已知风险（如实列出）

1. **libSystem 的 103 条绑定无法在包内核对**（iOS 版本相关），只能真机验证。
2. `SDL_StretchSurface` 是「等价语义」实现（转调 `SDL_BlitSurfaceScaled`），不是原函数；
   若真机出现缩放/像素异常，优先怀疑这里（彻底解法是用 SDL3 3.2.12+ 重编 framework）。
3. 大 dylib 仍未签名（侧载工具重签）；若 TrollStore 场景报签名错误，改用「给大 dylib 也签 ldid」。
4. 数据包 `resources.gpak`（4.78 GiB）依旧不进包，必须放在 `Documents/game/`。
