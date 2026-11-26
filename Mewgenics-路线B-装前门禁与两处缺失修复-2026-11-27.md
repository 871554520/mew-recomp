# 路线 B：装机前门禁与两处「加载期缺失符号」的定位/修复

> 日期：2026-11-27
> 触发问题：v0.9.0 在真机上预期会卡在 `[host 3b] dlopen 主 dylib`
> 结论：**不是猜的，是两个具体符号缺失，都是强绑定**。已修复并加了永久门禁。

## 1. 怎么发现的（纯静态，不依赖真机）

把 v0.9.0 的 IPA 解包后，逐条解析 `libmew_relinked.dylib` 的 **bind 操作码流**
（`LC_DYLD_INFO_ONLY` 的 `bind_off/bind_size` = 0x48f1ce1 / 38,664 B，共 **1,348 条**），
得到每条绑定的 `(dylib 序号, 符号名, flags)`，再和每个依赖库自己的 **export trie**
逐条对账。

这里的第一个坑：**Mach-O 的 bind 序号不含 `LC_ID_DYLIB`**。dylib 的加载命令顺序是

```
LC_ID_DYLIB      @rpath/libmew_relinked.dylib   ← 自己，不算依赖
LC_LOAD_DYLIB    /usr/lib/libSystem.B.dylib     ← 序号 1
LC_LOAD_DYLIB    @rpath/SDL3.framework/SDL3     ← 序号 2
LC_LOAD_DYLIB    @rpath/libbionic_shim.dylib    ← 序号 3
```

按这个映射对账（旧文档写的「SDL3 1,095 / libSystem 105 / shim 132」口径一致，
但需要按序号 1=libSystem、2=SDL3、3=shim 来读）：

| 序号 | 依赖 | 唯一符号 | 结果 |
|---:|---|---:|---|
| 1 | libSystem.B | 105 | 结构无法核（iOS 版本相关），名字全部是标准 libc/libm |
| 2 | SDL3.framework | 1,095 | **缺 1 个**：`_SDL_StretchSurface` |
| 3 | libbionic_shim | 133 | **缺 1 个**：`_bionic_tlsdesc_resolver`（×14 条绑定） |

两条 `flags=0x0`，即 **强绑定**：dyld 在加载期必须解析到，否则
`dlopen` 返回 0 并报 `symbol not found: _XXX`。

## 2. 两处缺失的根因（不是「大概」）

### 2.1 `_bionic_tlsdesc_resolver`：Release 里的 shim 早于 TLSDESC 汇编

- 仓库源码 `ios_port/shim/bionic_tlsdesc.S` 里**有**这个符号（`.globl _bionic_tlsdesc_resolver`）。
- 但 Release 资产 `mac-products-v1`（上传于 2026-11-26T17:31:58Z）里的
  `libbionic_shim.dylib`，**symtab 318 条里没有它**，export trie 153 条里也没有；
  只有 `_bionic_tlsdesc_get_offset`。
- 也就是说：转换器把 14 条 `R_AARCH64_TLSDESC` 重定位写成绑到 shim 的
  `_bionic_tlsdesc_resolver`，而包里那个 shim 根本不导出它。

### 2.2 `_SDL_StretchSurface`：打的 SDL3 版本比游戏自带的老

- 游戏 APK 里自带 `lib/arm64-v8a/libSDL3.so`，版本串是 **`SDL3-3.2.12`**（开发版），
  **导出** `SDL_StretchSurface`。
- 我们的 iOS `SDL3.framework` 是 **`release-3.2.0`**：二进制里连
  `SDL_StretchSurface` 这个名字都搜不到（导出、头文件声明都没有）。
- 官方文档：`SDL_StretchSurface` 自 **SDL 3.4.0** 起公开；实现就在
  `src/video/SDL_stretch.c`，语义是「校验矩形 + 加锁 + 按 scaleMode 缩放 blit」。

## 3. 修法（全程 Linux 可编，不动 macOS）

新增 **`libmewcompat.dylib`**（`ios_port/compat/mewcompat.c` + 复用
`ios_port/shim/bionic_tlsdesc.S` 的寄存器保全壳子），由
`ios_port/build_compat_linux.sh` 用 `clang -target arm64-apple-ios15.0` + `ld64.lld`
在 Ubuntu 上编出来（不需要 iPhoneOS.sdk）：

| 符号 | 实现 |
|---|---|
| `_bionic_tlsdesc_resolver` | asm 壳子保全 x1–x18 / q0–q31，跳到 `bionic_tlsdesc_get_offset(slot, tpidr)`，返回 `线程块 + slot - tpidr_el0` |
| `_SDL_StretchSurface` | 如实转调 3.2.0 已有的 `SDL_BlitSurfaceScaled(src, srcrect, dst, dstrect, scaleMode)`（同 5 参数、同语义，不假装成功） |

转换器 `tools/elf2macho_dylib.py` 相应改两处：

1. 依赖表加第 4 项 `@rpath/libmewcompat.dylib`（bind 序号 4）；
2. 14 条 TLSDESC 绑定与 `COMPAT_SYMBOLS = {SDL_StretchSurface}` 改指序号 4。

**改依赖表就等于改所有 bind 序号**，所以必须配门禁（下节）。

## 4. 永久门禁：`ios_port/verify_bundle.py`

只检查 Mach-O 结构（`llvm-objdump --macho` 那套）**不够**——它验证不了
「每条 bind 的符号是否真的存在于所属依赖库」。新门禁做三件事：

1. 每个 Mach-O 的 `@rpath/...` 依赖在包内必须找得到文件；
2. 每条**强绑定**的符号必须在该依赖库的 export trie 里；弱绑定缺失只告警；
3. export trie 必须落在 `__LINKEDIT` 内（dyld 会拒绝越界）。

`assemble_ipa_linux.sh` 在打包前调用它，失败直接 `exit 6` 拒绝出包。

**在 v0.9.0 上的实测输出**（这就是它的价值，一眼定性）：

```
bind 总数 1349（可核 1242，libSystem 106）
FAIL ... _bionic_tlsdesc_resolver 未被 ... libbionic_shim.dylib 导出  ×14
FAIL ... _SDL_StretchSurface 未被 ... SDL3.framework/SDL3 导出
共 15 处问题（去重后 2 类）
```

## 5. 顺带修掉的两件事

### 5.1 ldid 现在可以签大文件了（探针实测）

旧结论「ldid 签 78 MB dylib 会截断」只在**旧 `__LINKEDIT` 顺序**下成立。新顺序
（`rebase→bind→export→symtab→strtab`，STRTAB 最末）下探针结果是
**78,544,896 → 79,148,592 B（变大 603,696 B）**，即 ldid 正常追加签名槽，不再截断。
本轮仍保持「大文件跳过签名」（侧载工具会重签），但这条已经不再是风险项。

### 5.2 v0.10.0 出包已经通了（但只能当管道验证）

- IPA 26,604,433 B（v0.9.0 是 27,268,635 B，剔掉 SDL3 头文件省了 664 KB）；
- `Info.plist` 版本 **0.10.0 / build 100**（与文件名同源，P2-1 关闭）；
- ⚠️ 这只包**仍然带那两个缺失符号**（dylib 是同一份），**不要装**。
  能装的是修完后的 **v0.11.0**。

## 6. 方案二那边同一轮的收获

- stage3 run `45886525448` 前 19 步全绿（含 66 个分片编译），第 20 步
  「Stage 5 - build launcher」失败：我在 shim 里用了未定义的 `arg7(c)`
  （`win32_common.h` 原来只有 `arg0..arg5`）。已补 `arg6=[rsp+0x38]`、`arg7=[rsp+0x40]`。
- 诊断摘要步骤已扩展到包含「宿主链接日志末尾 40 行」，下次编译错误会直接出现在
  公开的 `ci-diag-stage3` 分支上，不必再找人取日志。

## 7. 还没验证的部分（别当成已完成）

- v0.11.0 未在任何设备上跑过；libSystem 的 106 条绑定无法在包内核对。
- `SDL_StretchSurface` 的兼容实现是「等价语义」而非原函数；若真机上出现缩放/像素
  异常，优先怀疑这里（可换成重编 SDL3 3.2.12+）。
- 方案二的堆路径修复（`HeapReAlloc` 等）尚未跑出新的运行期数据。
