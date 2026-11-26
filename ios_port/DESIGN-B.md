# iOS 路线 B：构建期把 libmain.so 重链接成签名 IPA（设计 + 实测）

> 目标：**原版（未越狱）设备也能装**。不需要 JIT、不需要可写可执行内存：
> 代码页留在 `__TEXT`（构建期签名），可变数据放 `__DATA`，所有运行时修补都只写数据页。

## 一、为什么 B 可行：把问题量化了

对 `libmain.so` 的 PT_LOAD 与 `.text`（66,034,608 字节）做了全量扫描：

```
PT_LOAD#0  va=0x00000000  size=0x44363d0  R+X   （.rodata + .text 都在这一段）
PT_LOAD#1  va=0x443a3d0  size=0x10ac30   RW    （.data.rel.ro / .got / .data）
PT_LOAD#2  va=0x4548df8  size=0x3449b8   RW    （.bss）
```

- `ADRP` 总数 **109,949**，其中跨段 **69,987**：
  - 65,105 条指向段 1（可变数据）
  - 4,862 条指向段 2（bss）
  - 20 条指向段外（待查）
- 关键点：**跨段引用全部是"指向数据段的绝对页号"**，也就是说
  **只要数据段整体平移一个固定页数 D，所有 69,987 条 ADRP 的立即数都要加同一个 D**。
  这是一次常数级 in-place 补丁（每条改 4 字节，21 位立即数范围 ±4 GB，绰绰有余），
  **不需要反汇编重写、不需要 GOT 重建、不需要改指令长度**。
- 段内引用（code ↔ rodata）是 PC 相对的，只要整段一起搬就不受影响。
- 数据→数据的指针全部在 `.rela.dyn` 里（`R_AARCH64_RELATIVE` 等），
  这些是**写数据页**，运行时做即可，不涉及代码页。

结论：B 路线 = 「把 ELF 镜像按原相对布局塞进 `__TEXT` 一段 + `__DATA` 一段，
按实测 D 批量补 ADRP 立即数 + 运行时应用 RELA」，全程不碰代码页的可执行性。

## 二、构建流水线（两趟，自动收敛）

```
libmain.so ──elf2macho.py──► mew_payload.o ──ld（Xcode）──► App / libmewpayload.dylib
                │                                            │
                └─ mew_layout.json（段大小、RELA 表、符号表、D 补丁点）┘
                                                        │
                                            otool 测量实际段地址
                                                        │
                              D = 实际数据页 - ELF 数据页 ──► 第二趟 patch → 重建
```

1. **第一趟**：`elf2macho.py` 产出
   - `__TEXT,__mewblob`：段 0 的全部字节（rodata+text，按原相对偏移，页对齐补齐）
   - `__DATA,__mewdata`：段 1+2 连续字节（含 bss 的零填充）
   - `mew_layout.json`：RELA 列表、需解析的外部符号名、ADRP 补丁点（偏移列表）、数据段基址
2. 链接后用 `otool -l` 读出两个 section 的实际地址，算出 D。
3. **第二趟**：同一脚本带上 `--delta D` 重跑，只改 ADRP 立即数（尺寸不变，所以布局不变，收敛）。
4. 校验 `D2 == D`，产物即为可签名 IPA。

## 三、运行时引导（几十行）

```c
// 1) 数据段已经是 RW（在 __DATA 里），直接改
// 2) 应用 .rela.dyn：RELATIVE -> blob_base + addend
//                    GLOB_DAT/JUMP_SLOT -> resolve(name)  // SDL3 / libc / bionic shim
// 3) 跑 init_array
// 4) 调 SDL_main(0, NULL)
```

`resolve(name)` 三级：我方 shim 表 → 自动生成的 SDL3 绑定表（1,095 条，从 SDL3-iOS 链接）→ `dlsym(RTLD_DEFAULT)`。

## 四、已经踩过/要盯的点

| 点 | 状态 / 处理 |
|---|---|
| `__eh_frame` 必须自成一节，否则 Darwin 的 unwinder 找不到 FDE | 段 0 里 `.eh_frame` 在 0x4a03e0；把 blob 在该处切成多节，并在 CI 里用 `otool -l` 校验实际偏移；必要时两趟调整 |
| ld64 对 `__TEXT` 内节的排序 | 未知，必须实测校验（若乱序，就把 blob 拆成 ld64 已知顺序的节名） |
| iOS arm64 页大小 16 KB | 所有对齐/补丁都按 0x4000 计算 |
| arm64e 指针签名 | 用户 App 是 arm64，数据段里的裸指针合法，无需 PAC |
| bionic 的 `struct stat`/`dirent` | 8 个符号必须手写翻译，否则 gpak 读文件大小会错 |
| `__sF` / `stdout` / `stderr` | 数据符号，指向 Darwin 的真 `FILE*` |
| 69,987 条 ADRP 补丁 | 常数 D，脚本一秒钟跑完；CI 里做"补完再测 D 是否为 0"的自检 |

## 五、和路线 A 的关系

路线 A（运行期加载，已写好 `ios_port/elf_loader.c`）与 B **共用**：
- 同一份 RELA 解析/应用代码（A 在加载时做，B 在启动时做）
- 同一套 bionic shim（40 来个）
- 同一份 SDL3-iOS 绑定表
- 同一套图形桥（SDL3 GPU，iOS 走 Metal）

所以 A 拿来当**调试夹具**（改 shim 不用重打包、能打断点），B 拿来做**最终交付**（签名 IPA，原版设备）。

## 六、下一步（按顺序）

1. ✅ P0：macOS arm64 上把 `libmain.so` 加载进来，出重定位/符号统计（CI run 已触发）
2. **P0b**：`elf2macho.py` 第一版 + 在 macOS CI 上链一个测试 dylib，验证「两节布局 + ADRP 常数补丁 + 运行时 RELA」三件事
3. **P1**：bionic shim（40 个）+ SDL3-iOS + 调 `SDL_main`，看它自己的日志打出来
4. **P2**：图形（SDL3 GPU Metal / 必要时 SPIR-V→MSL 桥）出第一帧
5. **P3**：iOS 工程 + 数据目录（`Documents/{game,user}`）+ 触屏映射 + 无签名 IPA
