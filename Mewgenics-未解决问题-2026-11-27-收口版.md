# Mewgenics 阶段 5 · 未解决问题清单（2026-11-27 21:4x 合并终版）

> 主线：**方案二（Windows exe 重编译，stage3 CI 迭代）**；iOS 路线 B 暂缓。
> 阶段 5 判据：**仍未达成** —— `gpak` = 0、`CreateFileW` = 0。
> 每项按 **现象 → 证据 → 根因 → 修法 → 验证状态** 组织；第 4 节是**已排除、不要再查**的方向。
> 本版合并了两份草稿（线上实测口径来自 `小炸鱼`，静态/代码侧的判据来自本 bot），两份内容已对齐。

---

## 0. 状态快照

**已经跨过的里程碑**（不再是未解决问题）：

- 初始化链**第一次完整走完**：XC 表 2351 项，最后一项 2350；`index=2339` 只跳过 1 次（旧版 129 次空转已消失）。
- `main` 真正被调用：`[main] 链尾补调 0x1409b5230 argc=1`，调用环 **144,245 帧**，早越过 `[12027]`。
- 三个 `0x140e39c0x` 调整器 thunk 的 FATAL 已消失；`0x140be07e4` vtable 标签已登记且能派发。
- 规模：seeds 31,079 / total **76,812**（ok 76,355 · stubbed 456 · failed 1）。

**远端与在飞**（21:4x 核对）：

- 远端 `main` = `1dec451`（`31fab13..1dec451` 只动 `tools/`，无 trigger，没起新 run）。
- **正在跑**：`46005752715`（head `31fab13`，pcmpestrm 前缀匹配版）——1–25 步全绿（`Compile all shards` / Gate 3 / Gate 1 / Stage 4 / Stage 5 run 全过），当前 26/29 `Stage 5b - reflow`，artifact 未上传。
- 同 head 门禁：lifter-build `46005752640` ✅、shim-syntax `46005752513` ✅、arm64-verify `46005752893` ✅。
- **被 cancel 的轮（不是失败）**：`46005327501`（`8ce7495`）被 `31fab13` 的 trigger 顶掉；`46002704286`（`dad286d`）被 `df7f774` 顶掉。真失败的只有 `46004499142`（`0f80e1e`）：16 步编译错误 = `c->af`。

**基线**（下文的「上轮」都指它）：`45999239672`（head `d7dfde6`）——seeds 31,079 / total 76,812（ok 76,355 · stubbed 456 · failed 1）；`[extend]` 16 行 / 15 地址；`index=2339` 只跳 1 次、`main` 被补调 `argc=1`；调用环 144,245 帧；结尾 `ExitProcess(3)` + `0xE06D7363` ×5；UNIMPL API 2 条、UNIMPL FUNC 1 条（`0x140d1a1b0`）；FATAL `0x140bf4ff0` + `0x50934f50`；ABI 41 / rsp-repair 40 / abi-repair 40。

---

## 1. 未解决问题（P0）

### P0-1　`0x140d1a1b0`（ucrt 的 SSE4.2 字符串例程）整函数被打桩

- **现象**：`[UNIMPL FUNC] va=0x140d1a1b0 missing=pcmpestrm,ptest` ×4；紧接着调用方抛 `std::out_of_range`（`_Xran`）。
- **证据**：`66 0f 3a 60 36 0c` = `pcmpestrm xmm6,[rsi],0x0c`（无符号字节 / equal-ordered / 正极性 / 位掩码输出）；调用点 `0x140d1a430`，其后的候选枚举在 `0x140d1a451..0x140d1a45d`。
- **根因**：lifter 没有 SSE4.2，整函数被判 `UNIMPL FUNC` 并占位成「返回 0」；调用方按返回的 0 去取子串就越界。
- **修法**：
  - `0819698` 按 SDM 重写 `ptest` / `pcmpestrm` / `pcmpestri`：`a`=needle（长度 EAX）、`b`=haystack（EDX），位图按 haystack 下标；`CF=IntRes2≠0`、`ZF=|EDX|<上限`、`SF=|EAX|<上限`、`OF=IntRes2[0]`；`ptest` 的 CF 方向为 `(SRC2 & ~SRC1)==0`。
  - 同一提交修掉上一版草稿「从没编过」的两个硬错误：`c->af`（`X64Ctx` 只有 `zf/sf/cf/of/pf/df`）、helper 放错命名空间（定义在 `sse::avx`，发射的是 `sse::`）。
  - `ce3192e` 把 equal-ordered 从「必须整段装得下（`i+la<=lb`）」改成「能比多少比多少」：调用方拿到位图后 `bsr`→`btr` 逐个枚举候选，再对每个候选做完整 16 字节比对，只有在位图**包含部分前缀匹配**时这套重试才成立；严格 SDM 语义下 `la=lb=16` 只剩 bit0，重试循环退化。
- **验证状态**：编译 ✅（`46005752715` 1–25 步全绿，说明发射的调用被生成器吃到了）／**语义 ⏳**（前缀匹配版 `ce3192e` 就在这一轮里）。判据：`0x140d1a1b0` 从 `UNIMPL FUNC` 表消失、`out_of_range`/`_Xran` 归零。

### P0-2　两条 API 仍无实现：`KERNEL32!EnumSystemLocalesW`、`SHELL32!SHGetFolderPathW`

- **现象**：`UNIMPL API` 表 2 条（其余都清了）。
- **根因**：shim 未实现。`EnumSystemLocalesW` 需要**回调 guest**，而宿主侧目前没有「回叫 guest」的机制（`runtime/` 与 `shims/` 里搜不到 call_guest/invoke 一类入口）；`SHGetFolderPathW` 需要给出沙盒内真实存在的目录。
- **修法（候选，未做）**：
  - `EnumSystemLocalesW`：先实现成「成功但不回调」（或回调一次 `en-US`），观察 CRT 是否还需要完整枚举；若需要，得先补一个 guest 回调入口。
  - `SHGetFolderPathW`：按 `host_path_from_guest` 的映射规则返回 `MEW_DATA_DIR` 下的 Documents/AppData，并保证目录存在（`CreateFileW` 的 `fopen` 不会建目录）。
- **验证状态**：❌ 未开始。

### P0-3　`0x140bf4ff0`：ff25 型 import thunk 漏挖（新 FATAL）

- **现象**：`[FATAL] Unmapped indirect target: 0x140bf4ff0 (nearest_lo=0x140bf4fe0 delta=16) in_fn=0x140be07e4`。
- **证据**：16 字节 `48 85 c9 74 07 48 ff 25 f4 f6 7b 00 c3` = `test rcx,rcx` / `je +7` / `jmp qword [0x1413b46f0]` / `ret`；**不在任何 `.pdata` 区间**（前一条 `0x140bf4fb8..0x140bf4fbf`，下一条从 `0x140bf5000` 开始）；`0x140bf4fc0/4fd0/4fe0/4ff0` 是四个 16 字节一格、彼此无填充的兄弟桩。
- **根因**：miner 的 ff25 规则只认「`48 85 /r` 守卫」这一种形态，纯 `48 ff 25` 尾跳（如 4fc0）不认；且兄弟桩会被「长度按下一个 seed 算」的区间吞掉，没有例外。
- **修法**：`1dec451` 把形状判定抽成 `tools/thunk_shapes.py` 纯函数，认 A 纯尾跳 / B `test+je` 守卫 / C `jne` 反向守卫三种形态，槽按 16 对齐整段扫，槽尾必须落在 `c3/cc/00`；配 `tools/test_thunk_shapes.py` 8 例（含实拍字节与三个反例），本地 8/8 通过。
- **验证状态**：⏳ 要等下一轮 stage3 的 `seeds.log`：`import-thunk` 候选数应比现在多（预期 ≥ +2），`0x140bf4ff0`/`0x140bf4fc0` 应出现在 `extra_seeds.txt` 里。
- **补充事实**：上一轮 `0x140bf4ff0` 只靠运行期 `discovered_entries.txt` + stage3b reflow 才进了第二遍构建（`stage3/manifest.tsv` 没有、`stage3b/manifest.tsv` 有）。`tools/` 改动本身不触发 run，所以要刻意安排一轮带 trigger 的 stage3 才验得到。

### P0-4　「把堆指针当函数调」：`0x50934f50`（in_fn=`0x140be0980` / `0x140bb067b`）

- **现象**：FATAL 目标是一个刚由 `HeapAlloc` 返回的堆地址。
- **根因（假设，未证）**：P0-15 的次生现象——`0x140be0980` 的结构是「先调一个填 out 参数的例程，再 `call qword [rsp+0x38]`」；若前一步（`0x140be07e4` 那条 vtable 调用）的间接目标 `0x140bf4ff0` 没派发，out 槽没写，`call [rsp+0x38]` 就用残留值。
- **修法**：同 P0-3。若 P0-3 修完仍复现，再按 `in_fn` 逐个查（`0x140be0980` / `0x140bb067b`）。
- **验证状态**：⏳ 跟随 P0-3。

### P0-5　main 路径里 5 次 `0xE06D7363`（C++ 异常）+ 结尾 `ExitProcess(3)`

- **现象**：最近一轮结尾是 `ExitProcess(3)`（CRT 自退，不是超时也不是段错误），期间 `0xE06D7363` 抛了 5 次。
- **根因**：未定位。缺少「每次 C++ 异常的 `throw_pc` + 抛点函数 + 对应 handler 结果」这一条链。
- **修法（下一步）**：确认 `RaiseException` 日志是否覆盖 C++ 异常路径；补打 `[seh] dispatch code=… throw_pc=… in_fn=…`，并与 `0x140d40978`（`_CxxThrowException`）的调用环对齐。
- **验证状态**：❌ 未定位。

### P0-6　阶段 5 判据本身：`gpak` / `CreateFileW` 仍为 0

- **说明**：`main` 已进去，但没走到资源加载。静态已确认：`0x140e3fee0` 之后那 60 个初始化器**一个导入函数都不引用**，所以 `gpak`/`CreateFileW` 只能来自 `MEW_CALL_MAIN` 补调的 `main` 链；先解 P0-1 / P0-3 / P0-5。
- **验证状态**：❌ 未达成。

---

## 2. 已知残留（P1，不阻塞主线）

| 编号 | 内容 | 现状 |
|---|---|---|
| P1-1 | 3,574 个「段连续家族」里 758 个 span 末尾不收在 `ret/jmp` 上 | 已知残留，本批补长不覆盖（补的 12 个都收在终止符上） |
| P1-2 | 打包叶子函数静态挖不出来；reflow 只能追「上一轮运行期发现的入口」 | 结构性限制，至少两轮才能收敛 |
| P1-3 | `[rsp-repair]` 只在 SAFE 趟出现（40 vs 0），ABI 41 / abi-repair 40 与上轮持平 | 差异未解释；暂不影响主线 |
| P1-4 | 二次构建让构建时间翻倍 | 优化项 |
| P1-5 | 「内层家族铺满」候选：覆盖 3,574→4,591，但收在终止符上的只多 51 | 已决定不做，`chain_family_spans` 维持原样 |

---

## 3. 工具与流程风险（长期约束，不是一次性问题）

1. **单点令牌 + 只能用 token-in-URL**：只有 `小炸鱼` 持可推主仓的 `GITHUB_WORKFLOW_TOKEN`；`PAT_B` 实测 401、`PAT_B2`/`PAT_B3` 不可用。而且推送只认 `https://x-access-token:<TOKEN>@github.com/...` 形式——`GIT_ASKPASS` 和 `~/.git-credentials` + `credential.helper=store` 在这台机器上都报 `Authentication failed`。
2. **concurrency 会 cancel 在跑的轮**：任何带 `.stage3-trigger` 的提交都会顶掉正在跑的 stage3（今天两次：`46002704286`、`46005327501`）。→ trigger 提交必须等上一轮结束；想验新代码又不想顶轮，就先推不带 trigger 的提交，等窗口再推 trigger。
3. **本机 `git status` 不可靠**：工作树与 HEAD 不同也会报 clean（`0f80e1f` 那版「从没编过」的草稿就是这样躺着的）。→ 判定改动用 `git ls-files -s` / `git hash-object` / `git show HEAD:<path>` 比 blob。
4. **`ci-diag-stage3` 分支陈旧、免 token 取日志的通路实际失效**：最新 publish 停在 `7ce2c8e`（run `45888616405`，11-26 20:22），今天所有轮都没更新，尽管步骤 28 报 success。→ 判读只能从 artifact 拉。
5. **artifact 直连会超时**：`curl` 两分钟无响应；要用 Python `urllib` 跟 302 Location + Range 1MB 分块重试。→ 这就是「明明有 artifact 却拉不下来」的原因。
6. **本地没有 C++ 编译器**：C++ 改动只能靠 `lifter-build` + stage3 的 `Compile all shards` 两道门。→ 语义改动先用 Python 复刻逻辑自测（`pcmp_core`、thunk 形状都这么做）。

---

## 4. 已排除（**不是根因，不要再查**）

- **SKIP_INIT 129 次空转**：不是机制缺陷，是 skip 分支 resume 回循环头时没把 `rbx` 推进（`f7f4c0e` 修，`d7dfde6` 轮实测只跳 1 次）。
- **三个 `0x140e39c0x` thunk**：`75e7557` 的 thunk 形状挖掘后 FATAL 消失。
- **`0x140be07e4` vtable 标签**：`cae149d` 登记后不再是 FATAL 目标（问题前移到它的间接目标 `0x140bf4ff0`）。
- **初始化器能带出 `gpak`/`CreateFileW`**：静态确认不可能（那 60 个初始化器零导入引用）。
- **cookie 未初始化 / 4 字节错位**：已由实测数据否定（容器布局 = `_Max_load_factor` / mask=7 / buckets=8 / `_Mysize`）。
- **`0x1409b5380`/`0x1409b9970`/`0x1409b5230` 是 gpak 入口**：实为 setlocale 试错路径。
- **「内层家族铺满」值得做**：只多救 51 个家族，不值得复杂化。

---

## 5. 下一轮判据（可直接照抄执行）

```bash
# 1) SSE4.2：函数是否还占位、越界异常是否消失
grep -n 'UNIMPL FUNC' runner*.err | grep 140d1a1b0    # 期望空
grep -c 'out_of_range\|_Xran' runner*.err             # 期望 0

# 2) thunk 挖掘（在 stage3 的 Mine hidden entries 步骤产物里看）
grep -n 'import-thunk' generated/seeds.log            # 候选数应上升
grep -n '140bf4ff0' generated/extra_seeds.txt         # 期望出现
grep -c 'Unmapped indirect target' runner*.err        # 期望 0

# 3) 初始化链 / main
grep -n '跳过初始化器' runner*.err                    # index 最大 2339，之后不应再有
grep -c 'runner: main returned' runner*.err           # > 0
grep -c 'main 内部又走到 resume' runner*.err          # 必须 0

# 4) C++ 异常 / 收尾
grep -c 'E06D7363' runner*.err                        # 5 → 期望下降
grep -n 'ExitProcess' runner*.err

# 5) 阶段 5 判据
grep -c 'gpak' runner.err runner_b.err
grep -c 'CreateFileW' runner.err
```

---

## 6. 关键定位速查

| VA / 路径 | 说明 |
|---|---|
| `0x140d1a1b0` | ucrt 的 SSE4.2 字符串例程（P0-1） |
| `0x140d1a430` / `0x140d1a451..45d` | `pcmpestrm` 站点 / 候选枚举与逐位验证 |
| `0x140bf4fc0..4ff0` | 四个 ff25 型 import thunk（P0-3） |
| `0x140be07a0..0x140be07fe` | 含 `0x140be07e4` 标签的函数（在 `.pdata` 内） |
| `0x140be0980` | `call qword [rsp+0x38]` 的所在函数（P0-4） |
| `0x140e3fee0` | XC 初始化表首（2351 项，表尾 2350） |
| `0x140d6aedd` / `0x140d6aec8` | `_initterm` 循环头（skip 分支 resume 目标） |
| `0x1409b5230` | CRT `main`（`argc=1`，`argv[0]="Mewgenics.exe"`） |
| `tools/thunk_shapes.py` | ff25 形状判定（可单测） |
| `tools/test_thunk_shapes.py` | 8 例本地单测 |
| `tools/check_run.py` | 一轮 artifact 的判据打印（已含 extend / skip index / main / target=0 / gpak） |

---

## 7. 待用户处理

- **`MEW_ASSETS_TOKEN`**：解决仓库里 27 MB APK 分片的合规问题，仍是 P0 挂账。
- **阶段 6**（GLSL → ES 3.00 全量化）未开始；**阶段 7** 真机：v0.11.8 的存档目录修复待复验。
