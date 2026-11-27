# Mewgenics 阶段 5 · 未解决问题清单（小炸鱼版 · 2026-11-27 21:35）

> 口径：只写**远端 CI 实测**能证实的项；每条带 run id / artifact 证据。
> 主线：方案二（Windows exe 重编译 + stage3 CI 迭代）。阶段 5 判据：**仍未达成**（`gpak` = 0、`CreateFileW` = 0）。
> 组织：现象 → 证据 → 根因 → 修法 → 验证状态。

---

## 0. 当前事实（先看这个，避免拿旧结论干活）

**远端 main = `1dec451`**（我推的 `31fab13..1dec451`，只动 `tools/`，无 `.stage3-trigger`，没起新 run）。

**正在跑**：`46005752715`（head `31fab13`，pcmpestrm「前缀能比多少比多少」版）
- 21:31 时 1–25 步全绿：`Compile all shards`、Gate 3、Gate 1、Stage 4、Stage 5 run 全过；
- 现在在 26/29 `Stage 5b - reflow runtime-missed entries`（第二遍构建），artifact 尚未上传。
- 同 head 的 lifter-build `46005752640` ✅、shim-syntax `46005752513` ✅、arm64-verify `46005752893` ✅。

**被顶掉的轮（不是失败，是 cancel）**：
- `46005327501`（`8ce7495`）13:14 被 `31fab13` 的 trigger 提交按 concurrency `cancel-in-progress` 干掉；
- `46002704286`（`dad286d`）13:08 被 `df7f774` 的 trigger 干掉。
- `46004499142`（`0f80e1e`）是**真失败**：16 步 `Compile all shards` 编译错误，后续全 skipped —— 就是 `c->af` 那个坑。

**上一轮完整数据基线**：`45999239672`（head `d7dfde6`），后面所有"上轮"都指它：

```
seeds 31,079 / total 76,812（ok 76,355 · stubbed 456 · failed 1）
[extend] 16 行 / 15 个地址（同一批白名单，0x140386180 208→779）
init：index=2339 只跳 1 次（游标 0x140e447f8→0x140e44800），main 被补调 argc=1
调用环 144,245 帧（旧壁垒 [12027] 早已越过）
结尾 ExitProcess(3)；0xE06D7363 抛 5 次
UNIMPL API 2 条、UNIMPL FUNC 1 条（0x140d1a1b0）
FATAL：0x140bf4ff0（in_fn=0x140be07e4，hits 1/2）、0x50934f50（堆指针当函数调，hits 1/2）
ABI VIOLATION 41 / rsp-repair 40 / abi-repair 40（与再上一轮持平）
```

---

## 1. P0：阻塞阶段 5 判据

### P0-A　SSE4.2 例程 `0x140d1a1b0`：能编不能证明语义

- **现象**：旧轮 `[UNIMPL FUNC] va=0x140d1a1b0 missing=pcmpestrm,ptest`；调用方随后抛 `std::out_of_range`（`_Xran`）。
- **证据**：`0f80e1e` 那轮 stage3 直接死在编译（`c->af` 不存在、helper 命名空间放错）。
- **现状**：`0819698` 按 SDM 重写三指令后，`46005752715` 的 `Compile all shards` 已过、Gate 全过 —— **说明编译与链接层没问题**；但 `UNIMPL FUNC` 表要等这一轮 artifact。
- **判据（下一轮）**：`UNIMPL FUNC` 里不再出现 `0x140d1a1b0`；`out_of_range`/`_Xran` 计数归零；`pcmpestrm` 位图语义（前缀匹配版 `ce3192e`）要等运行期数据。
- **验证状态**：⏳ 编译 ✅ / 语义 ⏳。

### P0-B　main 路径 5 次 `0xE06D7363` + 结尾 `ExitProcess(3)`

- **现象**：`d7dfde6` 轮结尾 CRT 走到 `ExitProcess(3)`（自退，不是超时/段错误），之前 `RaiseException(0xe06d7363)` 5 次。
- **证据**：`runner.out` = `entry returned rax=0 resumes=1, rc=3`；`runner.err` 末尾 `GetProcAddress("CorExitProcess") -> 0x0 (unmapped)` → `ExitProcess(3)`。
- **根因**：未定位。还没把「每次 C++ 异常的 `throw_pc` → 抛点函数 → handler 结果」串起来。
- **修法**：补打 `[seh] dispatch code/throw_pc/in_fn/handler`，与 `0x140d40978`（`_CxxThrowException`）的调用环对齐；确认是「无人接住」还是「接住了但语义错」。
- **验证状态**：❌ 未定位。

### P0-C　阶段 5 判据本身：`gpak` / `CreateFileW` 仍为 0

- **说明**：main 已真进去，但没走到资源加载。静态已确认那批初始化器零导入引用，`gpak`/`CreateFileW` 只能来自 `main → 0x1409b9970` 链；先解 P0-A / P0-B。
- **验证状态**：❌ 未达成。

### P0-D　`0x50934f50`：堆指针被当函数调

- **现象**：`[FATAL] Unmapped indirect target: 0x50934f50 (nearest_lo=0x0) in_fn=0x140be0980 / 0x140bb067b`，该值正好是 `HeapAlloc(6)` 返回的堆地址附近。
- **根因（假设）**：P0-3 的次生 —— `0x140be0980` 先调「填 out 槽」的例程、再 `call qword [rsp+0x38]`；前一步 `0x140bf4ff0` 没派发 → out 槽没写 → 用残留值当函数指针。
- **修法**：随 P0-E（thunk 漏挖）一起；修完仍复现再按 in_fn 单查。
- **验证状态**：⏳ 跟随 P0-E。

### P0-E　ff25 型 import thunk 漏挖（`0x140bf4ff0`）

- **现象/证据**：16 字节 `48 85 c9 74 07 48 ff 25 f4 f6 7b 00 c3` = `test rcx,rcx / je / jmp qword [0x1413b46f0] / ret`；不在任何 `.pdata` 区间（前一条 `0x140bf4fb8..0x140bf4fbf`，下一条从 `0x140bf5000` 起）；`0x140bf4fc0/4fd0/4fe0/4ff0` 是四个 16 字节一格的兄弟桩。
- **根因**：miner 只认「`48 85 /r` 守卫」形态，纯 `48 ff 25` 尾跳（4fc0）不认；兄弟桩被「长度按下一个 seed 算」的区间吞掉。
- **修法**：`1dec451`（已推）把形状判定抽成 `tools/thunk_shapes.py` 的纯函数，认 A 纯尾跳 / B `test+je` 守卫 / C `jne` 反向守卫；槽按 16 对齐整段扫，尾部必须落在 `c3/cc/00`；配 `tools/test_thunk_shapes.py` 8 例（含实拍字节 + 3 个反例），本地 8/8 通过。
- **验证状态**：⏳ 未跑（`tools/` 改动不触发 run，要等下一轮带 trigger 的 stage3），判据：`extra_seeds.txt` 出现 `0x140bf4ff0`/`0x140bf4fc0`，`Unmapped indirect target` 归零。
- **补充事实**：上一轮里 `0x140bf4ff0` 只靠运行期 `discovered_entries.txt` + stage3b reflow 补进第二遍构建；第一遍 `stage3/manifest.tsv` 没有它、`stage3b/manifest.tsv` 有。

### P0-F　两条 API 仍未实现

- **现象**：`UNIMPL API` 表 2 条：`KERNEL32!EnumSystemLocalesW`、`SHELL32!SHGetFolderPathW`（其余都清了）。
- **根因**：`EnumSystemLocalesW` 需要回调 guest，宿主侧目前没有「回叫 guest」入口；`SHGetFolderPathW` 需要给出沙盒内真实存在的目录（`MEW_DATA_DIR` 下并确保目录存在）。
- **修法（候选）**：`EnumSystemLocalesW` 先「成功但不回调」观察 CRT 反应；`SHGetFolderPathW` 按 `host_path_from_guest` 返回 Documents/AppData。
- **验证状态**：❌ 未开始。

---

## 2. P1：已知残留（不阻塞主线，但别忘）

| 编号 | 内容 | 现状 |
|---|---|---|
| P1-1 | 3,574 个「段连续家族」里有 758 个 span 末尾不收在 `ret/jmp` 上 | 已知残留，本批补长不覆盖 |
| P1-2 | 打包叶子函数静态挖不出来；reflow 只能追「上一轮运行期发现的入口」 | 结构性限制，至少两轮才收敛 |
| P1-3 | `[rsp-repair]` 只在 SAFE 趟出现（40 vs 0），ABI 41 / abi-repair 40 与上轮持平 | 差异未解释，暂不阻塞 |
| P1-4 | 二次构建（stage3b）让单轮时间接近翻倍 | 优化项 |
| P1-5 | 「内层家族铺满」：覆盖 3,574→4,591，收在终止符上只多 51 | 已决定不做 |

---

## 3. 流程 / 工具风险（我这边实测到的）

1. **concurrency 会 cancel 在跑的轮**：任何带 `.stage3-trigger` 的提交都会顶掉正在跑的 stage3。今天已发生两次（`46002704286`、`46005327501`）。→ trigger 提交必须等上一轮结束；新代码想验证又不想顶轮，就先只推不改 trigger 的提交，等窗口再推 trigger。
2. **git push 认证只能用 token-in-URL**：`GIT_ASKPASS`（脚本回 `x-access-token` + token）和 `~/.git-credentials` + `credential.helper=store` 在这台机器上都报 `Authentication failed`；只有 `git push https://x-access-token:<TOKEN>@github.com/...` 成功（token 是 `GITHUB_WORKFLOW_TOKEN`，API 侧权限 admin/push 齐全）。→ 推送脚本统一用 URL 形式，别依赖 askpass。
3. **本机 `git status` 不可靠**：工作树与 HEAD 不同也会报 clean（`0f80e1e` 那版草稿就是这样躺着的）。→ 判定改动用 `git hash-object` / `git show HEAD:<path>` 比对 blob。
4. **`ci-diag-stage3` 分支陈旧**：最新一次 publish 是 `7ce2c8e`（run `45888616405`，11-26 20:22），今天所有轮都没更新（尽管步骤 28 报 success）。→ 「免 token 取日志」的通路实际失效，判读只能从 artifact 拉。
5. **artifact 下载：curl 直连会超时**（2 分钟无响应），要用 Python `urllib` + 302 Location + Range 1MB 分块重试（现成脚本 `/tmp/dlg.py`）。→ 这也解释了为什么「明明有 artifact 却拉不下来」。
6. **本地没有 C++ 编译器**：C++ 改动只能靠 lifter-build + stage3 `Compile all shards` 两道门；语义类改动先用 Python 复刻自测（`pcmp_core`、thunk 形状都这么做）。

---

## 4. 已排除（不是根因，别回头查）

- SKIP_INIT 129 次空转：不是机制缺陷，是 skip 分支 resume 回循环头时没推进 `rbx`（`f7f4c0e` 修，`d7dfde6` 轮实测只跳 1 次）。
- 三个 `0x140e39c0x` 调整器 thunk：`75e7557` 的形状挖掘后 FATAL 消失。
- `0x140be07e4` vtable 标签：`cae149d` 登记后不再是目标（问题前移到 `0x140bf4ff0`）。
- 初始化器能带出 `gpak`/`CreateFileW`：静态确认不可能（60 个初始化器零导入引用）。
- cookie 未初始化 / 4 字节错位：实测数据否定（容器布局 = `_Max_load_factor`/mask=7/buckets=8/`_Mysize`）。
- `0x1409b5380`/`0x1409b9970`/`0x1409b5230` 是 gpak 入口：实为 setlocale 试错路径。
- 「内层家族铺满」值得做：只多救 51 个家族，不做。

---

## 5. 下一轮判据（拿到 artifact 直接跑）

```bash
# 1) SSE4.2 是否还占位 / 越界异常是否消失
grep -n 'UNIMPL FUNC' runner*.err | grep 140d1a1b0     # 期望空
grep -c 'out_of_range\|_Xran' runner*.err              # 期望 0
# 2) thunk 挖掘（1dec451 生效后）
grep -n 'import-thunk' generated/seeds.log             # 候选数应上升
grep -c '140bf4ff0' generated/extra_seeds.txt          # 期望 ≥1
grep -c 'Unmapped indirect target' runner*.err         # 期望 0
# 3) init / main
grep -n '跳过初始化器' runner*.err                     # index 最大 2339，之后不应再有
grep -c 'E06D7363' runner*.err                         # 5 → 期望下降
grep -n 'ExitProcess' runner*.err
# 4) 阶段 5 判据
grep -c 'gpak' runner.err runner_b.err
grep -c 'CreateFileW' runner.err
```

---

## 6. 不在本清单内、但还挂着的

- **阶段 6**（GLSL → ES 3.00 全量化）：未开始。
- **阶段 7**（iOS 真机）：v0.11.8 出包，存档目录修复待真机复验；真机判据 = 装包→开窗→建 GL→出图。
- **`MEW_ASSETS_TOKEN`**：仓库 27 MB APK 分片的合规问题，待用户处理。

---

## 7. 关键地址速查

| VA / 文件 | 说明 |
|---|---|
| `0x140d1a1b0` | ucrt SSE4.2 字符串例程（P0-A） |
| `0x140d1a430` / `0x140d1a451..45d` | `pcmpestrm` 站点 / 候选枚举 |
| `0x140bf4fc0..4ff0` | 四个 ff25 import thunk（P0-E） |
| `0x140be07a0..0x140be07fe` | 含 `0x140be07e4` 标签的函数（在 .pdata 内） |
| `0x140be0980` | `call qword [rsp+0x38]` 所在函数（P0-D） |
| `0x1409b5230` | CRT `main`（argc=1，argv[0]="Mewgenics.exe"） |
| `tools/thunk_shapes.py` / `tools/test_thunk_shapes.py` | ff25 形状判定 / 8 例单测 |
| `tools/check_run.py` | 一轮 artifact 的判据打印 |
