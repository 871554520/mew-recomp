# 方案二：窗口 / GDI / GL 垫片设计（静态数据先行）

> 日期：2026-11-27
> 目的：把「方案二离出画面还有多远」用静态数据钉死，避免无目标地补垫片。
> 数据来源：本机解析 `Mewgenics.exe` 导入表（455 个导入）与 `call/jmp [IAT]` 调用点（4,485 处）。

## 1. 数据：三类系统 DLL 的真实规模

| DLL | 导入数 | 调用点数 | 说明 |
|---|---:|---:|---|
| USER32 | 138 | 407 | 窗口/消息/输入 |
| GDI32 | 24 | 66 | 像素格式、DC、位图（GL 初始化用） |
| OPENGL32 | 27 | **2,893** | 其中 **2,730 处是 `wglGetProcAddress`** |

USER32 里真正关键的一小撮（按调用点排序）：

```
GetAsyncKeyState 20   GetWindowLongW 19   GetSystemMetrics 14
ScreenToClient 11     ReleaseDC 11        DestroyWindow 11
SetWindowPos 10       GetKeyState 10      GetDC 9  ClientToScreen 9
GetClientRect 8       CreateWindowExW 8   ShowWindow 7  SetWindowLongW 7
GetMessageW / PeekMessageW / DispatchMessageW / TranslateMessageW
RegisterClassW / DefWindowProcW / CallWindowProcW / SendMessageW / PostMessageW
```

GDI32 里关键的是 GL 初始化那一套：

```
SetPixelFormat 4   DescribePixelFormat 3   ChoosePixelFormat 2
GetDeviceCaps 3    CreateDIBSection 3      CreateCompatibleDC 3
SwapBuffers 1      DeleteObject 16         DeleteDC 6
```

## 2. 关键发现：窗口用 USER32 直接建，GL 入口是**动态加载**的

- 导入表里**没有 SDL3.dll**，说明 SDL 是静态链进 `Mewgenics.exe` 的。
- 导入表里**没有 `wglCreateContext` / `wglMakeCurrent`**，但 `SwapBuffers` 在 GDI32。
- 结论：SDL 的 Windows GL 后端走的是
  `LoadLibrary("opengl32.dll")` + `GetProcAddress("wglCreateContext"/"wglMakeCurrent"/…)`，
  扩展函数再经 `wglGetProcAddress` 取（2,730 处调用点就是这么来的）。

对垫片的直接含义：**`wgl*` 这一批的接入点是 KERNEL32 的动态加载垫片**
（`shim_KERNEL32_LoadLibraryW` 返回假模块句柄、`shim_KERNEL32_GetProcAddress` 查
`kApis` 表返回合成地址），而不是导入表。要接真 GL，就：
1. `LoadLibraryW("opengl32.dll")` 照旧返回假句柄；
2. `GetProcAddress(h,"wglCreateContext"/"wglMakeCurrent"/"wglDeleteContext"/
   "wglGetProcAddress"/"wglGetCurrentDC")` 在 `kApis` 里映射到**宿主侧实现**；
3. `wglGetProcAddress("glGenBuffers")` 这类直接 `dlsym(RTLD_DEFAULT, name)`——
   Linux 的 libGL 导出的名字与 Windows 完全一致（`glGenBuffers` 而不是 `_glGenBuffers`）。

## 3. 分两阶段：先「跑到资源加载」，再决定要不要画面

### 阶段 A（优先，成本低）：假窗口 + 有界消息循环 + GL 不可用

目标：让引擎初始化一路跑下去，跑到 gpak 解析、配置读取，然后**有界退出**，把日志拿全。

- **窗口模型**：`CreateWindowExW` 返回一个常量假 HWND（如 `0x10001`）；
  `GetDC`/`ReleaseDC` 返回常量假 HDC；`CreateWindowExW` 里把请求的 w/h 记进一张表，
  `GetClientRect`/`GetWindowRect` 如实回填。
- **消息循环**：`PeekMessageW`/`GetMessageW` 合成 `WM_PAINT`/`WM_TIMER`；
  跑到 `MEW_MAX_FRAMES`（默认 60）帧后投递 `WM_QUIT` 并让 `GetMessageW` 返回 0，
  引擎自然退出。**这一点很关键**：不设上限就会像现在这样只能靠 `timeout` 杀进程，
  丢掉退出路径的日志。
- **输入**：`GetAsyncKeyState`/`GetKeyState` 返回 0；`GetRawInputDeviceList` 返回 0 个设备
  （SDL 会因此禁用输入，正好）。
- **GL**：`GetProcAddress("wglCreateContext")` 先返回 0（如实失败）。引擎大概率会
  打一条「no GL」然后走软件渲染或直接退出——**这一步本身就是有价值的观测**。

### 阶段 B（成本高，按需）：真 GL 上下文

若阶段 A 证明「引擎在等 GL 就绪，没有它就不继续」，再上：

- 用 **EGL surfaceless**（`EGL_PLATFORM_SURFACELESS_MESA`）建上下文，
  `wglCreateContext`/`wglMakeCurrent` 映射到 EGL，`SwapBuffers` 映射 `eglSwapBuffers`；
- `wglGetProcAddress` → `dlsym(RTLD_DEFAULT, name)`；
- CI 侧需要装 `libegl1-mesa-dev libgl1-mesa-dri`（在 stage3 的 Install toolchain 里加）。

风险：Mesa 的 surfaceless 要走 llvmpipe（软件光栅），60 帧可能很慢；
可以只渲染 3~5 帧验证「能出画面」即可。

## 4. 优先级判断

| 项 | 成本 | 对「证明路线 B 的假设」的价值 |
|---|---|---|
| 假窗口 + 有界消息循环 | 低（~150 行） | 高：把引擎初始化跑穿，暴露后续缺的垫片 |
| 输入类垫片 | 低 | 低（没有它也能跑） |
| wgl 动态加载映射 | 中 | 中：能确认引擎是否卡在 GL |
| 真 GL（EGL 上下文） | 高 | 低：画面是路线 B 的 KPI，不是方案二的 |

结论：**先做阶段 A**。方案二存在的意义是「可观测、可插桩」，不是出画面。

## 5. 判据

- 阶段 A 通过：日志出现 gpak 打开/解析行，且进程在 `MEW_MAX_FRAMES` 帧后**正常退出**
  （`rc=0` 或引擎自己的退出码），不再需要 `timeout` 杀。
- 阶段 A 后的新缺口：`[UNIMPL API]` 表里若出现 `wglCreateContext` 相关或
  `USER32!GetMessageW` 之外的名字，按表继续补。
