# WinHttpRedirectProxy

轻量级通用 `winhttp.dll` 代理 DLL，用于在目标进程启动时注入自定义逻辑。

## 原理

将编译产物 `winhttp.dll` 放置到目标程序目录，系统加载时优先命中本地 DLL，所有 82 个 WinHTTP 导出函数通过静态链接器指令透明转发到 `winhttp_original.dll`（即系统原版备份），对宿主程序完全无感。

DLL 加载后会启动一个后台线程，通过 Named Pipe 连接外部 `winhttp_controller.exe`。控制器会显示当前已连接的进程列表，并可对指定进程下发 DLL 路径，目标进程收到命令后直接调用 `LoadLibraryW` 加载。

## 项目结构

```
WinHttpRedirectProxy/
├── pch.h / pch.cpp            # 预编译头
├── dllmain.cpp                # 极薄 DLL 入口壳
├── winhttp_redirect_proxy.hpp # 代理聚合头
├── winhttp_redirect_runtime.hpp # DLL 侧运行时 / Agent 线程
├── winhttp_ipc.hpp            # IPC 协议与管道辅助
├── winhttp_controller.cpp     # GUI 控制器入口
├── winhttp_controller_gui.*   # RunGui 声明与启动入口
├── winhttp_controller_state.* # Controller IPC / 会话状态
├── winhttp_controller_window.* # Controller 窗口与交互层
├── winhttp_forward_exports.hpp # 82 个 WinHTTP 导出转发声明
├── build.bat                  # 编译脚本
├── deploy.bat                 # 部署到目标目录
└── remove.bat                 # 从目标目录移除
```

## 编译

需要 Visual Studio 2022。直接运行：

```bat
build.bat
```

`build.bat` 会先调用 VS 开发者命令提示符，默认生成 x64 静态运行时产物；中间文件输出到 `obj/`，最终产物输出到 `bin/`。

产物输出到 `WinHttpRedirectProxy\bin\`：

| 文件 | 说明 |
|------|------|
| `winhttp.dll` | 代理 DLL，放到目标程序目录 |
| `winhttp_original.dll` | 系统原版备份，转发目标 |
| `winhttp_controller.exe` | 外部 GUI 控制器 |
| `winhttp_memory_client.exe` | 直接连目标进程内存 IPC 的命令行读写工具 |

## 部署

```bat
:: 部署到默认目标目录
deploy.bat

:: 部署到指定目录
deploy.bat "D:\Games\TargetGame"
```

## 移除

```bat
:: 从默认目标目录移除
remove.bat

:: 从指定目录移除
remove.bat "D:\Games\TargetGame"
```

## Controller 使用

先运行目标程序，让目录中的 `winhttp.dll` 被目标进程加载；随后运行：

```powershell
.\bin\winhttp_controller.exe
```

GUI 中可以：

- 查看当前已连接到控制器的进程
- 查看当前已存在的 `WinHttpRedirectProxyMemory-<pid>` 内存 IPC 管道；如果 control 会话暂未连上，列表会显示 `Memory IPC only`
- 选择目标进程
- 浏览并选择要加载的 DLL
- 向选中进程下发 `LoadLibraryW` 请求

`Load To Selected` 只会对带有 `Control` 通道的行启用；仅有 `Memory IPC only` 的行表示目标内存 IPC 在线，但 control 管道当前未连接到该 GUI 实例。

当前 GUI 的 `Load To Selected` 采用异步排队模型：按钮点击后会先把请求加入目标会话队列，再由对应会话线程独占 Named Pipe 发送请求，因此不会再因为同一管道句柄上的并发阻塞 I/O 导致界面卡死。

日志中通常会看到以下阶段：

- `[load-queued]`：GUI 已把请求加入队列
- `[load-request]`：会话线程已把请求发给目标进程
- `[load-ok]` / `[load-fail]`：目标进程返回加载结果

另外，`winhttp_controller.exe` 自身已显式跳过 DLL 侧 Agent 运行时，因此即使与 `winhttp.dll` 位于同一目录，也不会再把控制器自己错误显示为一个已连接目标。

## 运行时日志

代理 DLL 加载后会在同目录生成 `upd_runtime_log.txt`，记录控制器连接状态、队列请求处理以及 `LoadLibraryW` 结果。排查问题时建议同时查看 GUI 日志和该文件。

## 内存 IPC

代理 DLL 现在会在目标进程内额外开一个按 `PID` 区分的 Named Pipe：

- `\\.\pipe\WinHttpRedirectProxyMemory-<pid>`

该接口用于在目标进程内部执行带保护的内存读写，方便定位注入后必现崩溃点。核心策略：

- 先用 `VirtualQuery` 做区域级预检，并缓存查询结果
- 再用 `__try / __except` 包住真正的内存访问
- 额外注册 `VEH` 记录访问违规时的 `fault address`、`RIP` 和页属性

命令行客户端：

```powershell
.\bin\winhttp_memory_client.exe read <pid> <address> <size>
.\bin\winhttp_memory_client.exe write <pid> <address> <hex bytes...>
```

示例：

```powershell
.\bin\winhttp_memory_client.exe read 1234 0x140000000 64
.\bin\winhttp_memory_client.exe write 1234 0x140000000 90 90 CC
```

返回内容会带上：

- 请求状态
- 实际读写字节数
- `fault address`
- `RIP`
- `VirtualQuery` 命中的 `protect/state/type`
- `VirtualQuery` 缓存命中/失配次数

## 技术细节

- **编译器**：MSVC (cl.exe)，C++20，x64，静态运行时 (/MT)
- **导出转发**：通过 `#pragma comment(linker, "/export:...")` 静态声明，零运行时开销
- **核心结构**：DLL 侧与 Controller 侧已拆分，`dllmain.cpp` 仍保持极薄入口，GUI 再拆分为 `state` / `window` / `RunGui` 三层
- **IPC**：Windows Named Pipe，管道名为 `\\.\pipe\WinHttpRedirectProxyControl`
- **控制方式**：由外部 GUI 控制器选择进程并下发 DLL 路径
- **加载方式**：目标进程收到命令后直接调用 `LoadLibraryW`
- **线程模型**：会话线程独占单个 Pipe 的读写，GUI 线程只负责入队，避免同步句柄并发阻塞
- **线程安全**：日志、会话状态和待发送队列使用 `std::mutex` 与 `std::atomic` 保护

## License

MIT
