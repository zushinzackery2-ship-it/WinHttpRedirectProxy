# WinHttpRedirectProxy

轻量级通用 `winhttp.dll` 代理 DLL，用于在目标进程启动时注入自定义逻辑。

## 原理

将编译产物 `winhttp.dll` 放置到目标程序目录，系统加载时优先命中本地 DLL，所有 82 个 WinHTTP 导出函数通过静态链接器指令透明转发到 `winhttp_original.dll`（即系统原版备份），对宿主程序完全无感。

DLL 加载后会启动一个后台线程，等待 `GameAssembly.dll` 或 `UnityPlayer.dll` 就绪，随后加载同目录下的 `RuntimeCaptureProbe.dll` 执行运行时捕获逻辑。

## 项目结构

```
WinHttpRedirectProxy/
├── pch.h / pch.cpp          # 预编译头
├── dllmain.cpp               # DLL 入口与运行时线程
├── winhttp_forward_exports.h # 82 个 WinHTTP 导出转发声明
├── build.bat                 # 编译脚本
├── deploy.bat                # 部署到目标目录
└── remove.bat                # 从目标目录移除
```

## 编译

需要 Visual Studio 2022。直接运行：

```bat
build.bat
```

产物输出到 `ReverseTools\bin\WinHttpRedirectProxy\`：

| 文件 | 说明 |
|------|------|
| `winhttp.dll` | 代理 DLL，放到目标程序目录 |
| `winhttp_original.dll` | 系统原版备份，转发目标 |
| `RuntimeCaptureProbe.dll` | 运行时捕获探针（如已编译） |

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

## 运行时日志

代理 DLL 加载后会在同目录生成 `upd_runtime_log.txt`，记录启动流程和模块快照信息。

## 技术细节

- **编译器**：MSVC (cl.exe)，C++20，x64，静态运行时 (/MT)
- **导出转发**：通过 `#pragma comment(linker, "/export:...")` 静态声明，零运行时开销
- **模块等待**：轮询 `EnumProcessModules`，超时 180 秒
- **线程安全**：日志写入使用 `std::mutex` 保护

## License

MIT
