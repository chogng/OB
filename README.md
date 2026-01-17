# OriginBridge

OriginBridge 是一个 Windows 桌面应用（Tauri 2 + Rust + Vite），用于在本机自动处理 Appointer Device Analysis 导出的 `device_analysis_origin.zip`，并通过 OriginLab Origin（COM 自动化）生成图表与 `.opju` 项目文件。

## 功能特点

- **ZIP 出图**：选择 `device_analysis_origin.zip` 后，自动解压并出图
- **Origin 自动化**：优先执行包内 `.ogs` 脚本；失败时回退到 CSV 导入 + `plotxy`
- **可追溯**：每次任务保留 PowerShell 执行脚本与详细日志

## 使用方法

### 图形界面（推荐）

1. 启动 OriginBridge
2. 点击 **“解压 ZIP”**（如未先选择 ZIP，会自动弹出选择框）
3. 选择从 Appointer 下载的 `device_analysis_origin.zip`
4. 等待片刻，Origin 将自动打开并展示出图结果

### 工作目录

解压输出到 ZIP 所在目录下的 `extracted_（ZIP文件名）`（例如 `extracted_device_analysis_origin`；重复运行会覆盖该目录；若目录被占用无法删除则会创建带时间戳的新目录）。
日志/错误文件输出到解压目录下的 `.ob\\`，并会在解压目录下生成 `.ob\\log_location.txt` 指向真实路径。

### Origin 可执行文件配置

需要先配置本机 Origin 的可执行文件路径（常见为 `Origin64.exe`），应用才会拉起 Origin 打开出图结果。

- 推荐：在界面里点击“选择 Origin 可执行文件”进行配置并保存
- 可选：点击“自动检测”（快速：优先读取注册表 App Paths，其次快捷方式/常见安装目录；不会写入注册表）
- 兜底：点击“深度扫描（慢）”（递归扫描常见安装目录，可能较慢；不会写入注册表）

配置会写入 `%APPDATA%\\Appointer\\OriginBridge\\config.json`（字段：`originExe`）。

## 故障排查

1. **任务失败/无结果**
   - 优先打开解压目录下的 `.ob\\log_location.txt`（包含 WorkDir/Log/Error 的真实路径）
   - 失败时查看 `error.txt`；查看 `originbridge.log` 获取详细执行日志
2. **找不到 Origin 或启动失败**
   - 设置环境变量 `ORIGINBRIDGE_ORIGIN_EXE` 指向 Origin 可执行文件完整路径（如 `Origin64.exe` / `Origin.exe`）
   - 示例：`C:\Program Files\OriginLab\Origin2024\Origin64.exe`
3. **权限/杀软/策略限制**
   - 确保 ZIP 所在目录有写入权限（解压目录会创建在同级目录下）
   - 本项目会在后台启动 PowerShell worker（`-ExecutionPolicy Bypass`），如企业策略限制 PowerShell 请放行

## 开发指南

### 技术栈

- **前端**：Vanilla JavaScript + Tauri API（`index.html`）
- **后端**：Rust（Tauri 2.x，`src-tauri/src`）
- **自动化**：Windows COM + PowerShell worker（Origin Automation）

### 开发环境设置

```powershell
npm install
npm run tauri:dev
```

### 构建发布版本

```powershell
npm run tauri:build
```

构建产物默认在 `src-tauri/target/release/bundle/`。

### 项目结构

```
OriginBridge/
├── src-tauri/                      # Rust / Tauri 后端
│   ├── src/
│   │   ├── lib.rs                  # Tauri commands
│   │   └── utils/
│   │       └── origin.rs           # ZIP 处理 + Origin 自动化（含 PS worker）
│   ├── tauri.conf.json             # Tauri 配置
│   └── Cargo.toml
├── index.html                      # 前端界面（按钮 + 状态输出）
├── package.json
└── vite.config.ts
```

## 系统要求

- **操作系统**：Windows 10/11
- **必需软件**：OriginLab Origin（需已安装并可正常启动）
- **运行时**：WebView2（Windows 11 内置；Windows 10 可能需要安装）

## 许可证

MIT License

## Cleanup

OriginBridge automatically cleans up work artifacts under `extractDir\\.ob\\` after the generated `.opju` is closed by Origin.

To keep logs/scripts for debugging, set environment variable `ORIGINBRIDGE_KEEP_WORK=1` (or `ORIGINBRIDGE_KEEP_TEMP=1`) and re-run.

## 贡献

欢迎提交 Issue 和 Pull Request！
