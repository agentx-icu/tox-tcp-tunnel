# Cross-Platform Release Packaging Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 为 `toxtunnel` 增加跨平台安装包构建与发布能力，并提供 `print-id` 与终端 QR 输出能力，支持安装后以系统服务方式运行。

**Architecture:** 采用“功能先行、打包后置”的分层推进：先实现 `print-id`/QR 及轻量 Tox ID 读取，再补齐服务模式抽象，随后引入 CPack + 平台安装脚本，最后在 GitHub Actions tag 流程中构建并发布安装包。保持现有 CLI 与核心隧道逻辑不重构，仅做增量扩展。

**Tech Stack:** C++20, CMake/FetchContent, CPack, GitHub Actions, systemd/launchd/SCM, Nayuki QR Code Generator

---

### Task 1: 引入 QR 依赖并实现终端 QR 渲染

**Files:**
- Modify: `CMakeLists.txt`
- Create: `include/toxtunnel/util/qr_code.hpp`
- Create: `src/util/qr_code.cpp`
- Modify: `src/util/CMake` 引用位置（若项目中通过 `target_sources` 统一维护则改 `CMakeLists.txt`）
- Test: `tests/unit/` 下新增或扩展 QR 渲染测试（例如 `tests/unit/test_qr_code.cpp`）

**Step 1: 写失败测试（QR 基础契约）**

为 `generate_qr_terminal(text, use_color)` 建立最小契约测试：
- 空字符串返回错误/空输出（按接口约定二选一）
- 非空字符串输出包含多行
- 不开启颜色时不含 ANSI 转义码

**Step 2: 运行测试确认失败**

Run: `cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j4 && ./build/tests/unit_tests --gtest_filter=*Qr*`

Expected: 至少一条 `Qr` 相关用例失败（函数未实现或行为不符）。

**Step 3: 添加 Nayuki 依赖并实现最小可用渲染**

在 `CMakeLists.txt` 添加 `qrcodegen` 的 `FetchContent_Declare` + `FetchContent_MakeAvailable`，并在 `toxtunnel_lib` 里链接/包含所需源。实现 Unicode 块字符渲染（`█ ▀ ▄`）和基础边距。

**Step 4: 重新运行 QR 用例**

Run: `./build/tests/unit_tests --gtest_filter=*Qr*`

Expected: `Qr` 相关测试全部通过。

**Step 5: 提交**

Run: `git add CMakeLists.txt include/toxtunnel/util/qr_code.hpp src/util/qr_code.cpp tests/unit && git commit -m "feat: add terminal QR rendering utility"`

---

### Task 2: 为 ToxAdapter 增加轻量 ID 读取接口

**Files:**
- Modify: `include/toxtunnel/tox/tox_adapter.hpp`
- Modify: `src/tox/tox_adapter.cpp`
- Test: `tests/unit/test_tox_adapter.cpp`（或对应 tox adapter 测试文件）

**Step 1: 写失败测试（仅初始化身份，不启动网络）**

新增测试覆盖：
- 数据目录不存在时可创建并返回有效 ID
- 已有数据目录可稳定返回同一 ID
- 不需要启动连接/事件循环即可返回结果

**Step 2: 运行测试确认失败**

Run: `./build/tests/unit_tests --gtest_filter=*ToxAdapter*`

Expected: 新增用例失败。

**Step 3: 实现接口**

添加：
- `[[nodiscard]] util::Expected<std::string, std::string> get_tox_id_only(const std::filesystem::path& data_dir);`

实现要求：
- 仅做最小 tox profile 读写与地址提取
- 不创建网络会话、不启动后台线程
- 错误路径返回清晰错误字符串

**Step 4: 回归测试**

Run: `./build/tests/unit_tests --gtest_filter=*ToxAdapter*`

Expected: `ToxAdapter` 相关用例通过。

**Step 5: 提交**

Run: `git add include/toxtunnel/tox/tox_adapter.hpp src/tox/tox_adapter.cpp tests/unit && git commit -m "feat: add lightweight tox id retrieval API"`

---

### Task 3: 新增 `print-id` 子命令与 `--qr/--color`

**Files:**
- Modify: `cli/main.cpp`
- Modify: `include/toxtunnel/util/config.hpp`（仅当参数模型需扩展）
- Modify: `src/util/config.cpp`（仅当参数模型需扩展）
- Test: `tests/integration/` 下 CLI 行为测试（建议新增）

**Step 1: 写失败测试（CLI 行为）**

覆盖命令行为：
- `toxtunnel print-id -d <dir>` 输出纯 ID
- `toxtunnel print-id --qr` 输出多行二维码
- `toxtunnel print-id --color` 未带 `--qr` 时给出参数错误

**Step 2: 运行测试确认失败**

Run: `./build/tests/integration_tests --gtest_filter=*Cli*print*id*`

Expected: 至少一条失败。

**Step 3: 实现子命令**

在 `cli/main.cpp` 增加 `print-id` 子命令，调用 `get_tox_id_only()`，并在 `--qr` 时调用 `generate_qr_terminal()`。要求：
- `--color` 仅对 `--qr` 生效
- 保持主运行路径（server/client）逻辑不破坏

**Step 4: 本地手工验证**

Run:
- `./build/toxtunnel print-id`
- `./build/toxtunnel print-id --qr`
- `./build/toxtunnel print-id --qr --color`

Expected:
- 第一条输出 76 字符十六进制 Tox ID（或项目既定格式）
- 后两条输出可扫描二维码

**Step 5: 提交**

Run: `git add cli/main.cpp tests/integration && git commit -m "feat: add print-id command with terminal QR output"`

---

### Task 4: 增加服务模式抽象与平台支持

**Files:**
- Modify: `cli/main.cpp`
- Create: `include/toxtunnel/util/windows_service.hpp`
- Create: `src/util/windows_service.cpp`
- Create: `include/toxtunnel/util/systemd_notify.hpp`（若需要头文件）
- Create: `src/util/systemd_notify.cpp`
- Modify: `CMakeLists.txt`（平台条件编译与链接）
- Test: `tests/unit/` 新增服务模式参数/状态测试（可对 Linux notify 做单测）

**Step 1: 写失败测试（参数与最小行为）**

覆盖：
- `--service` 参数可被识别
- Linux 下 `sd_notify` 消息格式正确（mock socket）
- 非 Linux 平台下调用为 no-op 或安全降级

**Step 2: 运行测试确认失败**

Run: `./build/tests/unit_tests --gtest_filter=*Service*:*Systemd*`

Expected: 新增测试失败。

**Step 3: 实现 `--service` 路径**

- CLI 层面添加 `--service`
- Windows: 封装 SCM 状态上报与服务主循环入口（安装/卸载可先暴露 API，后续由安装器调用）
- Linux: 通过 `NOTIFY_SOCKET` 发送 `READY=1` / `STOPPING=1`
- macOS: 先遵循标准 daemon 行为（launchd 托管）

**Step 4: 回归 server/client 主逻辑**

Run:
- `./build/toxtunnel -m server --help`
- `./build/toxtunnel -m client --help`

Expected: 原有参数和运行模式不回归。

**Step 5: 提交**

Run: `git add cli/main.cpp include/toxtunnel/util src/util CMakeLists.txt tests/unit && git commit -m "feat: add cross-platform service mode hooks"`

---

### Task 5: 建立 packaging 目录与平台安装资源

**Files:**
- Create: `packaging/config.yaml.example`
- Create: `packaging/linux/toxtunnel.service`
- Create: `packaging/linux/postinst`
- Create: `packaging/linux/prerm`
- Create: `packaging/macos/com.toxtunnel.daemon.plist`
- Create: `packaging/windows/installer.nsi`
- Modify: `README.md`（增加安装/服务说明）

**Step 1: 先添加静态资源文件**

创建三平台服务模板和脚本，确保路径与 `ExecStart`、配置目录一致。

**Step 2: 校验脚本语法与换行**

Run:
- `bash -n packaging/linux/postinst`
- `bash -n packaging/linux/prerm`

Expected: 无语法错误。

**Step 3: 文档最小更新**

在 `README.md` 新增：
- 配置模板位置
- 安装后服务注册方式
- `print-id --qr` 示例

**Step 4: 提交**

Run: `git add packaging README.md && git commit -m "chore: add cross-platform packaging assets"`

---

### Task 6: 引入 CPack 配置与安装规则

**Files:**
- Create: `cmake/Packaging.cmake`
- Modify: `CMakeLists.txt`

**Step 1: 写最小 CPack 配置**

按平台设置生成器：
- Linux: `DEB;RPM;TGZ`
- macOS: `productbuild;TGZ`
- Windows: `NSIS;ZIP`

并定义包名、版本、依赖、安装组件映射。

**Step 2: 在主 CMake 挂载 packaging**

在 `CMakeLists.txt` 末尾 `include(cmake/Packaging.cmake)`，并补齐 `install(FILES ...)`、`install(PROGRAMS ...)` 规则，将 `packaging/*` 资源安装到正确位置（或通过 CPack script 注入）。

**Step 3: 本地打包验证（当前平台）**

Run:
- `cmake -B build -DCMAKE_BUILD_TYPE=Release`
- `cmake --build build -j4`
- `cd build && cpack -G TGZ`

Expected: 生成 `ToxTunnel-*.tar.gz` 且包含可执行文件与文档。

**Step 4: Linux 补充验证（在 Linux 环境执行）**

Run:
- `cd build && cpack -G DEB`
- `dpkg -c ./*.deb`

Expected: 包含 `toxtunnel` 二进制与服务/配置文件。

**Step 5: 提交**

Run: `git add CMakeLists.txt cmake/Packaging.cmake && git commit -m "build: add CPack packaging configuration"`

---

### Task 7: 扩展 GitHub Actions 构建安装包并发布

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: 新增 `build-installers` job**

要求：
- `needs: build-release-matrix`
- 仅 tag 触发：`if: startsWith(github.ref, 'refs/tags/v')`
- matrix 覆盖 `linux-x86_64` / `macos-universal` / `windows-x86_64`
- 执行 `cpack -G "<generator>"` 并上传安装包 artifact

**Step 2: 更新 `publish-release` job**

下载 `release-*` + `installer-*` artifacts，统一上传到 GitHub Release。

**Step 3: YAML 校验**

Run: `gh workflow view ci.yml --yaml >/dev/null`（或本地 YAML lint）

Expected: 语法正确，可被 GitHub Actions 正常解析。

**Step 4: 提交**

Run: `git add .github/workflows/ci.yml && git commit -m "ci: build and publish cross-platform installers on tags"`

---

### Task 8: 端到端验收与发布演练

**Files:**
- Inspect only

**Step 1: 本地功能验收**

Run:
- `cmake -B build -DCMAKE_BUILD_TYPE=Release`
- `cmake --build build -j$(sysctl -n hw.ncpu)`
- `./build/toxtunnel print-id --qr`

Expected: 构建成功，QR 可读。

**Step 2: 本地测试验收**

Run:
- `(cd build && ctest --output-on-failure)`

Expected: 全部测试通过。

**Step 3: CI 发布演练**

Run:
- `git tag v0.0.0-test`
- `git push origin v0.0.0-test`

Expected:
- `build-installers` 成功
- Release 页面包含二进制包 + 安装包

**Step 4: 安装后服务验收（各平台）**

检查：
- 服务是否成功注册
- 手动启动后隧道可工作
- `toxtunnel print-id --qr` 输出正常

---

### 风险与回滚策略

**风险 1: QR 渲染在某些终端字体下不可读**
- 缓解：默认输出纯文本 ID，`--qr` 为可选；保留 `--color` 开关可关闭。

**风险 2: systemd/launchd/SCM 行为差异导致服务状态不一致**
- 缓解：服务逻辑保持最小，平台脚本做职责隔离；每个平台独立验收清单。

**风险 3: CPack 生成器在 Runner 环境缺依赖**
- 缓解：在 workflow 显式安装打包依赖（rpm/nsis/productbuild 前置检查），失败时回落产出 `TGZ/ZIP` 作为兜底发布物。

**回滚策略**
- 若发布流程异常：先回滚 `.github/workflows/ci.yml` 到仅发布二进制模式；
- 若服务集成异常：保留 CLI 前台运行模式，关闭 `--service` 默认路径；
- 若 QR 影响稳定性：保留 `print-id` 纯文本输出，暂时隐藏 `--qr` 文档入口。

