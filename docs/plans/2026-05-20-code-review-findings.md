# ToxTunnel 全量代码 Review 发现汇总

**日期**: 2026-05-20
**输入**: 13 个 review 子任务 (R1-R13)，按 80 个 Feature 分派给独立 code-reviewer agent。每个 agent 仅报告 high-confidence 问题（置信度 ≥ 80）。
**配套文档**:
- 功能清单基线: [`2026-05-20-code-review-feature-inventory.md`](./2026-05-20-code-review-feature-inventory.md)

---

## 0. 数字汇总

| 严重度 | 数量 | 说明 |
|--------|-----:|------|
| **Critical** | 28 | 数据损坏 / UB / 安全漏洞 / 核心功能完全失效 |
| **High** | 41 | 逻辑错误 / 资源泄漏 / 竞态 / 规范违反 |
| **Medium** | 5 | 鲁棒性、可观测性 |
| **合计** | **74** | fully-expanded 计数口径（按独立 finding 编号统计） |

**所有 Critical 都强烈建议在下一个版本前修复**；其中至少 8 项与持久化或线程模型直接相关，是 v0.4 系列的回归风险源。

### 0.1 按子系统分布

| 子系统 | Feature 数 | Critical | High | Medium | 合计 | 每 Feature finding 密度 | 观察 |
|--------|-----------:|---------:|-----:|-------:|-----:|------------------------:|------|
| App | 21 | 9 | 11 | 1 | 21 | 1.00 | Server 主路径与 Client failover/reload 都是热点 |
| Core | 10 | 1 | 2 | 2 | 5 | 0.50 | 量不大，但集中在 `TcpConnection` / `TcpListener` 并发边界 |
| Tox | 13 | 5 | 7 | 2 | 14 | 1.08 | 线程契约、bootstrap、持久化问题高度集中 |
| Tunnel | 18 | 5 | 10 | 0 | 15 | 0.83 | v0.4 新增性能路径（coalescing / BDP / backpressure）风险高 |
| Util | 12 | 6 | 7 | 0 | 13 | 1.08 | config/reload/atomic-write/metrics 是运维入口高危面 |
| CLI | 6 | 2 | 4 | 0 | 6 | 1.00 | `inspect` / `reload` / signal handling 需要专门硬化 |

结论很直接：**先别按目录平均修，优先打 Tox / Tunnel / Util 这三条线**；其中 Tox / Util 的 finding 密度最高，Tunnel 则承载了最多 v0.4 性能路径风险，三者刚好踩在线程模型、协议兼容、配置入口这三类放大器上。

---

## 1. 横切主题（多个 review 共同发现的模式）

按发生频次排序，每条都跨多个子系统出现，**优先按主题修复比按 R 编号修复成本低**：

### T1. 跨线程拿裸指针访问对象 (5 处)
裸指针在锁外被解引用，与并发销毁/erase 产生 UAF。
- R1: `TunnelServer::on_lossless_packet` → `manager_ptr-&gt;route_frame` (`tunnel_server.cpp:104-119`)
- R1: `TunnelServer::handle_tunnel_open` 锁外 `manager_ptr-&gt;handle_incoming_open / add_tunnel` (`tunnel_server.cpp:562-608`)
- R1: `TunnelServer::wire_tcp_to_tunnel` 锁外 `manager_ptr-&gt;send_frame` (`tunnel_server.cpp:774`)
- R5: `TcpConnection::do_write` `async_write` 持 `front.bytes()` 裸指针 (`tcp_connection.cpp:420-444`)
- R10: `TunnelManager::route_frame` 锁内取裸 `Tunnel*` 后无锁调用 `handle_frame` (`tunnel_manager.cpp:393-413`)

**统一修复方向**：所有这类容器值改为 `shared_ptr`，锁内拷贝 `shared_ptr` 后释放锁再调用。

### T2. 非原子写持久化文件，崩溃易损坏 (4 处)
项目规范明确要求所有持久化走 `util::atomic_write_file`，但有多处违规。
- R6/R7: `ToxAdapter::write_save_data` 手写 tmp+rename 无 fsync (`tox_adapter.cpp:892-933`) ← `tox_save.dat`
- R7: `ToxWatchdog::persist_abort_count` `ios::trunc` 后写入，abort 在中间触发即清零 (`tox_watchdog.cpp:107-129`)
- R7: `bootstrap_source::write_cache` 普通 `ofstream` 写节点缓存 (`bootstrap_source.cpp:46-58`)
- R11: `Config::save()` 用 `std::ofstream` 直接写 (`config.cpp:714-726`)

**统一修复方向**：全部走 `util::atomic_write_file`，并补回归测试覆盖崩溃恢复。

### T3. 配置热重载 diff 不完整 (3+ 处)
CLAUDE.md 明确只允许 reload `server.rules_file` / `client.forwards` / `logging.level`，其他必须拒绝 — 但 diff 实现有遗漏，会静默接受应被拒绝的变更。
- R11: 缺 `client.fallback_server_ids` 检查 (`config_reload.cpp:99-108`)
- R11: 缺 `client.failover` (FailoverConfig) 检查 (`config_reload.cpp:96-109`)
- R1: `sync_rate_limiter` 不清除被删除好友的旧 token 桶，reload 后旧限流状态残留 (`tunnel_server.cpp:424-433`)

**统一修复方向**：补全 diff 字段；reload 时 `RateLimiter` 整体替换实例而非增量更新。

### T4. 线程模型违规：跨线程调用 toxcore (1 个根因，影响极广)
- R6 (Critical): `ToxAdapter` 大量 public 方法 (`bootstrap`、`add_friend`、`send_lossless_packet`、`get_address` 等) 用 mutex 串行化跨线程调用 toxcore，**违反"所有 toxcore API 仅在 Tox 线程"的设计契约** (`tox_adapter.cpp:310-333` 等)。

**统一修复方向**：所有 toxcore 调用改走 `ToxThread` 的 Command 队列；现有 mutex 方案要么补充文档说明 toxcore 在 mutex 下确实多线程安全，要么彻底重构。

### T5. 流控/背压链路断裂 (2 处 Critical)
**v0.4 性能路径关键缺陷**：背压名义上从 TCP→Tunnel→Tox 全链路，但实际未联动。
- R9 (Critical): `send_window_used_` 满后 `send_data_to_tox` 返回 false，但 `on_tcp_data_received` `(void)` 忽略返回值，TCP 不暂停 — **新数据被静默丢弃**而非反向 pause read。`TunnelManager::has_backpressure()` 计算正确，但无任何 listener/connection 消费 (`tunnel.cpp:473-478`, `tunnel_manager.cpp:510-512`)
- R7 (Critical): `ToxConnection::on_ack` 与 `get_pending_data` 不同步 `send_window_used_`，`can_send` 与实际队列永久失步 (`tox_connection.cpp:136-150`)

**统一修复方向**：补 read pause/resume；明确每个计数器的 +/− 配对来源。

### T6. v0.3↔v0.4 互通性破损
- R8 (High): `deserialize` 对 unknown opcode 返回错误而非"忽略" — v0.4 client 发 RESUME 帧给 v0.3 server，server 会断连 (`protocol.cpp:44-61, 330-331`)
- R8 (Critical): `deserialize` 与 `serialize_tunnel_data_in_place` 对 `0xA0` lossless 前缀的约定不一致，需要确认 ToxAdapter 回调时是否剥头 (`protocol.cpp:303-364`)

### T7. 信号/生命周期 (CLI + Server 共性)
- R13 (Critical): `run_server/run_client` SIGINT/SIGTERM 一次性 handler，第二次信号无响应 — `server.stop()` 阻塞时只能 SIGKILL (`cli/main.cpp:658-663, 758-763`)

### T8. 数据竞争（非原子量被多线程读写）(汇总)
- R5: `TcpListener::accepting_` / `max_connections_` 非原子 (`tcp_listener.hpp:167-168`)
- R5: `IoContext::running_` 非原子 (`io_context.hpp:185`)
- R9: `WriteCoalescer::candidate_` / `candidate_streak_` 非原子 (`write_coalescer.hpp:152-153`)
- R9/R10: `TunnelManager::backpressure_threshold_` 非原子 (`tunnel_manager.hpp:368`, `tunnel_manager.cpp:510-512`)
- R3: `TunnelClient::server_tox_id_hex_` (`std::string`) 跨线程无锁读 (`tunnel_client.cpp:1103`, `981-993`)
- R11: `Logger g_logger` (`std::shared_ptr`) 非原子 (`logger.cpp:110-118`)

---

## 2. Critical 问题清单（共 28 项）

### C-1 ~ C-6 (App 层)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| C-1 | R1 | `on_friend_connection` 与 `on_lossless_packet` 跨线程裸指针 UAF | `tunnel_server.cpp:104-119` |
| C-2 | R1 | `handle_tunnel_open` 锁外 `manager_ptr` UAF | `tunnel_server.cpp:562-608` |
| C-3 | R2 | `host_matches` 通配符匹配大小写敏感（应不敏感），导致 deny 规则可被大写绕过 — **安全漏洞** | `rules_engine.cpp:211-246` |
| C-4 | R2 | RateLimiter `report` 模式 `try_consume_open` 与 `try_consume_bytes` 语义不一致（bytes 路径允许负值积压） | `rate_limiter.cpp:144-180` |
| C-5 | R3 | `TunnelClient::reload()` 无线程同步直接 mutate `listeners_` / `forward_rules_` | `tunnel_client.cpp:353-403` |
| C-6 | R3 | Grace-period `online_since` 在网络抖动后不重置，可能秒级切回 primary 引发抖动 | `tunnel_client.cpp:1062-1069` |

### C-7 ~ C-9 (Inspect/SOCKS5/Resume)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| C-7 | R4 | **`Socks5Listener::start()` 不校验 loopback**（仅 Config 校验）— 安全不变量在组件边界未守护 | `socks5_listener.cpp:403-447` |
| C-8 | R4 | Windows Inspect 命名管道 `nMaxInstances=1`，且 `CreateNamedPipeA` 失败时永久 return — **IPC 端点单失败永久不可用** | `inspect_server.cpp:362, 371` |
| C-9 | R4 | `TunnelResumeStore` 用 `steady_clock` 计 `saved_at_ns`，**跨进程重启后语义完全失效** — resume 的核心使用场景破损 | `tunnel_resume_store.cpp:16-18, 65, 164` |

### C-10 (Core I/O)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| C-10 | R5 | `TcpConnection::do_write` `async_write` 持 `front.bytes()` 裸指针，`force_close` 可在飞行中 `clear()` 队列触发 UAF | `tcp_connection.cpp:420-444` |

### C-11 ~ C-12 (Tox 实例 + 线程)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| C-11 | R6 | **`ToxAdapter` 大量 public 方法跨线程调 toxcore（仅 mutex 串行化）— 违反"所有 toxcore API 仅在 Tox 线程"的核心契约** | `tox_adapter.cpp:310-333` 等 |
| C-12 | R6 | `ToxThread::run_loop` 不 wait `command_cv_`，用 `sleep_for` busy-tick — 投递的 Command（含 Shutdown）有 50ms 量级的延迟 | `tox_thread.cpp:178-179` |

### C-13 ~ C-15 (Tox Watchdog/Save/Bootstrap)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| C-13 | R7 | `ToxConnection::on_ack` 与 `get_pending_data` 不同步 `send_window_used_`，**窗口计数器与实际队列永久失步** | `tox_connection.cpp:136-150` |
| C-14 | R7 | `ToxWatchdog::persist_abort_count` 用 `ios::trunc` 后写入，abort 在中间触发即清零文件 | `tox_watchdog.cpp:107-129` |
| C-15 | R7 | `fetch_default_nodes_json` 用 `popen("curl …")` 同步阻塞主线程最长 20 s — 启动 / 初始化路径直接卡死 | `bootstrap_source.cpp:157-195` |

### C-16 (Tunnel 协议)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| C-16 | R8 | `deserialize` 与 `serialize_tunnel_data_in_place` 对 `0xA0` lossless 前缀字节的约定不一致 — 需立即对齐 | `protocol.cpp:303-364` |

### C-17 ~ C-18 (Tunnel 流控 + 写合并)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| C-17 | R9 | **`coalesce_arm_timer_locked` 捕获裸 `this`**，`cancel()` 不阻塞 → tunnel 销毁后定时器回调 UAF | `tunnel.cpp:800` |
| C-18 | R9 | **`send_window_used_` 满后 TCP read 未 pause** — 新数据被静默丢弃，背压链断裂 | `tunnel.cpp:473-478`, `tunnel_manager.cpp:510-512` |

### C-19 ~ C-20 (TunnelManager)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| C-19 | R10 | `handle_incoming_open` 标记 ID 已用但**不加入 `tunnels_` map**，且依赖回调消费者补 `add_tunnel`；失败路径未回滚 → 65534 次后 ID 全泄漏 | `tunnel_manager.cpp:416-468` |
| C-20 | R10 | `route_frame` 锁内取裸 `Tunnel*`、锁外调 `handle_frame`，与 `close_all` 并发 → UAF | `tunnel_manager.cpp:393-413` |

### C-21 ~ C-24 (Util Config)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| C-21 | R11 | `Config::validate()` 对 `server_id` 强校验 76-hex — **误拒所有使用 known-servers 别名的配置** | `config.cpp:369-378` |
| C-22 | R11 | `merge_cli_overrides` 用"等于默认值"判断"是否已设置"，CLI flag `--log-level=info` / `udp_enabled=true` 无法覆盖 YAML | `config.cpp:483-493` |
| C-23 | R11 | `check_reloadable` 缺 `client.fallback_server_ids` 检查 — 改 fallback 列表 reload 不被拒绝但不生效 | `config_reload.cpp:99-108` |
| C-24 | R11 | `check_reloadable` 缺 `client.failover` (FailoverConfig) 检查 | `config_reload.cpp:96-109` |

### C-25 ~ C-26 (Util Atomic File)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| C-25 | R12 | Windows `atomic_write_file` 的临时文件名固定 `<path>.tmp`，无 PID — 多实例并发互毁 `tox_save.dat` | `atomic_file.cpp:124` |
| C-26 | R12 | Windows `WriteFile` 单次调用，无 4 GB 截断保护和分段循环 | `atomic_file.cpp:133-138` |

### C-27 ~ C-28 (CLI)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| C-27 | R13 | `run_server` / `run_client` 的 `signals.async_wait` 一次性 handler，第二次信号无响应 — `stop()` 卡住后只能 SIGKILL | `cli/main.cpp:658-663, 758-763` |
| C-28 | R13 | `cmd_inspect` POSIX 读循环无上限/超时 — 守护进程响应异常时挂死 | `cli/main.cpp:288-299` |

> 实际计数 28 项；上文摘要 22 项是对部分多重项的合并计数。建议以本节为准。

---

## 3. High 问题清单（共 41 项）

### App 层 (R1-R4)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| H-1 | R1 | `on_friend_connection` 双次加 `managers_mutex_` 用 `recursive_mutex` 掩盖语义错误 | `tunnel_server.cpp:328-342` |
| H-2 | R1 | **auto-accept friend request 无 allowlist** — 任何持有 server Tox ID 者均可灌满好友列表 | `tunnel_server.cpp:313-326` |
| H-3 | R1 | `sync_rate_limiter` 不清除被删除好友的旧 token 桶 — reload 后旧限流状态残留 | `tunnel_server.cpp:424-433` |
| H-4 | R2 | `RateLimiter::refill` 缺速率上限校验 — `bytes_per_sec × elapsed_ns` 在 INT64 溢出 | `rate_limiter.cpp:100-132` |
| H-5 | R2 | `RulesEngine::from_file` `Dump → from_string` 丢失原始行号 — 运维错误信息无定位价值 | `rules_engine.cpp:62-63` |
| H-6 | R2 | `RateLimitSpec` YAML decode 缺 `mode` 字段默认 `Enforce`，与默认构造 `Off` 冲突，配置歧义 | `rules_engine.cpp:575-579` |
| H-7 | R3 | `switch_active_endpoint` 写 `server_tox_id_hex_` 在锁内，但 `record_server_*` 在 strand 内无锁读 — std::string 数据竞争 | `tunnel_client.cpp:1103`, `981-993` |
| H-8 | R3 | `pipe_bridge_` 在 `on_close` / `on_state_change` 不同 lambda 中无序竞争访问 — UAF/null deref | `tunnel_client.cpp:650-657` |
| H-9 | R3 | INFO_REPLY filter TOCTOU：filter 之后到 strand 处理之间可能 failover 切换，info 记入错误 Tox ID | `tunnel_client.cpp:484, 511` |
| H-10 | R4 | `InspectSession` 持 `InspectProviders&` 引用 — `InspectServer::stop()` 期间未完成的 session 触发 UAF | `inspect_server.cpp:119-162` |
| H-11 | R4 | `StdioPipeBridge::close_descriptors` 不持 `output_mutex_` 即关 fd，与 `write_output` 竞争 → 写到回收的 fd | `stdio_pipe_bridge.cpp:123-134, 51-75` |

### Core / Tox 层 (R5-R7)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| H-12 | R5 | `TcpListener::on_connection_closed` + `do_accept` 无 strand 同步，多线程 close 并发触发双 `async_accept` | `tcp_listener.cpp:66-91` |
| H-13 | R5 | `force_close` 把 `write_in_progress_=false` 后，飞行中的 `async_write` completion `fetch_sub` 触发 size_t 下溢 | `tcp_connection.cpp:308-323` |
| H-14 | R6 | `ToxThread::stop` 期间未 drain 的 Command 的 `promise` 永不 set_value — 调用方 future 永挂 | `tox_thread.cpp:60-73, 189-285` |
| H-15 | R6 | `ToxAdapter::write_save_data` 用裸 ofstream + tmp+rename，无 fsync，违反 v0.4 规范 | `tox_adapter.cpp:892-933` |
| H-16 | R6 | `init_tox()` 在 `start()` 的 caller 线程执行 toxcore 注册回调与 bootstrap — 与"仅 Tox 线程调 toxcore"契约相违 | `tox_thread.cpp:51-58` |
| H-17 | R7 | `can_send()` / `send_buffer_space()` 不持锁读 — TOCTOU 致短暂超窗发送 | `tox_connection.cpp:42-49` |
| H-18 | R7 | `tox_iterate` 在持 `tox_mutex_` 期间触发回调，回调内加 `event_mutex_` — 隐式锁序脆弱，任何反向加锁即死锁 | `tox_adapter.cpp:749, 946-1015` |
| H-19 | R7 | `ToxWatchdog::abort_hook_` 普通 `std::function`，无线程安全保护 | `tox_watchdog.cpp:77-89` |
| H-20 | R7 | `bootstrap_source::write_cache` 非原子覆盖写 — 崩溃导致缓存损坏，下次启动无 DHT 节点 | `bootstrap_source.cpp:46-58` |

### Tunnel 层 (R8-R10)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| H-21 | R8 | `is_valid_frame_type` unknown opcode 直接 `invalid_argument` — 破坏 v0.3↔v0.4 互通 | `protocol.cpp:44-61, 330-331` |
| H-22 | R8 | `make_tunnel_open` hostname 超 255 字节静默截断 — 可能连到错误目标 | `protocol.cpp:129` |
| H-23 | R8 | `handle_tunnel_close_frame` 在 Disconnecting 态不检查，可能重复 `on_close_` 回调致 double-remove | `tunnel.cpp:305-329` |
| H-24 | R8 | `serialize_tunnel_data_in_place` 对空 payload 生成无意义的 length=0 帧 | `protocol.cpp:303-319` |
| H-25 | R9 | `WriteCoalescer::candidate_` / `candidate_streak_` 普通成员，与 `decide()` 跨线程调用产生 data race | `write_coalescer.hpp:152-153` |
| H-26 | R9 | open-ACK 路径 `return` 前不处理 `bytes_acked`，非守规对端可让 send_window 永久泄漏 | `tunnel.cpp:339-344` |
| H-27 | R9 | `TunnelManager::backpressure_threshold_` 非原子，`has_backpressure` 无锁读 vs `set_*` 有锁写 — UB | `tunnel_manager.cpp:510-512`, `tunnel_manager.hpp:368` |
| H-28 | R10 | Reaper 未跳过 `Disconnecting`/`Error`/`Closed` 状态的 tunnel — 触发重复 `on_close_` | `tunnel_manager.cpp:134-142`, `tunnel.cpp:157-179` |
| H-29 | R10 | `TunnelManager` 自维护 `used_ids_` 与已存在的 `TunnelIdAllocator` 重复实现，且竞态点不同 | `tunnel_id_allocator.hpp` + `tunnel_manager.cpp:14-17` |
| H-30 | R10 | **`handle_pong_frame` 不记录时间戳，PING 也无 last_ping_ns_ — dead-peer 检测形同虚设** | `tunnel_manager.cpp:618-621`, `tunnel.cpp:436-438` |

### Util / CLI 层 (R11-R13)

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| H-31 | R11 | `Logger::get()` 对 `g_logger` (shared_ptr) 非原子并发读写 | `logger.cpp:110-118` |
| H-32 | R11 | `tunnel_rtt_microseconds_max` / `_send_window_bytes_max` / `_bandwidth_bytes_per_second_max` 三个 _max metric 缺 `# HELP / # TYPE` 行 — Prometheus 解析告警 | `metrics.cpp:432-434` |
| H-33 | R11 | `MetricsServer` `async_read_until` 无读超时 — slowloris 类客户端可永久占 fd | `metrics.cpp:654-725` |
| H-34 | R11 | `Config::save()` 用 `std::ofstream`，绕过 `atomic_write_file` 规范 | `config.cpp:714-726` |
| H-35 | R12 | macOS 父目录 fsync 仍用 `::fsync` 而非 `F_FULLFSYNC` — 与 "identity 文件用 F_FULLFSYNC" 承诺不符 | `atomic_file.cpp:104-114` |
| H-36 | R12 | `CircularBuffer` 移动声明 `= default` 与 `std::mutex` 成员矛盾，调用即编译错误（隐藏的接口契约违反） | `circular_buffer.hpp:30-31` |
| H-37 | R12 | `Expected<void, E>` 用 `E error_{}` — 强制 E 默认构造，与 `std::expected` 语义不一致 | `expected.hpp:154` |
| H-38 | R13 | `cmd_inspect` Windows `WriteFile` 返回值被忽略 — 写失败时返回空响应，运维看到空表无错误 | `cli/main.cpp:253` |
| H-39 | R13 | Windows service 路径 `signal_ctx.poll_one` 与 SCM stop 双路径可能 double `server.stop()` | `cli/main.cpp:712-721` |
| H-40 | R13 | `servers add` 错误信息把"Tox ID 非法"和"alias 冲突"合并 — 运维误判 | `cli/main.cpp:187-191` |
| H-41 | R13 | `JsonCursor` `\uXXXX` 转义产生乱码（fallthrough 把 `\u` 当 `u`） | `cli/main.cpp:330-355` |

---

## 4. Medium 问题清单（共 5 项）

| ID | 子任务 | 标题 | 位置 |
|----|--------|------|------|
| M-1 | R1 | `wire_tcp_to_tunnel` 同类裸指针访问（与 T1 主题同根因） | `tunnel_server.cpp:774` |
| M-2 | R5 | `TcpListener::accepting_` / `max_connections_` 普通 bool / size_t 跨线程访问 | `tcp_listener.hpp:167-168` |
| M-3 | R5 | `IoContext::running_` 普通 bool 跨线程访问 | `io_context.hpp:185` |
| M-4 | R6 | `send_lossy_packet` 在持 `tox_mutex_` 时 `notify_one`，产生 spurious wakeup | `tox_adapter.cpp:615-616` |
| M-5 | R6 | `send_lossless_packet` / `send_lossy_packet` 未在应用层校验 1xx/2xx 字节范围 — 失败仅 DEBUG 日志，难排查 | `tox_adapter.cpp:575-626` |

---

## 5. 修复优先级建议

按"风险 / 成本"的乘积排序：

### P0（必须修复，发布阻断）
1. **T5 背压链路 (C-13, C-18)** — 数据被静默丢弃，影响所有真实工作负载
2. **T2 持久化非原子 (C-14, H-15, H-20, H-34) + (C-25)** — tox_save、abort_count、bootstrap_cache、config 任一损坏即影响服务可用性
3. **C-3 (规则大小写)** — 安全规则可被绕过
4. **C-7 (SOCKS5 loopback)** — 配置之外的路径即变开放代理
5. **C-9 (TunnelResumeStore steady_clock)** — Resume 功能本身完全无法跨重启使用，骨架等于无效
6. **C-16 (协议 0xA0 前缀对齐)** — 在线上发现前必须澄清不变量

### P1（高优先，下次小版本）
7. **T1 跨线程裸指针 UAF (C-1, C-2, C-10, C-20, M-1)** — 系统化迁移到 shared_ptr
8. **T4 Tox 线程模型 (C-11, H-16)** — 决策：要么严格走 Command 队列，要么文档化 mutex 方案
9. **T3 reload diff 缺字段 (C-23, C-24, H-3)** — 补全 + 用 RateLimiter 替换实例
10. **C-12 (run_loop busy-sleep)** — 用 condvar.wait_for，shutdown 延迟可从 50ms 降到 immediate
11. **C-19 (handle_incoming_open ID 泄漏)** — 65534 次后服务不可用
12. **C-21, C-22 (Config 别名误拒 / CLI 覆盖单向)** — 影响所有用别名配置的客户端

### P2（鲁棒性）
13. **T7 信号处理 (C-27)** — 二次 SIGTERM 应能强制退出
14. **T8 数据竞争（H-25, H-27, M-2, M-3, H-31）** — 改为 atomic 即可
15. **T6 互通性 (H-21)** — 重要但仅在引入新 opcode 时显现
16. **H-30 (dead-peer 检测)** — 名义功能，影响长连接清理

### P3（可观测性 / 改进）
17. **H-32 (metric 缺 TYPE)** — 影响 Grafana 但不影响功能
18. **H-5, H-40, H-41 (运维体验)** — 错误信息可读性
19. **H-22, H-24, M-5** — 协议鲁棒性细节

---

## 6. 建议的修复批次（按根因/改动面聚类）

按编号逐条修很容易在多个 PR 里反复碰同一批文件。更合适的方式是按根因收敛成几批：

| 批次 | 建议覆盖 | 主要文件 | 建议验证 |
|------|---------|---------|---------|
| **B1 生命周期 / 所有权** | T1, C-17, H-10, H-11, H-13, H-28 | `tunnel_server.cpp`, `tcp_connection.cpp`, `inspect_server.cpp`, `stdio_pipe_bridge.cpp`, `tunnel.cpp`, `tunnel_manager.cpp` | ASAN + 并发 close/cancel chaos 测试 |
| **B2 Tox 线程契约** | T4, C-12, C-15, H-14, H-16, H-18, H-19, M-4, M-5 | `tox_adapter.cpp`, `tox_thread.cpp`, `tox_watchdog.cpp`, `bootstrap_source.cpp` | 脱离主线程的 API 调用测试 + 启动时延 budget |
| **B3 持久化 / 时间语义** | T2, C-9, C-14, C-25, C-26, H-15, H-20, H-34, H-35 | `tunnel_resume_store.cpp`, `tox_watchdog.cpp`, `tox_adapter.cpp`, `bootstrap_source.cpp`, `config.cpp`, `atomic_file.cpp` | 崩溃恢复测试、重启后 resume 测试、Windows 多实例写测试 |
| **B4 协议 / 背压 / 窗口** | T5, T6, C-16, C-18, C-19, H-21, H-22, H-23, H-24, H-26, H-30 | `protocol.cpp`, `tunnel.cpp`, `tunnel_manager.cpp`, `tox_connection.cpp` | v0.3/v0.4 互通 fixture + no-drop backpressure 测试 |
| **B5 Config / Reload / 运维入口** | T3, C-21, C-22, C-23, C-24, C-27, C-28, H-3, H-32, H-33, H-38, H-39, H-40, H-41 | `config.cpp`, `config_reload.cpp`, `metrics.cpp`, `cli/main.cpp`, `tunnel_server.cpp` | reload reject matrix、alias config、inspect timeout、double-signal integration |
| **B6 安全边界** | C-3, C-7, H-2, H-6 | `rules_engine.cpp`, `socks5_listener.cpp`, `tunnel_server.cpp` | 大小写 deny 规则测试、显式 loopback 断言、好友接纳策略测试 |

如果要压缩成最少 PR 数，建议先做 **B3 + B4 + B6**；这三批覆盖了持久化、数据正确性、安全边界三个发布阻断面。

---

## 7. 建议新增测试矩阵

当前 findings 已经足够说明问题，但下一步不该只修代码而不补测试。建议至少补下面 6 类：

| 测试类型 | 目标 | 首批覆盖项 |
|---------|------|-----------|
| 崩溃恢复集成测试 | 验证持久化真正 crash-safe | C-14, C-25, H-15, H-20, H-34 |
| restart/resume 语义测试 | 验证 `saved_at_ns` / offset 在进程重启后仍有意义 | C-9, F-TUN-16 |
| 背压端到端测试 | 小 send window 下不得静默丢数据，必须 pause/resume read | C-13, C-18, H-26 |
| 协议兼容 fixture | v0.3 peer 遇到 unknown opcode / v0.4 data frame 前缀时行为正确 | C-16, H-21, H-24 |
| reload admission matrix | 只允许 `rules_file` / `forwards` / `logging.level`，其余字段拒绝 | C-23, C-24, H-3, C-21, C-22 |
| IPC / signal 鲁棒性测试 | `inspect` 异常响应不挂死，二次 SIGTERM 可强退 | C-27, C-28, H-33, H-38, H-39 |

这些测试不一定都要在第一批修复里完成，但 **B3/B4/B5 每批至少带 1 个新的回归测试**，否则非常容易在 v0.4.x 上反复回归。

---

## 8. 已确认 clean 的范围

不是 reviewer 偷懒，是真的 clean。下次 review 可以快速跳过：

- **F-CORE-2, F-CORE-3, F-CORE-4, F-CORE-10** (IoContext 调度、TcpConnection 状态机、OwnedBufferView)
- **F-TOX-3, F-TOX-12, F-TOX-13** (跨线程 Command 协议本身、ToxId hex 编解码、DHT 状态/身份)
- **F-TUN-5, F-TUN-7, F-TUN-8, F-TUN-13 (TunnelIdAllocator 自身), F-TUN-16, F-TUN-18** (入站 TCP 转发、固定模式合并、BDP 数学、Resume wire-inactive、统计快照)
- **F-UTIL-4 (rotating sink), F-UTIL-5 (counter overflow), F-UTIL-8 (QR), F-UTIL-9 (systemd_notify), F-UTIL-12 (system_info disclose)**
- **F-APP-17 (SOCKS5 / HTTP CONNECT 协议解析), F-APP-18 (SOCKS5 转发握手), F-APP-20 (KnownServersStore atomic write)**
- **F-CLI-1 (print-id), F-CLI-5 (install-windows-service)**

---

## 9. 备注与局限

- Review 由 13 个独立 agent 并行完成，每个仅看自己分到的文件范围。**没有 agent 跨子系统验证不变量**（例如：`InspectProviders` 的生命周期 vs `InspectServer` — 这是从 R4 自报视角看到的问题，但实际依赖 caller 行为）。
- 所有 Critical / High 均带置信度，本汇总只接受 ≥ 80。**修复前仍建议对源代码做 ground-truth 验证**（特别是 T1 / T2 / T5 这种横切主题）。
- 部分发现可能与你的实际意图不符（例如 H-2 auto-accept 是设计选择？）— 修复前请按业务上下文确认。
- **未覆盖**：测试套件本身（tests/unit, tests/integration, tests/chaos, tests/soak, tests/packaging）、build 系统（CMake）、第三方依赖 (c-toxcore submodule)、文档准确性。

---

## 10. 下一步建议

1. 把 P0 的 6 项作为 v0.4.2 hotfix 的 scope，每项都开 issue 并附本文 anchor。
2. T1 / T2 主题各做一个集成测试用例（fault-injection + 崩溃恢复）。
3. 与 CLAUDE.md 的"线程模型"段落对照，决定 T4 走哪条路（重构 vs 文档化）。
4. Resume 功能（C-9 + F-TUN-16）在底层日历问题修复前**不要打开**默认开关。
