# ToxTunnel 全量代码 Review 功能清单

**日期**: 2026-05-20
**目标**: 用作全量代码 review 的拆分基线。每条 Feature 是一个可独立 review 的子任务，标注主要实现文件与关联组件，便于后续按 Feature 分派给不同的 reviewer / 子 agent。
**生成方式**: 5 个 Explore agent 并行扫描 5 个分层（App / Core / Tox / Tunnel / Util+CLI）后汇总。

---

## 0. 总览

| 分层 | Feature 数 | 编号前缀 |
|------|-----------|---------|
| Application 层 | 21 | `F-APP-*` |
| Core (TCP I/O) 层 | 10 | `F-CORE-*` |
| Tox 层 | 13 | `F-TOX-*` |
| Tunnel 层 | 18 | `F-TUN-*` |
| Util 层 | 12 | `F-UTIL-*` |
| CLI 入口 | 6 | `F-CLI-*` |
| **合计** | **80** | |

Review 推荐拆分粒度: 每个 reviewer / 子 agent 领 **3-6 个相邻 Feature**（同分层 + 同子系统），便于在单次会话中读完上下文。

### 0.1 本轮 inventory 的覆盖边界

这份 inventory 的目标是给 **src/include/cli 主实现面** 做全量 code review 拆分，不是整个仓库的 release-readiness checklist。

- **已纳入**: `src/`, `include/toxtunnel/`, `cli/main.cpp`
- **显式未纳入**: `tests/unit`, `tests/integration`, `tests/chaos`, `tests/soak`, `tests/packaging`
- **显式未纳入**: `cmake/`, `packaging/`, `third_party/c-toxcore/`, 文档准确性本身
- **补充建议**: 如果下一轮目标从"源代码结构 review"升级到"发版就绪性 review"，建议单独补一份 `F-TEST-*` / `F-BUILD-*` inventory，而不是继续把这些内容塞进现有 80 个 Feature

### 0.2 结合 findings 的高风险 Feature 簇

下面这些 Feature 簇在 [`2026-05-20-code-review-findings.md`](./2026-05-20-code-review-findings.md) 里问题最密集，建议优先阅读：

| Feature 簇 | 先看原因 | 典型问题主题 |
|-----------|---------|-------------|
| `F-APP-1~6` | Server 主路径承载好友事件、规则、限流、隧道路由 | 裸指针 UAF、热重载残留状态、自动接好友边界 |
| `F-APP-10~15` | Client failover / reload / info-discovery 都在这一带汇合 | reload 竞态、主备切换抖动、INFO_REPLY TOCTOU |
| `F-TOX-1~11` | 线程模型、持久化、bootstrap、watchdog 都直接碰核心不变量 | toxcore 线程契约、busy-loop、阻塞启动、非原子持久化 |
| `F-TUN-1~10`, `F-TUN-14~15` | v0.4 的协议、背压、写合并、窗口管理基本都在这里 | 0xA0 前缀约定、send window 失步、timer UAF、ID 泄漏 |
| `F-UTIL-1~7`, `F-UTIL-11`, `F-CLI-3~4`, `F-CLI-6` | 配置入口、原子写、指标/inspect、信号处理是运维面高频入口 | alias 校验误拒、reload diff 漏检、Windows atomic write、inspect/signal 挂死 |

---

## 1. Application 层（src/app/, include/toxtunnel/app/）

### F-APP-1: TunnelServer 初始化与 Tox 集成
- 读取规则文件、初始化 ToxAdapter、配置 DHT 引导，启动 InspectServer
- 主要文件: `src/app/tunnel_server.cpp:36-150`
- 关联组件: ToxAdapter, RulesEngine, IoContext, InspectServer

### F-APP-2: TunnelServer 服务端生命周期管理
- Server 启动、停止、运行状态检查、前期回调连接
- 主要文件: `src/app/tunnel_server.cpp:150-250`
- 关联组件: ToxAdapter, IoContext, TunnelManager

### F-APP-3: TunnelServer 配置热加载
- SIGHUP 触发规则文件重加载，原子交换 RulesEngine，不中断运行
- 主要文件: `src/app/tunnel_server.cpp:75-89`
- 关联组件: RulesEngine, RateLimiter

### F-APP-4: TunnelServer 好友连接生命周期
- 响应好友上线/离线事件，创建/销毁 TunnelManager、自动接受好友请求
- 主要文件: `src/app/tunnel_server.cpp:105-135`
- 关联组件: ToxAdapter, TunnelManager

### F-APP-5: TunnelServer 协议解析与隧道转发
- 处理 TUNNEL_OPEN、TUNNEL_DATA 等协议帧，鉴权、开启 TCP 连接、双向数据流转
- 主要文件: `src/app/tunnel_server.cpp:140-170`
- 关联组件: RulesEngine, TcpConnection, TunnelManager

### F-APP-6: TunnelServer 限流同步
- 将规则引擎的限流配置同步至全局 RateLimiter 单例（每次规则加载/重加载调用）
- 主要文件: `src/app/tunnel_server.cpp:125-128`
- 关联组件: RulesEngine, RateLimiter

### F-APP-7: RulesEngine 规则加载与解析
- 从 YAML 文件/字符串加载好友规则、Target/Source 规范，支持通配符匹配
- 主要文件: `src/app/rules_engine.cpp:55-120`
- 关联组件: YAML-CPP

### F-APP-8: RulesEngine 访问决策引擎
- 评估 TUNNEL_OPEN 请求的允许/拒绝，先检查拒绝规则再检查允许规则，默认拒绝
- 主要文件: `src/app/rules_engine.cpp:150-200`

### F-APP-9: RateLimiter token bucket 限流
- 每好友维护 TUNNEL_OPEN/TUNNEL_DATA 的 token bucket，支持三种模式：Off/Report/Enforce
- 主要文件: `src/app/rate_limiter.cpp:1-100`
- 关联组件: RulesEngine

### F-APP-10: TunnelClient 初始化与 Tox 集成
- 读取客户端配置、初始化 ToxAdapter、将所有服务端（主+备）加为好友、创建 TcpListener
- 主要文件: `src/app/tunnel_client.cpp:36-130`
- 关联组件: ToxAdapter, IoContext, KnownServersStore, TcpListener

### F-APP-11: TunnelClient 主备故障转移状态机
- 周期性检查好友在线/离线时间戳，触发自动切换活跃服务端，清理旧隧道，更新注册表
- 主要文件: `src/app/tunnel_client.cpp:220-250`
- 关联组件: ClientServerEndpoint, KnownServersStore

### F-APP-12: TunnelClient 本地 TCP 监听转发
- 为每个 forward_rule 创建 TcpListener，接受本地连接，开启 Tox 隧道转发到服务端
- 主要文件: `src/app/tunnel_client.cpp:150-180`
- 关联组件: TcpListener, TunnelManager

### F-APP-13: TunnelClient Pipe 模式 (stdio)
- 支持单隧道 stdin/stdout 转发模式，用于代理脚本集成
- 主要文件: `src/app/tunnel_client.cpp:164-170`
- 关联组件: StdioPipeBridge, TunnelManager

### F-APP-14: TunnelClient 配置热加载
- 动态增删 forward_rule，对比当前监听器列表，新增启动新监听、删除停止旧监听
- 主要文件: `src/app/tunnel_client.cpp:120-130`
- 关联组件: TcpListener

### F-APP-15: TunnelClient 服务器信息发现
- 周期性发送 INFO_REQUEST，接收 INFO_REPLY 解析服务端系统信息，更新 KnownServersStore
- 主要文件: `src/app/tunnel_client.cpp:275-310`
- 关联组件: KnownServersStore

### F-APP-16: InspectServer 本地 IPC 协议
- POSIX AF_UNIX socket / Windows 命名管道，单次请求-应答，返回 JSON 隧道/状态快照
- 主要文件: `src/app/inspect_server.cpp:1-150`

### F-APP-17: Socks5Listener SOCKS5/HTTP CONNECT 协议解析
- 嗅探首字节识别协议版本，完整解析 SOCKS5 招呼/请求、HTTP CONNECT 请求头
- 主要文件: `src/app/socks5_listener.cpp:19-120`

### F-APP-18: Socks5Listener 动态目标转发
- 接受 SOCKS5 连接、解析目标主机/端口、转换为 TUNNEL_OPEN 请求、缓存管道字节
- 主要文件: `src/app/socks5_listener.cpp:150-250`
- 关联组件: TunnelClient (via callback)

### F-APP-19: TunnelResumeStore 断线续传状态持久化
- 保存活跃隧道的 tunnel_id/host/port/offsets 到 YAML，支持冷启动恢复、时效检查
- 主要文件: `src/app/tunnel_resume_store.cpp:1-100`

### F-APP-20: KnownServersStore 已知服务器注册表
- 维护客户端连接过的服务器列表（Tox ID、别名、连接时间、传输方式、系统信息）
- 主要文件: `src/app/known_servers.cpp:1-150`

### F-APP-21: StdioPipeBridge 标准输入输出管道转发
- 独立线程读取 stdin，回调驱动上游（隧道），向 stdout 写出隧道接收数据
- 主要文件: `src/app/stdio_pipe_bridge.cpp:1-100`
- 关联组件: TunnelClient

---

## 2. Core 层 — TCP I/O（src/core/, include/toxtunnel/core/）

### F-CORE-1: IoContext 线程池生命周期管理
- 管理 asio worker 线程池的启动、停止、重启和生命周期
- 主要文件: `src/core/io_context.cpp:21-74`
- 关联组件: TcpConnection、TcpListener 的底层执行器

### F-CORE-2: IoContext 定时器与事件调度
- 提供 schedule_after、schedule_at 及 post/dispatch 等异步任务调度接口
- 主要文件: `include/toxtunnel/core/io_context.hpp:107-168`
- 关联组件: 定时重连、速率控制等上层机制

### F-CORE-3: TcpConnection 连接生命周期状态机
- 状态转换 Disconnected → Connecting → Connected → Disconnecting → Disconnected
- 主要文件: `src/core/tcp_connection.cpp:38-67`, `include/toxtunnel/core/tcp_connection.hpp:23-28`

### F-CORE-4: TcpConnection 读循环与数据回调
- 异步读取、read buffer 管理、on_data 回调分发
- 主要文件: `include/toxtunnel/core/tcp_connection.hpp:150` (`do_read()`)
- 关联组件: DataCallback 机制

### F-CORE-5: TcpConnection 写队列与背压控制
- 支持 vector / OwnedBufferView 两种写入路径，write buffer 字节计数与上限检查
- 主要文件: `include/toxtunnel/core/tcp_connection.hpp:152-172`
- 关联组件: OwnedBuffer 零拷贝路径

### F-CORE-6: TcpConnection 优雅关闭与 TCP_NODELAY
- close() 刷新写队列后关闭，force_close() 立即关闭；禁用 Nagle 算法
- 主要文件: `src/core/tcp_connection.cpp:43-54`, `include/toxtunnel/core/tcp_connection.hpp:174-180`
- 关联组件: DisconnectCallback

### F-CORE-7: TcpConnection 跨线程串行化与 Strand
- 通过 `asio::strand` 序列化所有 socket 操作和队列变更，可从任意线程安全调用 write/close
- 主要文件: `include/toxtunnel/core/tcp_connection.hpp:236-239`, `src/core/tcp_connection.cpp:40`
- 关联组件: Tox 线程与 I/O 线程协作

### F-CORE-8: TcpListener Accept 循环与连接计数
- 异步 accept 循环、connection count 原子变量的递增/递减、do_accept() 重新投递
- 主要文件: `src/core/tcp_listener.cpp:32-43, 66-80`
- 关联组件: AcceptHandler

### F-CORE-9: TcpListener 连接数限制与背压
- 达 max_connections 时暂停 accept；on_connection_closed() 递减并恢复
- 主要文件: `include/toxtunnel/core/tcp_listener.hpp:114-118`, `src/core/tcp_listener.cpp:66-80`

### F-CORE-10: OwnedBufferView 零拷贝缓冲管理
- 基于 shared_ptr 的引用计数缓冲视图，支持偏移和长度窗口，供 inbound TUNNEL_DATA 路径使用
- 主要文件: `include/toxtunnel/core/owned_buffer.hpp:30-73`
- 关联组件: TcpConnection write() 零拷贝重载

---

## 3. Tox 层（src/tox/, include/toxtunnel/tox/）

### F-TOX-1: Tox 实例生命周期管理
- 初始化、启动、停止 Tox 实例；加载/创建身份
- 主要文件: `src/tox/tox_adapter.cpp:232-269`, `src/tox/tox_save.cpp:73-91`
- 关联组件: ToxDeleter, ToxPtr, ToxAdapterConfig

### F-TOX-2: 专用线程事件循环
- tox_iterate() 循环，tox_iterate_interval 动态控制，条件变量驱动唤醒
- 主要文件: `src/tox/tox_adapter.cpp:742`, `src/tox/tox_thread.cpp`
- 关联组件: ToxThread, run_loop, condition_variable

### F-TOX-3: 跨线程任务投递
- 其他线程通过 Command 队列投递任务，Tox 线程执行后通过 promise 返回结果
- 主要文件: `include/toxtunnel/tox/tox_thread.hpp:33-49`, `src/tox/tox_thread.cpp`
- 关联组件: Command, EventQueue, promise/future

### F-TOX-4: 朋友管理（添加/移除/查询）
- add_friend, remove_friend, get_friend_list, friend_by_public_key 等
- 主要文件: `src/tox/tox_adapter.cpp:272-306`
- 关联组件: FriendInfo, FriendState

### F-TOX-5: 朋友连接状态追踪
- 监听 friend_connection_status 变化，缓存连接状态
- 主要文件: `src/tox/tox_adapter.cpp:463-505`, `include/toxtunnel/tox/types.hpp:133-144`
- 关联组件: FriendState, FriendConnectionCallback

### F-TOX-6: 自定义包收发（lossless/lossy）
- send_lossless_packet, send_lossy_packet，包头字节范围校验
- 主要文件: `src/tox/tox_adapter.cpp:575-631`
- 关联组件: Tox 协议 1xx/2xx 包号范围

### F-TOX-7: ToxConnection 流控与缓冲
- 双向缓冲、发送窗口、背压信号、on_ack 释放空间
- 主要文件: `src/tox/tox_connection.cpp`, `include/toxtunnel/tox/tox_connection.hpp:38-253`
- 关联组件: ToxConnection::State, send_window_size, can_send()

### F-TOX-8: 回调机制与事件分发
- 6 种回调：friend_request, friend_connection, lossless_packet, lossy_packet, message, self_connection
- 主要文件: `src/tox/tox_adapter.cpp:676-701, 784-831`
- 关联组件: 事件队列, dispatch_pending_events()

### F-TOX-9: Tox 线程心跳与 Watchdog
- Tox 线程每次 tox_iterate 返回调用 heartbeat()，watchdog 检测超时 abort()
- 主要文件: `src/tox/tox_watchdog.cpp:69-100`, `include/toxtunnel/tox/tox_adapter.hpp:219-221`
- 关联组件: ToxWatchdog, heartbeat_counter_, deadline_seconds_

### F-TOX-10: 持久化保存与恢复
- tox_get_savedata() 序列化，原子写入（临时文件+rename）防止损坏
- 主要文件: `src/tox/tox_save.cpp:47-92`, `src/tox/tox_adapter.cpp:376, 722`
- 关联组件: save_tox_data(), create_or_load_tox()

### F-TOX-11: Bootstrap 节点解析与自动发现
- 解析 JSON/配置，支持 Auto/LAN 模式，缓存与 HTTP 拉取
- 主要文件: `src/tox/bootstrap_source.cpp`, `src/tox/tox_adapter.cpp:284-341`
- 关联组件: BootstrapMode, BootstrapSource, parse_nodes_json()

### F-TOX-12: Tox ID 与公钥解析/编码
- hex ↔ bytes 双向转换，checksum 验证，nospam 管理
- 主要文件: `src/tox/types.cpp`, `src/tox/tox_adapter.cpp:380-385, 252-257`
- 关联组件: ToxId, PublicKeyArray, hex_to_bytes()

### F-TOX-13: DHT 连接状态与身份管理
- 获取 self_connection_status，get_address/get_public_key，set_nospam
- 主要文件: `src/tox/tox_adapter.cpp:710-725, 252-263`
- 关联组件: is_connected(), SelfConnectionCallback

---

## 4. Tunnel 层（src/tunnel/, include/toxtunnel/tunnel/）

### F-TUN-1: 协议帧序列化与反序列化
- 将 5 字节帧头 + 变长 payload 与网络字节序相互转换
- 主要文件: `src/tunnel/protocol.cpp`
- 关联组件: ProtocolFrame

### F-TUN-2: TUNNEL_OPEN 握手协议
- 目标地址编码、OPEN 帧创建、远端应答处理
- 主要文件: `src/tunnel/tunnel.cpp` (`handle_tunnel_open_frame()`)
- 关联组件: TunnelImpl, TunnelOpenPayload

### F-TUN-3: TUNNEL_CLOSE 优雅关闭
- 状态转移、缓冲区刷新、对端通知
- 主要文件: `src/tunnel/tunnel.cpp` (`close()`, `handle_tunnel_close_frame()`)
- 关联组件: TunnelImpl

### F-TUN-4: TUNNEL_DATA 出站零拷贝路径
- OwnedFrameBuffer 在位序列化、无额外 memcpy、共享指针生命周期管理
- 主要文件: `src/tunnel/tunnel.cpp` (`send_data_to_tox()`), `src/tunnel/protocol.cpp` (`serialize_tunnel_data_in_place()`)
- 关联组件: OwnedFrameBuffer, SendOwnedToToxCallback

### F-TUN-5: TUNNEL_DATA 入站处理与 TCP 转发
- 接收帧、反序列化 payload、零拷贝转发 TCP
- 主要文件: `src/tunnel/tunnel.cpp` (`handle_tunnel_data_frame()`, `on_tcp_data_received()`)
- 关联组件: TunnelImpl, ProtocolFrame::as_tunnel_data_owned()

### F-TUN-6: WriteCoalescer 自适应合并策略
- 固定/自适应/绕过三种模式、EWMA 平均写大小与间隔、四次滞后转换
- 主要文件: `src/tunnel/write_coalescer.cpp`
- 关联组件: WriteCoalescer, CoalesceMode, CoalescePolicy

### F-TUN-7: 固定模式写合并（Batch/Drain/Bypass）
- coalesce_buf_ 缓冲、定时器驱动、每帧最大字节数限制
- 主要文件: `src/tunnel/tunnel.cpp` (`coalesce_append_locked()`, `coalesce_emit_front_locked()`)
- 关联组件: TunnelImpl.coalesce_*

### F-TUN-8: BDP 流控窗口动态调整
- RTT/带宽 EWMA、BDP = RTT × BW、窗口 [64KiB, 4MiB] 自适应
- 主要文件: `src/tunnel/bdp_flow_control.cpp` (`observe_rtt_us()`, `observe_bandwidth_bps()`)
- 关联组件: BdpFlowControl, FlowControlMode::Bdp

### F-TUN-9: TUNNEL_ACK 流控反馈与接收窗口
- ACK 帧生成、阈值驱动（默认 16KiB）、字节计数
- 主要文件: `src/tunnel/tunnel.cpp` (`maybe_send_ack()`, `handle_tunnel_ack_frame()`)
- 关联组件: TunnelImpl.ack_threshold_, TunnelAckPayload

### F-TUN-10: 发送窗口与背压控制
- send_window_used_ 原子跟踪、TunnelManager 总和聚合、64KiB 背压阈值
- 主要文件: `src/tunnel/tunnel.cpp`, `src/tunnel/tunnel_manager.cpp` (`total_buffer_level()`)
- 关联组件: TunnelImpl, TunnelManager

### F-TUN-11: Keep-Alive PING/PONG
- 定期心跳、无实际 payload、TunnelManager 级统一处理
- 主要文件: `src/tunnel/tunnel.cpp` (`handle_ping_frame()`, `handle_pong_frame()`)
- 关联组件: TunnelManager

### F-TUN-12: 隧道生命周期状态机
- None → Connecting → Connected → Disconnecting → Closed/Error 转移、回调触发
- 主要文件: `src/tunnel/tunnel.cpp` (`transition_state()`, `set_state()`)
- 关联组件: Tunnel::State enum

### F-TUN-13: TunnelManager ID 分配与回收
- 1-65535 范围游标式分配，位集追踪占用，O(1) 平均
- 主要文件: `include/toxtunnel/tunnel/tunnel_id_allocator.hpp`, `src/tunnel/tunnel_manager.cpp` (`allocate_tunnel_id()`)
- 关联组件: TunnelIdAllocator

### F-TUN-14: TunnelManager 索引与路由
- 按 tunnel_id 存储 shared_ptr 映射、frame 路由、快速查询
- 主要文件: `src/tunnel/tunnel_manager.cpp` (`route_frame()`, `get_tunnel()`)
- 关联组件: TunnelManager.tunnels_

### F-TUN-15: 闲置隧道回收 (Reaper)
- 周期扫描、TUNNEL_DATA 活动时间戳检查、可配阈值与 tick 周期
- 主要文件: `src/tunnel/tunnel_manager.cpp` (`reap_idle_tunnels_once()`, `schedule_reaper_tick()`)
- 关联组件: TunnelManager.reaper_*

### F-TUN-16: 隧道续传协议支持 (Resume, 部分实现)
- TUNNEL_RESUME_REQUEST/ACK 帧定义、状态码、偏移量编码（wire-inactive 默认）
- 主要文件: `src/tunnel/protocol.cpp`, `include/toxtunnel/tunnel/protocol.hpp` (`TUNNEL_RESUME_*`)
- 关联组件: TunnelResumeRequestPayload, TunnelResumeAckPayload
- 参考: `docs/plans/2026-05-15-tunnel-resume-protocol-partial.md`

### F-TUN-17: 错误处理与诊断
- TUNNEL_ERROR 帧、错误代码 + 描述、状态转移
- 主要文件: `src/tunnel/tunnel.cpp` (`send_error()`, `handle_tunnel_error_frame()`)
- 关联组件: TunnelErrorPayload

### F-TUN-18: 统计计数与快照
- 字节/帧计数、TunnelSnapshot、线程安全读取
- 主要文件: `src/tunnel/tunnel_manager.cpp` (`snapshot()`, `record_bytes_*()`, `record_frame_*()`)
- 关联组件: ManagerSnapshot, TunnelSnapshot

---

## 5. Util 层（src/util/, include/toxtunnel/util/）

### F-UTIL-1: YAML 配置加载与验证
- 从 YAML 文件或字符串加载、反序列化、验证完整配置
- 主要文件: `src/util/config.cpp`, `include/toxtunnel/util/config.hpp:320-356`
- 关联组件: 25 个 `convert<T>` 特化, ConfigError

### F-UTIL-2: CLI 参数覆盖与配置合并
- 将 CLI flag (--mode, --port, --server-id 等) 与 YAML 配置合并
- 主要文件: `include/toxtunnel/util/config.hpp:344-346`, `cli/main.cpp:1119-1204`
- 关联组件: Config::merge_cli_overrides

### F-UTIL-3: 配置热重载差分校验
- 校验新配置仅在允许字段变化（rules_file/forwards/log_level）
- 主要文件: `include/toxtunnel/util/config_reload.hpp:30-55`, `src/util/config_reload.cpp`
- 关联组件: ForwardDiff, diff_forwards

### F-UTIL-4: 日志初始化与文件轮转
- spdlog 控制台/文件日志，可配级别 + pattern + 5MiB/3file 轮转
- 主要文件: `include/toxtunnel/util/logger.hpp:44-70`, `src/util/logger.cpp`
- 关联组件: LogLevel, Logger

### F-UTIL-5: MetricsRegistry 原子计数器
- 线程安全 Prometheus 指标：tunnels_active/opened/closed, bytes_in/out, iterate_lag summary, BDP 窗口, 速率限制, watchdog abort 计数等
- 主要文件: `include/toxtunnel/util/metrics.hpp:31-252`, `src/util/metrics.cpp`
- 关联组件: 无锁 atomic<T>, Role/OpenResult/CloseReason 标签

### F-UTIL-6: MetricsServer HTTP 路由
- 单连接 /metrics GET，其他路径 404，Prometheus text format 0.0.4
- 主要文件: `include/toxtunnel/util/metrics.hpp:269-309`, `src/util/metrics.cpp`
- 关联组件: asio acceptor, render(), parse_listen_spec()

### F-UTIL-7: 原子文件写（多平台 fsync）
- write → temp → fsync → rename → fsync_parent；macOS F_FULLFSYNC；Windows MOVEFILE_WRITE_THROUGH
- 主要文件: `include/toxtunnel/util/atomic_file.hpp:19-52`, `src/util/atomic_file.cpp`
- 关联组件: AtomicFileOptions, Expected<void, string>

### F-UTIL-8: QR 码终端渲染
- Nayuki 算法 Unicode 块符 / ANSI 彩色输出
- 主要文件: `include/toxtunnel/util/qr_code.hpp:11-12`, `src/util/qr_code.cpp`
- 关联组件: generate_qr_terminal()

### F-UTIL-9: systemd 服务通知
- notify_service_ready / notify_service_stopping（Linux only）
- 主要文件: `include/toxtunnel/util/systemd_notify.hpp:5-6`, `src/util/systemd_notify.cpp`

### F-UTIL-10: Windows 服务与 reload 命名管道
- install_windows_service、named pipe（reload + inspect IPC）、SCM 集成、is_windows_service_stopping 轮询
- 主要文件: `include/toxtunnel/util/windows_service.hpp:8-43`, `src/util/windows_service.cpp`, `cli/main.cpp:558-626`
- 关联组件: WindowsReloadPipeServer

### F-UTIL-11: CircularBuffer / Expected / Error 基础抽象
- 线程安全固定容量环形缓冲（覆盖最旧）；Expected<T,E> tag-based error；ToxError/TunnelError/NetworkError 错误码
- 主要文件: `include/toxtunnel/util/circular_buffer.hpp:18-80`, `include/toxtunnel/util/expected.hpp`, `include/toxtunnel/util/error.hpp`
- 关联组件: unexpected<E>, std::variant<ValueHolder, ErrorHolder>

### F-UTIL-12: 系统信息收集与序列化
- gather_system_info() 按 ServerInfoDisclose 策略采集 hostname/os/arch/uptime/version；YAML ↔ 二进制序列化
- 主要文件: `include/toxtunnel/util/system_info.hpp:24-38`, `src/util/system_info.cpp`
- 关联组件: SystemInfoSnapshot

---

## 6. CLI 入口（cli/main.cpp）

### F-CLI-1: print-id 子命令（QR + 文本）
- 加载或创建本地 Tox 身份、--qr/--color 输出，可选数据目录
- 主要文件: `cli/main.cpp:856-1086`
- 关联组件: ToxAdapter::get_tox_id_only, generate_qr_terminal

### F-CLI-2: servers 子命令组（list/show/add/remove）
- 管理 known_servers.yaml（别名↔Tox ID）、原子写 + 加载错误容忍；数据目录三阶段解析
- 主要文件: `cli/main.cpp:107-213, 866-912, 1011-1032`
- 关联组件: KnownServersStore, resolved_tox_id 别名查询

### F-CLI-3: inspect 子命令（守护进程 IPC）
- Unix socket / Windows named pipe；GET /tunnels、GET /status；手写 JSON walker 表格渲染
- 主要文件: `cli/main.cpp:223-462, 918-932, 1035-1042`
- 关联组件: inspect_send_request, render_tunnels_table, JsonCursor

### F-CLI-4: reload 子命令（热重载触发）
- POSIX 输出 kill -HUP 提示；Windows 写 "RELOAD\n" 到 named pipe
- 主要文件: `cli/main.cpp:476-509, 939-946, 1045-1050`
- 关联组件: WindowsReloadPipeServer

### F-CLI-5: install-windows-service（仅 Windows）
- register_packaged_toxtunnel_service() 在 SCM 中注册服务
- 主要文件: `cli/main.cpp:948-1008`
- 关联组件: util::register_packaged_toxtunnel_service

### F-CLI-6: 主循环与 SIGHUP / reload 处理
- run_server / run_client：asio signal_set（POSIX SIGHUP）或 Windows named pipe reload
- 热重载校验 + server/client.reload() 应用
- 主要文件: `cli/main.cpp:630-830`
- 关联组件: reload_config_from_disk, check_reloadable

---

## 7. 跨切关注点（Review 时应额外注意）

这些不是"功能"而是横切维度，建议每个 Feature review 时都对照检查：

| 维度 | 关注点 |
|------|--------|
| **线程模型** | Tox 线程独占 toxcore API；strand 序列化跨线程操作；watchdog abort 路径不能阻塞 |
| **并发与原子性** | atomic 计数器、shared_ptr 生命周期、回调期间的对象销毁、ABA |
| **零拷贝路径** | OwnedFrameBuffer / OwnedBufferView 是否真的避免了 memcpy；序列化在位是否覆盖窗口 |
| **背压链** | TCP read → Tunnel send window → Tox lossless queue → BDP 窗口 → ACK 反馈，链路是否完整 |
| **配置热重载** | reload 仅 rules/forwards/log_level；其他字段变化必须拒绝；reload 失败必须回滚 |
| **持久化原子性** | tox_save.dat、known_servers.yaml 是否走 atomic_write_file；macOS F_FULLFSYNC |
| **网络协议** | 帧头边界、长度字段验证、unknown opcode 容忍（v0.3 ↔ v0.4 互通） |
| **错误传播** | TUNNEL_ERROR 帧 vs 静默关闭；rules deny vs rate_limit enforce 的可观测性 |
| **资源耗尽** | tunnel_id 全占满、coalesce 缓冲爆、accept 队列满、watchdog 触发后状态 |

---

## 8. 建议的 review 子任务分派

按 Feature 编号区间将工作拆分给独立 reviewer / agent：

| 子任务 | Feature 区间 | 主题 | 估算工作量 |
|-------|------------|------|----------|
| R1 | F-APP-1~6 | Server 主流程 + 热重载 | 中 |
| R2 | F-APP-7~9 | 规则引擎 + 限流 | 小 |
| R3 | F-APP-10~15 | Client 主备故障转移 + 信息发现 | 大 |
| R4 | F-APP-16~21 | Inspect / SOCKS5 / Resume / KnownServers / Pipe | 中 |
| R5 | F-CORE-1~10 | TCP I/O 全套 | 中 |
| R6 | F-TOX-1~6 | Tox 实例、线程、好友、自定义包 | 中 |
| R7 | F-TOX-7~13 | ToxConnection、watchdog、持久化、bootstrap、身份 | 中 |
| R8 | F-TUN-1~5 | 协议帧 + 零拷贝 + OPEN/CLOSE/DATA | 大 |
| R9 | F-TUN-6~10 | 写合并 + BDP + ACK + 背压 | 大 |
| R10 | F-TUN-11~18 | 生命周期 + 索引 + 回收 + Resume + 错误 + 统计 | 中 |
| R11 | F-UTIL-1~6 | 配置 + 日志 + 指标 | 中 |
| R12 | F-UTIL-7~12 | 原子写 + QR + systemd + Windows + 基础抽象 + 系统信息 | 中 |
| R13 | F-CLI-1~6 | CLI 子命令 + 主循环 | 小 |

**建议**: 先跑 R8 / R9 / R11（核心性能路径 + 配置入口），其他可以并行。
