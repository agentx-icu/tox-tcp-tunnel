#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

#include "toxtunnel/util/config.hpp"

using namespace toxtunnel;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

class ConfigTest : public ::testing::Test {
   protected:
    void SetUp() override {
        const auto unique_suffix =
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
            std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
        test_dir_ =
            std::filesystem::temp_directory_path() / ("toxtunnel_config_test_" + unique_suffix);
        std::filesystem::create_directories(test_dir_);
    }

    void TearDown() override {
        // Clean up temp files
        if (std::filesystem::exists(test_dir_)) {
            std::filesystem::remove_all(test_dir_);
        }
    }

    std::filesystem::path test_dir_;
    std::filesystem::path test_file_;

    void write_test_file(const std::string& content) {
        test_file_ = test_dir_ / "test_config.yaml";
        std::ofstream ofs(test_file_);
        ofs << content;
    }
};

// ---------------------------------------------------------------------------
// YAML Parsing Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, ParseMinimalServerConfig) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& config = result.value();
    EXPECT_EQ(config.mode, Mode::Server);
    EXPECT_EQ(config.data_dir, "/var/lib/toxtunnel");
    EXPECT_TRUE(config.server.has_value());
    // Absent `service:` keeps ServiceConfig defaults: auto_start=true (server is online by
    // default), allow_client_daemon=false. This guarantees existing server YAML configs
    // without a `service:` section keep being daemonized after upgrade.
    EXPECT_TRUE(config.service.auto_start);
    EXPECT_FALSE(config.service.allow_client_daemon);
}

TEST_F(ConfigTest, ParseMinimalClientConfig) {
    const char* yaml = R"(
mode: client
data_dir: ~/.config/toxtunnel
server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& config = result.value();
    EXPECT_EQ(config.mode, Mode::Client);
    EXPECT_TRUE(config.client.has_value());
    EXPECT_EQ(config.client->server_id,
              "0000000000000000000000000000000000000000000000000000000000000000000000000000");
    // Absent `service:` keeps ServiceConfig defaults; allow_client_daemon=false means a
    // packaged client install never auto-binds local forward ports.
    EXPECT_FALSE(config.service.allow_client_daemon);
    EXPECT_FALSE(config.should_run_as_service_daemon());
}

TEST_F(ConfigTest, ParseFullServerConfig) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
tcp_port: 33445
udp_enabled: true
bootstrap_nodes:
  - address: bootstrap.tox.me
    port: 33445
    public_key: 0000000000000000000000000000000000000000000000000000000000000000
rules_file: /etc/toxtunnel/rules.conf
logging:
  level: info
  file: /var/log/toxtunnel.log
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& config = result.value();
    EXPECT_EQ(config.mode, Mode::Server);
    EXPECT_EQ(config.data_dir, "/var/lib/toxtunnel");
    ASSERT_TRUE(config.server.has_value());
    EXPECT_EQ(config.server->tcp_port, 33445);
    EXPECT_TRUE(config.server->udp_enabled);
    ASSERT_EQ(config.server->bootstrap_nodes.size(), 1);
    EXPECT_EQ(config.server->bootstrap_nodes[0].address, "bootstrap.tox.me");
    EXPECT_EQ(config.server->bootstrap_nodes[0].port, 33445);
    EXPECT_EQ(config.server->bootstrap_nodes[0].public_key,
              "0000000000000000000000000000000000000000000000000000000000000000");
    ASSERT_TRUE(config.server->rules_file.has_value());
    EXPECT_EQ(*config.server->rules_file, "/etc/toxtunnel/rules.conf");
    EXPECT_EQ(config.logging.level, util::LogLevel::Info);
    ASSERT_TRUE(config.logging.file.has_value());
    EXPECT_EQ(*config.logging.file, "/var/log/toxtunnel.log");
}

TEST_F(ConfigTest, ParseNestedServerConfig) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
logging:
  level: info
server:
  tcp_port: 33445
  udp_enabled: true
  bootstrap_nodes:
    - address: bootstrap.tox.me
      port: 33445
      public_key: 0000000000000000000000000000000000000000000000000000000000000000
  rules_file: /etc/toxtunnel/rules.conf
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& config = result.value();
    ASSERT_TRUE(config.server.has_value());
    EXPECT_EQ(config.server->tcp_port, 33445);
    EXPECT_TRUE(config.server->udp_enabled);
    ASSERT_EQ(config.server->bootstrap_nodes.size(), 1);
    EXPECT_EQ(config.server->bootstrap_nodes[0].address, "bootstrap.tox.me");
    ASSERT_TRUE(config.server->rules_file.has_value());
    EXPECT_EQ(*config.server->rules_file, "/etc/toxtunnel/rules.conf");
}

TEST_F(ConfigTest, ParseFullClientConfig) {
    const char* yaml = R"(
mode: client
data_dir: ~/.config/toxtunnel
server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
forwards:
  - local_port: 2222
    remote_host: localhost
    remote_port: 22
  - local_port: 8080
    remote_host: 192.168.1.100
    remote_port: 80
logging:
  level: debug
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& config = result.value();
    EXPECT_EQ(config.mode, Mode::Client);
    ASSERT_TRUE(config.client.has_value());
    EXPECT_EQ(config.client->server_id,
              "0000000000000000000000000000000000000000000000000000000000000000000000000000");
    ASSERT_EQ(config.client->forwards.size(), 2);

    EXPECT_EQ(config.client->forwards[0].local_port, 2222);
    EXPECT_EQ(config.client->forwards[0].remote_host, "localhost");
    EXPECT_EQ(config.client->forwards[0].remote_port, 22);

    EXPECT_EQ(config.client->forwards[1].local_port, 8080);
    EXPECT_EQ(config.client->forwards[1].remote_host, "192.168.1.100");
    EXPECT_EQ(config.client->forwards[1].remote_port, 80);

    EXPECT_EQ(config.logging.level, util::LogLevel::Debug);
}

TEST_F(ConfigTest, ParseNestedClientConfig) {
    const char* yaml = R"(
mode: client
data_dir: ~/.config/toxtunnel
logging:
  level: debug
client:
  server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
  forwards:
    - local_port: 2222
      remote_host: localhost
      remote_port: 22
    - local_port: 8080
      remote_host: 192.168.1.100
      remote_port: 80
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& config = result.value();
    ASSERT_TRUE(config.client.has_value());
    EXPECT_EQ(config.client->server_id,
              "0000000000000000000000000000000000000000000000000000000000000000000000000000");
    ASSERT_EQ(config.client->forwards.size(), 2);
    EXPECT_EQ(config.client->forwards[0].local_port, 2222);
    EXPECT_EQ(config.client->forwards[1].remote_port, 80);
    EXPECT_EQ(config.logging.level, util::LogLevel::Debug);
}

TEST_F(ConfigTest, ParseInvalidYaml) {
    const char* yaml = R"(
mode: server
  invalid indentation
)";

    auto result = Config::from_string(yaml);
    EXPECT_FALSE(result.has_value());
}

TEST_F(ConfigTest, ParseInvalidMode) {
    const char* yaml = R"(
mode: invalid
data_dir: /var/lib/toxtunnel
)";

    auto result = Config::from_string(yaml);
    EXPECT_FALSE(result.has_value());
}

TEST_F(ConfigTest, ParseMissingMode) {
    const char* yaml = R"(
data_dir: /var/lib/toxtunnel
)";

    auto result = Config::from_string(yaml);
    EXPECT_FALSE(result.has_value());
}

// ---------------------------------------------------------------------------
// Log Level Parsing Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, ParseLogLevelTrace) {
    auto result = Config::from_string("mode: server\nlogging:\n  level: trace");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().logging.level, util::LogLevel::Trace);
}

TEST_F(ConfigTest, ParseLogLevelDebug) {
    auto result = Config::from_string("mode: server\nlogging:\n  level: debug");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().logging.level, util::LogLevel::Debug);
}

TEST_F(ConfigTest, ParseLogLevelInfo) {
    auto result = Config::from_string("mode: server\nlogging:\n  level: info");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().logging.level, util::LogLevel::Info);
}

TEST_F(ConfigTest, ParseLogLevelWarn) {
    auto result = Config::from_string("mode: server\nlogging:\n  level: warn");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().logging.level, util::LogLevel::Warn);
}

TEST_F(ConfigTest, ParseLogLevelWarning) {
    auto result = Config::from_string("mode: server\nlogging:\n  level: warning");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().logging.level, util::LogLevel::Warn);
}

TEST_F(ConfigTest, ParseLogLevelError) {
    auto result = Config::from_string("mode: server\nlogging:\n  level: error");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().logging.level, util::LogLevel::Error);
}

TEST_F(ConfigTest, ParseLogLevelCritical) {
    auto result = Config::from_string("mode: server\nlogging:\n  level: critical");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().logging.level, util::LogLevel::Critical);
}

TEST_F(ConfigTest, ParseLogLevelCaseInsensitive) {
    auto result = Config::from_string("mode: server\nlogging:\n  level: DEBUG");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().logging.level, util::LogLevel::Debug);
}

// ---------------------------------------------------------------------------
// Validation Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, ValidateValidServerConfig) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
tcp_port: 33445
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value());

    auto validation = result.value().validate();
    EXPECT_TRUE(validation.has_value()) << validation.error();
}

TEST_F(ConfigTest, ValidateValidClientConfig) {
    const char* yaml = R"(
mode: client
data_dir: ~/.config/toxtunnel
server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
forwards:
  - local_port: 2222
    remote_host: localhost
    remote_port: 22
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value());

    auto validation = result.value().validate();
    EXPECT_TRUE(validation.has_value()) << validation.error();
}

TEST_F(ConfigTest, ValidateClientMissingServerId) {
    const char* yaml = R"(
mode: client
data_dir: ~/.config/toxtunnel
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value());

    auto validation = result.value().validate();
    EXPECT_FALSE(validation.has_value());
}

TEST_F(ConfigTest, ValidateClientInvalidServerIdLength) {
    const char* yaml = R"(
mode: client
data_dir: ~/.config/toxtunnel
server_id: tooshort
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value());

    auto validation = result.value().validate();
    EXPECT_FALSE(validation.has_value());
}

TEST_F(ConfigTest, ValidateForwardRuleMissingRemoteHost) {
    const char* yaml = R"(
mode: client
data_dir: ~/.config/toxtunnel
server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
forwards:
  - local_port: 2222
    remote_port: 22
)";

    // This should fail YAML parsing since remote_host is required
    auto result = Config::from_string(yaml);
    EXPECT_FALSE(result.has_value());
}

TEST_F(ConfigTest, ValidateBootstrapNodeInvalidPublicKey) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
bootstrap_nodes:
  - address: bootstrap.tox.me
    port: 33445
    public_key: invalid
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value());

    auto validation = result.value().validate();
    EXPECT_FALSE(validation.has_value());
}

// ---------------------------------------------------------------------------
// File I/O Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, LoadFromFile) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
tcp_port: 33445
)";
    write_test_file(yaml);

    auto result = Config::from_file(test_file_);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_EQ(result.value().mode, Mode::Server);
    EXPECT_EQ(result.value().server->tcp_port, 33445);
}

TEST_F(ConfigTest, LoadFromNonexistentFile) {
    auto result = Config::from_file("/nonexistent/path/config.yaml");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ConfigTest, SaveConfig) {
    Config config = Config::default_server();
    config.data_dir = "/test/path";
    config.server->tcp_port = 12345;

    auto save_path = test_dir_ / "save_test.yaml";
    auto save_result = config.save(save_path);
    ASSERT_TRUE(save_result.has_value()) << save_result.error();

    // Load it back
    auto load_result = Config::from_file(save_path);
    ASSERT_TRUE(load_result.has_value()) << load_result.error();

    const auto& loaded = load_result.value();
    EXPECT_EQ(loaded.mode, Mode::Server);
    EXPECT_EQ(loaded.data_dir, "/test/path");
    EXPECT_EQ(loaded.server->tcp_port, 12345);
}

// ---------------------------------------------------------------------------
// Default Config Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, DefaultServerConfig) {
    auto config = Config::default_server();
    EXPECT_EQ(config.mode, Mode::Server);
    EXPECT_TRUE(config.server.has_value());
    EXPECT_FALSE(config.client.has_value());
    EXPECT_TRUE(config.service.auto_start);
    EXPECT_FALSE(config.service.allow_client_daemon);
}

TEST_F(ConfigTest, DefaultClientConfig) {
    auto config = Config::default_client();
    EXPECT_EQ(config.mode, Mode::Client);
    EXPECT_TRUE(config.client.has_value());
    EXPECT_FALSE(config.server.has_value());
    EXPECT_FALSE(config.service.auto_start);
    EXPECT_FALSE(config.service.allow_client_daemon);
}

// ---------------------------------------------------------------------------
// Mode Helper Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, IsServerMode) {
    auto config = Config::default_server();
    EXPECT_TRUE(config.is_server());
    EXPECT_FALSE(config.is_client());
}

TEST_F(ConfigTest, IsClientMode) {
    auto config = Config::default_client();
    EXPECT_TRUE(config.is_client());
    EXPECT_FALSE(config.is_server());
}

TEST_F(ConfigTest, ServerConfigAccessor) {
    auto config = Config::default_server();
    EXPECT_NO_THROW((void)config.server_config());
}

TEST_F(ConfigTest, ClientConfigAccessor) {
    auto config = Config::default_client();
    EXPECT_NO_THROW((void)config.client_config());
}

TEST_F(ConfigTest, ServerConfigAccessorThrowsInClientMode) {
    auto config = Config::default_client();
    EXPECT_THROW((void)config.server_config(), std::runtime_error);
}

TEST_F(ConfigTest, ClientConfigAccessorThrowsInServerMode) {
    auto config = Config::default_server();
    EXPECT_THROW((void)config.client_config(), std::runtime_error);
}

// ---------------------------------------------------------------------------
// YAML Serialization Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, ToYamlServer) {
    Config config = Config::default_server();
    config.data_dir = "/test/path";
    config.server->tcp_port = 12345;
    config.server->udp_enabled = false;
    config.logging.level = util::LogLevel::Debug;

    std::string yaml = config.to_yaml();
    EXPECT_TRUE(yaml.find("mode: server") != std::string::npos);
    EXPECT_TRUE(yaml.find("data_dir: /test/path") != std::string::npos);
    EXPECT_TRUE(yaml.find("server:") != std::string::npos);
    EXPECT_TRUE(yaml.find("tcp_port: 12345") != std::string::npos);
    EXPECT_TRUE(yaml.find("udp_enabled: false") != std::string::npos);
    EXPECT_TRUE(yaml.find("level: debug") != std::string::npos);
}

TEST_F(ConfigTest, ToYamlClient) {
    Config config = Config::default_client();
    config.data_dir = "/client/path";
    config.client->server_id =
        "0000000000000000000000000000000000000000000000000000000000000000000000000000";
    config.client->forwards.push_back({2222, "localhost", 22});

    std::string yaml = config.to_yaml();
    EXPECT_TRUE(yaml.find("mode: client") != std::string::npos);
    EXPECT_TRUE(yaml.find("data_dir: /client/path") != std::string::npos);
    EXPECT_TRUE(yaml.find("client:") != std::string::npos);
    EXPECT_TRUE(yaml.find("server_id:") != std::string::npos);
    EXPECT_TRUE(yaml.find("forwards:") != std::string::npos);
    EXPECT_TRUE(yaml.find("local_port: 2222") != std::string::npos);
}

TEST_F(ConfigTest, RoundTripServer) {
    Config original = Config::default_server();
    original.data_dir = "/round/trip";
    original.server->tcp_port = 54321;
    original.server->udp_enabled = true;
    original.logging.level = util::LogLevel::Warn;
    original.logging.file = "/var/log/test.log";

    // Serialize
    std::string yaml = original.to_yaml();

    // Deserialize
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& loaded = result.value();
    EXPECT_EQ(loaded.mode, original.mode);
    EXPECT_EQ(loaded.data_dir, original.data_dir);
    EXPECT_EQ(loaded.server->tcp_port, original.server->tcp_port);
    EXPECT_EQ(loaded.server->udp_enabled, original.server->udp_enabled);
    EXPECT_EQ(loaded.logging.level, original.logging.level);
    EXPECT_EQ(loaded.logging.file, original.logging.file);
    EXPECT_EQ(loaded.service, original.service);
}

TEST_F(ConfigTest, RoundTripClient) {
    Config original = Config::default_client();
    original.data_dir = "/client/round/trip";
    original.client->server_id =
        "0000000000000000000000000000000000000000000000000000000000000000000000000001";
    original.client->forwards.push_back({8080, "192.168.1.1", 80});
    original.client->forwards.push_back({2222, "localhost", 22});

    // Serialize
    std::string yaml = original.to_yaml();

    // Deserialize
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& loaded = result.value();
    EXPECT_EQ(loaded.mode, original.mode);
    EXPECT_EQ(loaded.data_dir, original.data_dir);
    EXPECT_EQ(loaded.client->server_id, original.client->server_id);
    EXPECT_EQ(loaded.client->forwards.size(), original.client->forwards.size());
    for (size_t i = 0; i < loaded.client->forwards.size(); ++i) {
        EXPECT_EQ(loaded.client->forwards[i].local_port, original.client->forwards[i].local_port);
        EXPECT_EQ(loaded.client->forwards[i].remote_host, original.client->forwards[i].remote_host);
        EXPECT_EQ(loaded.client->forwards[i].remote_port, original.client->forwards[i].remote_port);
    }
    EXPECT_EQ(loaded.service, original.service);
}

TEST_F(ConfigTest, ServerDiscloseDefaultsAllFalse) {
    auto config = Config::default_server();
    ASSERT_TRUE(config.server.has_value());
    EXPECT_FALSE(config.server->disclose.hostname);
    EXPECT_FALSE(config.server->disclose.os);
    EXPECT_FALSE(config.server->disclose.os_version);
    EXPECT_FALSE(config.server->disclose.arch);
    EXPECT_FALSE(config.server->disclose.uptime);
    EXPECT_FALSE(config.server->disclose.toxtunnel_version);
    EXPECT_FALSE(config.server->disclose.any());
}

TEST_F(ConfigTest, ParseServerDiscloseExplicitFields) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
server:
  disclose:
    hostname: true
    os: true
    arch: true
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    const auto& cfg = result.value();
    ASSERT_TRUE(cfg.server.has_value());
    EXPECT_TRUE(cfg.server->disclose.hostname);
    EXPECT_TRUE(cfg.server->disclose.os);
    EXPECT_TRUE(cfg.server->disclose.arch);
    EXPECT_FALSE(cfg.server->disclose.os_version);
    EXPECT_FALSE(cfg.server->disclose.uptime);
    EXPECT_TRUE(cfg.server->disclose.any());
}

TEST_F(ConfigTest, ParseServerDiscloseScalarTrueFlipsAllFields) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
server:
  disclose: true
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    const auto& cfg = result.value();
    ASSERT_TRUE(cfg.server.has_value());
    EXPECT_TRUE(cfg.server->disclose.hostname);
    EXPECT_TRUE(cfg.server->disclose.os);
    EXPECT_TRUE(cfg.server->disclose.os_version);
    EXPECT_TRUE(cfg.server->disclose.arch);
    EXPECT_TRUE(cfg.server->disclose.uptime);
    EXPECT_TRUE(cfg.server->disclose.toxtunnel_version);
}

TEST_F(ConfigTest, RoundTripServerDisclose) {
    Config original = Config::default_server();
    original.server->disclose.hostname = true;
    original.server->disclose.arch = true;

    auto yaml = original.to_yaml();
    auto loaded = Config::from_string(yaml);
    ASSERT_TRUE(loaded.has_value()) << loaded.error();
    EXPECT_EQ(loaded.value().server->disclose, original.server->disclose);
}

TEST_F(ConfigTest, ParseServiceSection) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
service:
  auto_start: false
  allow_client_daemon: true
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_FALSE(result.value().service.auto_start);
    EXPECT_TRUE(result.value().service.allow_client_daemon);
}

TEST_F(ConfigTest, ShouldRunAsServiceDaemon) {
    Config srv_on = Config::default_server();
    ASSERT_TRUE(srv_on.should_run_as_service_daemon());

    Config srv_off = Config::default_server();
    srv_off.service.auto_start = false;
    ASSERT_FALSE(srv_off.should_run_as_service_daemon());

    Config cli_gate = Config::default_client();
    ASSERT_FALSE(cli_gate.should_run_as_service_daemon());

    Config cli_allow = cli_gate;
    cli_allow.service.allow_client_daemon = true;
    ASSERT_TRUE(cli_allow.should_run_as_service_daemon());

    // Critical invariant: in client mode `auto_start` is IGNORED. Only
    // `allow_client_daemon` may un-gate the daemon. Without this check the
    // earlier assertions all pass by coincidence (default_client() zeros both
    // flags), so a regression that read auto_start in client mode would slip.
    Config cli_auto_only = Config::default_client();
    cli_auto_only.service.auto_start = true;
    cli_auto_only.service.allow_client_daemon = false;
    ASSERT_FALSE(cli_auto_only.should_run_as_service_daemon())
        << "client mode must ignore auto_start and only consult allow_client_daemon";

    // Symmetric: in server mode `allow_client_daemon` is IGNORED.
    Config srv_allow_only = Config::default_server();
    srv_allow_only.service.auto_start = false;
    srv_allow_only.service.allow_client_daemon = true;
    ASSERT_FALSE(srv_allow_only.should_run_as_service_daemon())
        << "server mode must ignore allow_client_daemon and only consult auto_start";
}

// ---------------------------------------------------------------------------
// Merge CLI Overrides Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, MergeOverrideDataDir) {
    Config base = Config::default_server();
    base.data_dir = "/original";

    Config overrides;
    overrides.data_dir = "/overridden";

    base.merge_cli_overrides(overrides);
    EXPECT_EQ(base.data_dir, "/overridden");
}

// C-22 / 2026-05-20 finding: merge_cli_overrides previously used
// `overrides.logging.level != Info` as a stand-in for "the user passed
// --log-level". That made it impossible to override a Debug YAML
// setting back to Info from the CLI, because the override value
// "looked unset" to the merge logic. The fix moves logging.level
// application out of merge_cli_overrides into main.cpp (which knows
// whether the flag was actually passed). This test pins the new
// behaviour: merge_cli_overrides leaves logging.level alone.
TEST_F(ConfigTest, MergeDoesNotTouchLogLevel) {
    Config base = Config::default_server();
    base.logging.level = util::LogLevel::Debug;

    Config overrides;
    overrides.logging.level = util::LogLevel::Info;  // would have been a no-op pre-fix

    base.merge_cli_overrides(overrides);
    EXPECT_EQ(base.logging.level, util::LogLevel::Debug)
        << "merge_cli_overrides should not touch logging.level; main.cpp applies it directly";
}

TEST_F(ConfigTest, MergeOverrideTcpPort) {
    Config base = Config::default_server();
    base.server->tcp_port = 33445;

    Config overrides;
    overrides.mode = Mode::Server;
    overrides.server = ServerConfig{};
    overrides.server->tcp_port = 443;

    base.merge_cli_overrides(overrides);
    EXPECT_EQ(base.server->tcp_port, 443);
}

TEST_F(ConfigTest, MergeOverrideServerId) {
    Config base = Config::default_client();
    base.client->server_id =
        "0000000000000000000000000000000000000000000000000000000000000000000000000001";

    Config overrides;
    overrides.mode = Mode::Client;
    overrides.client = ClientConfig{};
    overrides.client->server_id =
        "0000000000000000000000000000000000000000000000000000000000000000000000000002";

    base.merge_cli_overrides(overrides);
    EXPECT_EQ(base.client->server_id,
              "0000000000000000000000000000000000000000000000000000000000000000000000000002");
}

TEST_F(ConfigTest, MergeOverrideForwards) {
    Config base = Config::default_client();
    base.client->forwards.push_back({8080, "localhost", 80});

    Config overrides;
    overrides.mode = Mode::Client;
    overrides.client = ClientConfig{};
    overrides.client->forwards.push_back({2222, "remote", 22});

    base.merge_cli_overrides(overrides);
    ASSERT_EQ(base.client->forwards.size(), 1);
    EXPECT_EQ(base.client->forwards[0].local_port, 2222);
    EXPECT_EQ(base.client->forwards[0].remote_host, "remote");
}

TEST_F(ConfigTest, MergeDoesNotOverrideEmptyString) {
    Config base = Config::default_client();
    base.client->server_id =
        "0000000000000000000000000000000000000000000000000000000000000000000000000001";

    Config overrides;
    overrides.mode = Mode::Client;
    overrides.client = ClientConfig{};
    // server_id is empty, should not override

    base.merge_cli_overrides(overrides);
    EXPECT_EQ(base.client->server_id,
              "0000000000000000000000000000000000000000000000000000000000000000000000000001");
}

// ---------------------------------------------------------------------------
// Equality Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, ForwardRuleEquality) {
    ForwardRule a{2222, "localhost", 22};
    ForwardRule b{2222, "localhost", 22};
    ForwardRule c{2222, "otherhost", 22};

    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST_F(ConfigTest, BootstrapNodeConfigEquality) {
    BootstrapNodeConfig a{"bootstrap.tox.me", 33445, "key"};
    BootstrapNodeConfig b{"bootstrap.tox.me", 33445, "key"};
    BootstrapNodeConfig c{"other.node", 33445, "key"};

    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST_F(ConfigTest, ConfigEquality) {
    Config a = Config::default_server();
    Config b = Config::default_server();
    Config c = Config::default_client();

    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

// ---------------------------------------------------------------------------
// ConfigError Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, ConfigErrorCodeCategory) {
    auto ec = make_error_code(ConfigError::FileNotFound);

    EXPECT_EQ(ec.category().name(), std::string("config"));
    EXPECT_FALSE(ec.message().empty());
}

TEST_F(ConfigTest, AllConfigErrorCodesHaveMessages) {
    std::vector<ConfigError> errors = {
        ConfigError::FileNotFound,     ConfigError::ParseError,      ConfigError::ValidationError,
        ConfigError::InvalidMode,      ConfigError::InvalidPort,     ConfigError::InvalidToxId,
        ConfigError::InvalidPublicKey, ConfigError::MissingRequired,
    };

    for (const auto& err : errors) {
        auto ec = make_error_code(err);
        EXPECT_FALSE(ec.message().empty())
            << "Error code " << static_cast<int>(err) << " has no message";
    }
}

// ---------------------------------------------------------------------------
// BootstrapNodeConfig Conversion Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, BootstrapNodeConfigToBootstrapNode) {
    // Use a valid 64-char hex key
    BootstrapNodeConfig config{"bootstrap.tox.me", 33445,
                               "0000000000000000000000000000000000000000000000000000000000000000"};

    auto result = config.to_bootstrap_node();
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& node = result.value();
    EXPECT_EQ(node.ip, "bootstrap.tox.me");
    EXPECT_EQ(node.port, 33445);
}

TEST_F(ConfigTest, BootstrapNodeConfigInvalidPublicKey) {
    BootstrapNodeConfig config{"bootstrap.tox.me", 33445, "invalid_key"};

    auto result = config.to_bootstrap_node();
    EXPECT_FALSE(result.has_value());
}

// ---------------------------------------------------------------------------
// Optional Fields Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, OptionalLoggingFile) {
    const char* yaml_with_file = R"(
mode: server
logging:
  level: info
  file: /var/log/test.log
)";

    auto result = Config::from_string(yaml_with_file);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result.value().logging.file.has_value());
    EXPECT_EQ(*result.value().logging.file, "/var/log/test.log");

    const char* yaml_without_file = R"(
mode: server
logging:
  level: info
)";

    result = Config::from_string(yaml_without_file);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result.value().logging.file.has_value());
}

TEST_F(ConfigTest, OptionalRulesFile) {
    const char* yaml_with_rules = R"(
mode: server
rules_file: /etc/toxtunnel/rules.conf
)";

    auto result = Config::from_string(yaml_with_rules);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result.value().server->rules_file.has_value());
    EXPECT_EQ(*result.value().server->rules_file, "/etc/toxtunnel/rules.conf");

    const char* yaml_without_rules = R"(
mode: server
)";

    result = Config::from_string(yaml_without_rules);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result.value().server->rules_file.has_value());
}

// ---------------------------------------------------------------------------
// Default Port for Bootstrap Node Tests
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, BootstrapNodeDefaultPort) {
    const char* yaml = R"(
mode: server
bootstrap_nodes:
  - address: bootstrap.tox.me
    public_key: 0000000000000000000000000000000000000000000000000000000000000000
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value());

    const auto& nodes = result.value().server->bootstrap_nodes;
    ASSERT_EQ(nodes.size(), 1);
    EXPECT_EQ(nodes[0].port, 33445);  // Default port
}

TEST_F(ConfigTest, BootstrapNodeCustomPort) {
    const char* yaml = R"(
mode: server
bootstrap_nodes:
  - address: bootstrap.tox.me
    port: 433
    public_key: 0000000000000000000000000000000000000000000000000000000000000000
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value());

    const auto& nodes = result.value().server->bootstrap_nodes;
    ASSERT_EQ(nodes.size(), 1);
    EXPECT_EQ(nodes[0].port, 433);
}

TEST_F(ConfigTest, Ipv6EnabledDefaultsTrue) {
    // Defaults must be dual-stack: an IPv4-only DHT bind silently steals the
    // IPv4 wildcard from other Tox apps on the host
    // (docs/FIELD_NOTES_SSH_TUNNEL.md #8).
    EXPECT_TRUE(ToxConfig{}.ipv6_enabled);
    EXPECT_TRUE(Config::default_client().tox.ipv6_enabled);
    EXPECT_TRUE(Config::default_server().tox.ipv6_enabled);
}

TEST_F(ConfigTest, Ipv6EnabledParsesAndRoundTrips) {
    const char* yaml = R"(
mode: client
data_dir: ~/.config/toxtunnel
tox:
  ipv6_enabled: false
)";
    auto parsed = Config::from_string(yaml);
    ASSERT_TRUE(parsed.has_value()) << parsed.error();
    EXPECT_FALSE(parsed.value().tox.ipv6_enabled);

    // Round-trip: an explicit false must survive serialize -> parse.
    std::string out = parsed.value().to_yaml();
    EXPECT_TRUE(out.find("ipv6_enabled: false") != std::string::npos);
    auto reparsed = Config::from_string(out);
    ASSERT_TRUE(reparsed.has_value()) << reparsed.error();
    EXPECT_FALSE(reparsed.value().tox.ipv6_enabled);
}

TEST_F(ConfigTest, ParseCanonicalServerToxConfig) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
tox:
  udp_enabled: true
  tcp_port: 33445
  bootstrap_mode: lan
  bootstrap_nodes:
    - address: 192.168.1.10
      port: 33445
      public_key: 0000000000000000000000000000000000000000000000000000000000000000
server:
  rules_file: /etc/toxtunnel/rules.conf
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& config = result.value();
    EXPECT_EQ(config.tox.udp_enabled, true);
    EXPECT_EQ(config.tox.tcp_port, 33445);
    EXPECT_EQ(config.tox.bootstrap_mode, BootstrapMode::Lan);
    ASSERT_EQ(config.tox.bootstrap_nodes.size(), 1u);
    EXPECT_EQ(config.tox.bootstrap_nodes[0].address, "192.168.1.10");
    ASSERT_TRUE(config.server.has_value());
    ASSERT_TRUE(config.server->rules_file.has_value());
    EXPECT_EQ(*config.server->rules_file, "/etc/toxtunnel/rules.conf");
}

TEST_F(ConfigTest, ParseCanonicalClientToxConfig) {
    const char* yaml = R"(
mode: client
data_dir: ~/.config/toxtunnel
tox:
  udp_enabled: true
  bootstrap_mode: lan
  bootstrap_nodes:
    - address: 192.168.1.11
      port: 33445
      public_key: 1111111111111111111111111111111111111111111111111111111111111111
client:
  server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
  forwards:
    - local_port: 2222
      remote_host: localhost
      remote_port: 22
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& config = result.value();
    EXPECT_EQ(config.tox.bootstrap_mode, BootstrapMode::Lan);
    ASSERT_EQ(config.tox.bootstrap_nodes.size(), 1u);
    EXPECT_EQ(config.tox.bootstrap_nodes[0].address, "192.168.1.11");
    ASSERT_TRUE(config.client.has_value());
    EXPECT_EQ(config.client->forwards[0].local_port, 2222);
}

TEST_F(ConfigTest, LegacyServerBootstrapFieldsNormalizeIntoSharedToxConfig) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
server:
  tcp_port: 33445
  udp_enabled: false
  bootstrap_nodes:
    - address: 192.168.1.12
      port: 33445
      public_key: 2222222222222222222222222222222222222222222222222222222222222222
  rules_file: /etc/toxtunnel/rules.conf
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const auto& config = result.value();
    EXPECT_EQ(config.tox.tcp_port, 33445);
    EXPECT_FALSE(config.tox.udp_enabled);
    ASSERT_EQ(config.tox.bootstrap_nodes.size(), 1u);
    EXPECT_EQ(config.tox.bootstrap_nodes[0].address, "192.168.1.12");
    ASSERT_TRUE(config.server.has_value());
    ASSERT_TRUE(config.server->rules_file.has_value());
    EXPECT_EQ(*config.server->rules_file, "/etc/toxtunnel/rules.conf");
}

TEST_F(ConfigTest, ValidateLanBootstrapRequiresUdpEnabled) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
tox:
  udp_enabled: false
  tcp_port: 33445
  bootstrap_mode: lan
server: {}
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    auto validation = result.value().validate();
    EXPECT_FALSE(validation.has_value());
}

TEST_F(ConfigTest, ValidateRejectsNonLoopbackSocks5Listen) {
    const char* yaml = R"(
mode: client
data_dir: /tmp/toxtunnel
tox:
  udp_enabled: true
  tcp_port: 33445
  bootstrap_mode: auto
client:
  server_id: "DE47F247CE6D7BE29A5903A234A045A227C6CB969943A8317EA74F7D38810D10D43C53082F2B"
  socks5:
    enabled: true
    listen: "0.0.0.0:1080"
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    auto validation = result.value().validate();
    ASSERT_FALSE(validation.has_value());
    EXPECT_NE(validation.error().find("loopback"), std::string::npos);
}

TEST_F(ConfigTest, ValidateAcceptsLoopbackSocks5Variants) {
    const char* yaml_template = R"(
mode: client
data_dir: /tmp/toxtunnel
tox:
  udp_enabled: true
  tcp_port: 33445
  bootstrap_mode: auto
client:
  server_id: "DE47F247CE6D7BE29A5903A234A045A227C6CB969943A8317EA74F7D38810D10D43C53082F2B"
  socks5:
    enabled: true
    listen: ")";

    for (const char* const listen :
         {"127.0.0.1:1080", "127.42.13.7:9999", "[::1]:1080", "localhost:1080", "LocalHost:8080"}) {
        const std::string yaml = std::string(yaml_template) + listen + "\"";
        auto result = Config::from_string(yaml);
        ASSERT_TRUE(result.has_value()) << "listen=" << listen << " err=" << result.error();
        auto validation = result.value().validate();
        EXPECT_TRUE(validation.has_value()) << "listen=" << listen << " err=" << validation.error();
    }
}

TEST_F(ConfigTest, ToYamlEmitsCanonicalToxBlock) {
    Config config = Config::default_server();
    config.data_dir = "/test/path";
    config.tox.udp_enabled = true;
    config.tox.tcp_port = 12345;
    config.tox.bootstrap_mode = BootstrapMode::Lan;
    config.tox.bootstrap_nodes.push_back(
        {"192.168.1.13", 33445,
         "3333333333333333333333333333333333333333333333333333333333333333"});
    config.server->rules_file = "/etc/toxtunnel/rules.conf";

    std::string yaml = config.to_yaml();
    EXPECT_TRUE(yaml.find("tox:") != std::string::npos);
    EXPECT_TRUE(yaml.find("bootstrap_mode: lan") != std::string::npos);
    EXPECT_TRUE(yaml.find("tcp_port: 12345") != std::string::npos);
    EXPECT_TRUE(yaml.find("rules_file: /etc/toxtunnel/rules.conf") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Tilde expansion in YAML path fields
//
// Regression test for the bug where `data_dir: ~/.config/toxtunnel` in a YAML
// config was passed verbatim to KnownServersStore, causing alias resolution to
// silently miss the registry file (manifesting as a confusing
// "Server ID must be 76 characters, got 7" validation error).
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, TildeInDataDirIsExpanded) {
    const char* fake_home = "/tmp/toxtunnel-tilde-test-home";
#ifdef _WIN32
    _putenv_s("HOME", fake_home);
#else
    setenv("HOME", fake_home, /*overwrite=*/1);
#endif

    const char* yaml = R"(
mode: server
data_dir: ~/.config/toxtunnel
server: {}
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_EQ(result.value().data_dir, std::filesystem::path(fake_home) / ".config" / "toxtunnel");
}

TEST_F(ConfigTest, TildeInRulesFileIsExpanded) {
    const char* fake_home = "/tmp/toxtunnel-tilde-test-home";
#ifdef _WIN32
    _putenv_s("HOME", fake_home);
#else
    setenv("HOME", fake_home, /*overwrite=*/1);
#endif

    const char* yaml = R"(
mode: server
data_dir: /tmp/data
server:
  rules_file: ~/rules.yaml
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_TRUE(result.value().server.has_value());
    ASSERT_TRUE(result.value().server->rules_file.has_value());
    EXPECT_EQ(*result.value().server->rules_file, std::string(fake_home) + "/rules.yaml");
}

TEST_F(ConfigTest, BareTildeIsExpandedToHome) {
    // YAML parses bare `~` as null, so the user must quote it to pass a literal
    // tilde. This is a YAML quirk independent of our expansion logic — we just
    // confirm the quoted form round-trips through the expander correctly.
    const char* fake_home = "/tmp/toxtunnel-tilde-test-home";
#ifdef _WIN32
    _putenv_s("HOME", fake_home);
#else
    setenv("HOME", fake_home, /*overwrite=*/1);
#endif

    const char* yaml = R"(
mode: server
data_dir: '~'
server: {}
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_EQ(result.value().data_dir, fake_home);
}

TEST_F(ConfigTest, NonTildePathIsUnchanged) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
server: {}
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_EQ(result.value().data_dir, "/var/lib/toxtunnel");
}

TEST_F(ConfigTest, TildeUsernameFormIsNotExpanded) {
    // `~user/path` is POSIX-only and requires getpwnam. Out of scope — pass through.
    const char* yaml = R"(
mode: server
data_dir: ~someuser/data
server: {}
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_EQ(result.value().data_dir, "~someuser/data");
}

// ---------------------------------------------------------------------------
// Parser-effect tests: keys that reach the live Config
//
// `config_diagnostics` only proves a key is *spelled* correctly; it says
// nothing about whether the parser reads it. `inspect` and
// `client.fallback_server_ids` were both allowlisted there while
// `convert<Config>::decode` ignored them, so the documented settings were
// silently dropped. These tests assert the parsed Config actually carries the
// value, which is the property the allowlist tests cannot see.
// ---------------------------------------------------------------------------

TEST_F(ConfigTest, InspectDefaultsToEnabledWhenBlockAbsent) {
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_TRUE(result.value().inspect.enabled);
}

TEST_F(ConfigTest, ParseInspectDisabled) {
    // The documented way to keep a host from opening the local IPC socket.
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
inspect:
  enabled: false
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_FALSE(result.value().inspect.enabled);
}

TEST_F(ConfigTest, ParseInspectExplicitlyEnabled) {
    const char* yaml = R"(
mode: client
data_dir: /tmp/data
server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
inspect:
  enabled: true
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_TRUE(result.value().inspect.enabled);
}

TEST_F(ConfigTest, ParseInspectScalarShorthand) {
    // convert<InspectConfig>::decode also accepts the bare-bool spelling.
    const char* yaml = R"(
mode: server
data_dir: /var/lib/toxtunnel
inspect: false
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_FALSE(result.value().inspect.enabled);
}

TEST_F(ConfigTest, RoundTripInspectDisabled) {
    Config original = Config::default_server();
    original.data_dir = "/inspect/round/trip";
    original.inspect.enabled = false;

    const std::string yaml = original.to_yaml();
    EXPECT_TRUE(yaml.find("inspect:") != std::string::npos) << yaml;

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_FALSE(result.value().inspect.enabled);
}

TEST_F(ConfigTest, DefaultInspectIsOmittedFromEncodedYaml) {
    // Same conditional-emit policy `to_yaml()` applies to `metrics`: a default
    // block is noise in a generated file. Its absence must still decode to
    // enabled. `tunnel`, `flow_control` and `watchdog` follow the same rule now
    // that `to_yaml()` shares convert<Config>::encode — see the round-trip
    // tests at the end of this file for the non-default half of that contract.
    Config original = Config::default_server();
    const std::string yaml = original.to_yaml();
    EXPECT_TRUE(yaml.find("inspect:") == std::string::npos) << yaml;

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_TRUE(result.value().inspect.enabled);
}

TEST_F(ConfigTest, ParseFallbackServerIdsKeyNested) {
    const char* yaml = R"(
mode: client
data_dir: /tmp/data
client:
  server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
  fallback_server_ids:
    - 1111111111111111111111111111111111111111111111111111111111111111111111111111
    - 2222222222222222222222222222222222222222222222222222222222222222222222222222
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_TRUE(result.value().client.has_value());
    const auto& client = *result.value().client;
    EXPECT_EQ(client.server_id,
              "0000000000000000000000000000000000000000000000000000000000000000000000000000");
    ASSERT_EQ(client.fallback_server_ids.size(), 2u);
    EXPECT_EQ(client.fallback_server_ids[0],
              "1111111111111111111111111111111111111111111111111111111111111111111111111111");
    EXPECT_EQ(client.fallback_server_ids[1],
              "2222222222222222222222222222222222222222222222222222222222222222222222222222");
    // all_server_ids() is what TunnelClient's failover state machine walks.
    EXPECT_EQ(client.all_server_ids().size(), 3u);
}

TEST_F(ConfigTest, ParseFallbackServerIdsKeyFlatLayout) {
    // The legacy flat layout reads client keys straight off the root node.
    const char* yaml = R"(
mode: client
data_dir: /tmp/data
server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
fallback_server_ids:
  - 1111111111111111111111111111111111111111111111111111111111111111111111111111
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_TRUE(result.value().client.has_value());
    ASSERT_EQ(result.value().client->fallback_server_ids.size(), 1u);
    EXPECT_EQ(result.value().client->fallback_server_ids[0],
              "1111111111111111111111111111111111111111111111111111111111111111111111111111");
}

TEST_F(ConfigTest, FallbackServerIdsKeyAppendsToServerIdListForm) {
    // Both spellings are documented; mixing them accumulates rather than one
    // silently winning. A genuine duplicate is then validate()'s to reject.
    const char* yaml = R"(
mode: client
data_dir: /tmp/data
client:
  server_id:
    - 0000000000000000000000000000000000000000000000000000000000000000000000000000
    - 1111111111111111111111111111111111111111111111111111111111111111111111111111
  fallback_server_ids:
    - 2222222222222222222222222222222222222222222222222222222222222222222222222222
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_TRUE(result.value().client.has_value());
    const auto& client = *result.value().client;
    EXPECT_EQ(client.server_id,
              "0000000000000000000000000000000000000000000000000000000000000000000000000000");
    ASSERT_EQ(client.fallback_server_ids.size(), 2u);
    EXPECT_EQ(client.fallback_server_ids[0],
              "1111111111111111111111111111111111111111111111111111111111111111111111111111");
    EXPECT_EQ(client.fallback_server_ids[1],
              "2222222222222222222222222222222222222222222222222222222222222222222222222222");
}

// A non-sequence `fallback_server_ids` used to be dropped on the floor: the
// decoder tested `IsSequence()` and did nothing otherwise, so a scalar parsed,
// passed `config check --strict` with exit 0 and "valid (client mode)", and the
// daemon started with no fallback at all. Silently ignoring a key the operator
// wrote is the worst of the available behaviours — these pin the two shapes we
// accept and the one we reject.
TEST_F(ConfigTest, ParseFallbackServerIdsScalarShorthand) {
    // Mirrors `server_id`, which has always taken either a scalar or a list.
    const char* yaml = R"(
mode: client
data_dir: /tmp/data
client:
  server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
  fallback_server_ids: 1111111111111111111111111111111111111111111111111111111111111111111111111111
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_TRUE(result.value().client.has_value());
    const auto& client = *result.value().client;
    ASSERT_EQ(client.fallback_server_ids.size(), 1u)
        << "a scalar fallback must not be silently discarded";
    EXPECT_EQ(client.fallback_server_ids[0],
              "1111111111111111111111111111111111111111111111111111111111111111111111111111");
    EXPECT_EQ(client.all_server_ids().size(), 2u);
}

TEST_F(ConfigTest, ParseFallbackServerIdsEmptyKeyIsEmptyList) {
    // An explicit-but-valueless key is "no fallbacks", not a parse error.
    const char* yaml = R"(
mode: client
data_dir: /tmp/data
client:
  server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
  fallback_server_ids:
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_TRUE(result.value().client.has_value());
    EXPECT_TRUE(result.value().client->fallback_server_ids.empty());
}

TEST_F(ConfigTest, ParseFallbackServerIdsMapIsRejected) {
    // A map cannot be read as a tox id. It must surface as a parse failure
    // rather than being quietly ignored the way it was before.
    const char* yaml = R"(
mode: client
data_dir: /tmp/data
client:
  server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
  fallback_server_ids:
    some_key: 1111111111111111111111111111111111111111111111111111111111111111111111111111
)";
    auto result = Config::from_string(yaml);
    EXPECT_FALSE(result.has_value()) << "a map-valued fallback_server_ids must not parse as valid";
}

// convert<ClientConfig> is a public specialisation with no in-tree caller
// today. It is tested directly because the standalone and Config-embedded
// decoders drifting apart is precisely how fallback_server_ids came to be
// unreadable in one of them.
TEST_F(ConfigTest, StandaloneClientConfigDecoderReadsFallbackKey) {
    const YAML::Node node = YAML::Load(R"(
server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
fallback_server_ids:
  - 1111111111111111111111111111111111111111111111111111111111111111111111111111
)");
    const auto client = node.as<ClientConfig>();
    EXPECT_EQ(client.server_id,
              "0000000000000000000000000000000000000000000000000000000000000000000000000000");
    ASSERT_EQ(client.fallback_server_ids.size(), 1u);
    EXPECT_EQ(client.fallback_server_ids[0],
              "1111111111111111111111111111111111111111111111111111111111111111111111111111");
}

TEST_F(ConfigTest, StandaloneClientConfigDecoderTakesScalarFallback) {
    const YAML::Node node = YAML::Load(R"(
server_id: 0000000000000000000000000000000000000000000000000000000000000000000000000000
fallback_server_ids: 1111111111111111111111111111111111111111111111111111111111111111111111111111
)");
    const auto client = node.as<ClientConfig>();
    ASSERT_EQ(client.fallback_server_ids.size(), 1u);
    EXPECT_EQ(client.fallback_server_ids[0],
              "1111111111111111111111111111111111111111111111111111111111111111111111111111");
}

TEST_F(ConfigTest, ParseServerIdSequencePopulatesFallbacks) {
    // Pre-existing path, pinned so the fallback_server_ids fix cannot regress it.
    const char* yaml = R"(
mode: client
data_dir: /tmp/data
client:
  server_id:
    - 0000000000000000000000000000000000000000000000000000000000000000000000000000
    - 1111111111111111111111111111111111111111111111111111111111111111111111111111
)";
    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_TRUE(result.value().client.has_value());
    ASSERT_EQ(result.value().client->fallback_server_ids.size(), 1u);
    EXPECT_EQ(result.value().client->fallback_server_ids[0],
              "1111111111111111111111111111111111111111111111111111111111111111111111111111");
}

TEST_F(ConfigTest, RoundTripFallbackServerIds) {
    // encode() folds the fallbacks into the list form of `server_id`; decode
    // must give them back unchanged.
    Config original = Config::default_client();
    original.data_dir = "/fallback/round/trip";
    original.client->server_id =
        "0000000000000000000000000000000000000000000000000000000000000000000000000000";
    original.client->fallback_server_ids = {
        "1111111111111111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222222222222222"};

    auto result = Config::from_string(original.to_yaml());
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_TRUE(result.value().client.has_value());
    EXPECT_EQ(result.value().client->server_id, original.client->server_id);
    EXPECT_EQ(result.value().client->fallback_server_ids, original.client->fallback_server_ids);
}

// ---------------------------------------------------------------------------
// Single-source-of-truth serialization tests
//
// `Config::to_yaml()` used to be a second, hand-rolled emitter alongside
// `convert<Config>::encode`, and it had drifted to omitting `tunnel`,
// `flow_control` and `watchdog` entirely — so every `save()` silently
// discarded those blocks. The tests below are parser-effect tests: they assert
// values survive the real serialize -> parse path. A structural "is the key
// spelled right" check cannot see this class of loss, which is how it survived.
// ---------------------------------------------------------------------------

namespace {

/// A server Config with a non-default value in every block that has one.
/// `server->{tcp_port,udp_enabled,bootstrap_nodes}` are set to mirror `tox`
/// because the parser re-derives them from the canonical `tox:` block, and
/// `Config::operator==` compares the mirror.
Config make_populated_server_config() {
    Config cfg = Config::default_server();
    cfg.data_dir = "/populated/server";
    cfg.logging.level = util::LogLevel::Trace;
    cfg.logging.file = "/var/log/toxtunnel-populated.log";
    cfg.service.auto_start = false;
    cfg.service.allow_client_daemon = true;
    cfg.metrics.enabled = true;
    cfg.metrics.listen = "127.0.0.1:9333";
    cfg.metrics.path = "/m";
    cfg.inspect.enabled = false;

    cfg.tox.udp_enabled = false;
    cfg.tox.ipv6_enabled = false;
    cfg.tox.tcp_port = 44444;
    cfg.tox.bootstrap_mode = BootstrapMode::Lan;
    cfg.tox.bootstrap_nodes.push_back(
        {"192.168.1.77", 33445,
         "4444444444444444444444444444444444444444444444444444444444444444"});

    cfg.tunnel.coalesce_max_delay_us = 900;
    cfg.tunnel.coalesce_max_bytes = 4096;
    cfg.tunnel.coalesce_mode = "adaptive";
    cfg.tunnel.idle_timeout_seconds = 600;
    cfg.tunnel.reaper_tick_seconds = 7;
    cfg.tunnel.half_close_timeout_seconds = 45;
    cfg.tunnel.keepalive_interval_seconds = 20;
    cfg.tunnel.resume.enabled = true;
    cfg.tunnel.resume.state_path = "/populated/server/resume.yaml";
    cfg.tunnel.resume.max_age_seconds = 900;
    cfg.tunnel.resume.on_gap = "close";

    cfg.flow_control.mode = "fixed";
    cfg.flow_control.send_window_min_bytes = 32768;
    cfg.flow_control.send_window_max_bytes = 8 * 1024 * 1024;
    cfg.flow_control.safety_factor_x100 = 210;
    cfg.flow_control.fixed_window_bytes = 131072;

    cfg.watchdog.enabled = false;
    cfg.watchdog.deadline_seconds = 90;
    cfg.watchdog.systemd_notify = false;

    cfg.server->rules_file = "/etc/toxtunnel/populated-rules.yaml";
    cfg.server->disclose.hostname = true;
    cfg.server->disclose.uptime = true;
    cfg.server->tcp_port = cfg.tox.tcp_port;
    cfg.server->udp_enabled = cfg.tox.udp_enabled;
    cfg.server->bootstrap_nodes = cfg.tox.bootstrap_nodes;
    return cfg;
}

/// A client Config with a non-default value in every block that has one.
Config make_populated_client_config() {
    Config cfg = Config::default_client();
    cfg.data_dir = "/populated/client";
    cfg.logging.level = util::LogLevel::Error;
    cfg.logging.file = "/var/log/toxtunnel-client.log";
    cfg.service.auto_start = true;
    cfg.service.allow_client_daemon = true;
    cfg.metrics.enabled = true;
    cfg.metrics.listen = "127.0.0.1:9444";
    cfg.metrics.path = "/mc";
    cfg.inspect.enabled = false;

    cfg.tox.udp_enabled = false;
    cfg.tox.ipv6_enabled = false;
    cfg.tox.tcp_port = 45555;
    cfg.tox.bootstrap_mode = BootstrapMode::Lan;

    cfg.tunnel.coalesce_max_delay_us = 111;
    cfg.tunnel.coalesce_mode = "bypass";
    cfg.tunnel.idle_timeout_seconds = 300;
    cfg.tunnel.keepalive_interval_seconds = 15;
    cfg.tunnel.resume.enabled = true;
    cfg.tunnel.resume.on_gap = "close";

    cfg.flow_control.mode = "fixed";
    cfg.flow_control.fixed_window_bytes = 65536;

    cfg.watchdog.enabled = false;
    cfg.watchdog.deadline_seconds = 120;

    cfg.client->server_id =
        "0000000000000000000000000000000000000000000000000000000000000000000000000000";
    cfg.client->fallback_server_ids = {
        "1111111111111111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222222222222222"};
    cfg.client->forwards.push_back({2222, "localhost", 22});
    cfg.client->forwards.push_back({8080, "10.0.0.5", 80});
    cfg.client->pipe_target = PipeTarget{"pipe.example", 4444};
    cfg.client->failover.timeout_seconds = 12;
    cfg.client->failover.prefer_primary_grace_seconds = 34;
    cfg.client->socks5.enabled = true;
    cfg.client->socks5.listen = "127.0.0.1:1085";
    return cfg;
}

}  // namespace

TEST_F(ConfigTest, RoundTripPreservesTunnelBlock) {
    const Config original = make_populated_server_config();

    auto result = Config::from_string(original.to_yaml());
    ASSERT_TRUE(result.has_value()) << result.error();
    const auto& loaded = result.value();

    EXPECT_EQ(loaded.tunnel.coalesce_max_delay_us, 900u);
    EXPECT_EQ(loaded.tunnel.coalesce_max_bytes, 4096u);
    EXPECT_EQ(loaded.tunnel.coalesce_mode, "adaptive");
    EXPECT_EQ(loaded.tunnel.idle_timeout_seconds, 600u);
    EXPECT_EQ(loaded.tunnel.reaper_tick_seconds, 7u);
    EXPECT_EQ(loaded.tunnel.half_close_timeout_seconds, 45u);
    EXPECT_EQ(loaded.tunnel.keepalive_interval_seconds, 20u);
    EXPECT_TRUE(loaded.tunnel.resume.enabled);
    EXPECT_EQ(loaded.tunnel.resume.state_path, "/populated/server/resume.yaml");
    EXPECT_EQ(loaded.tunnel.resume.max_age_seconds, 900u);
    EXPECT_EQ(loaded.tunnel.resume.on_gap, "close");
    EXPECT_EQ(loaded.tunnel, original.tunnel);
}

TEST_F(ConfigTest, RoundTripPreservesFlowControlBlock) {
    const Config original = make_populated_server_config();

    auto result = Config::from_string(original.to_yaml());
    ASSERT_TRUE(result.has_value()) << result.error();
    const auto& loaded = result.value();

    EXPECT_EQ(loaded.flow_control.mode, "fixed");
    EXPECT_EQ(loaded.flow_control.send_window_min_bytes, 32768u);
    EXPECT_EQ(loaded.flow_control.send_window_max_bytes, 8u * 1024u * 1024u);
    EXPECT_EQ(loaded.flow_control.safety_factor_x100, 210u);
    EXPECT_EQ(loaded.flow_control.fixed_window_bytes, 131072u);
    EXPECT_EQ(loaded.flow_control, original.flow_control);
}

TEST_F(ConfigTest, RoundTripPreservesWatchdogBlock) {
    const Config original = make_populated_server_config();

    auto result = Config::from_string(original.to_yaml());
    ASSERT_TRUE(result.has_value()) << result.error();
    const auto& loaded = result.value();

    EXPECT_FALSE(loaded.watchdog.enabled);
    EXPECT_EQ(loaded.watchdog.deadline_seconds, 90u);
    EXPECT_FALSE(loaded.watchdog.systemd_notify);
    EXPECT_EQ(loaded.watchdog, original.watchdog);
}

TEST_F(ConfigTest, RoundTripPopulatedServerConfigIsLossless) {
    const Config original = make_populated_server_config();

    auto result = Config::from_string(original.to_yaml());
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_EQ(result.value(), original) << original.to_yaml();
}

TEST_F(ConfigTest, RoundTripPopulatedClientConfigIsLossless) {
    const Config original = make_populated_client_config();

    auto result = Config::from_string(original.to_yaml());
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_EQ(result.value(), original) << original.to_yaml();
}

TEST_F(ConfigTest, SavePreservesTunnelFlowControlAndWatchdog) {
    // The file path is the one that actually loses data in production: an
    // operator edits `watchdog.enabled: false`, some code path calls save(),
    // and the setting is gone from the file on disk.
    const Config original = make_populated_server_config();

    const auto path = test_dir_ / "populated_save.yaml";
    auto saved = original.save(path);
    ASSERT_TRUE(saved.has_value()) << saved.error();

    auto loaded = Config::from_file(path);
    ASSERT_TRUE(loaded.has_value()) << loaded.error();
    EXPECT_EQ(loaded.value().tunnel, original.tunnel);
    EXPECT_EQ(loaded.value().flow_control, original.flow_control);
    EXPECT_EQ(loaded.value().watchdog, original.watchdog);
    EXPECT_EQ(loaded.value(), original);
}

TEST_F(ConfigTest, SavePreservesPopulatedClientConfig) {
    const Config original = make_populated_client_config();

    const auto path = test_dir_ / "populated_client_save.yaml";
    auto saved = original.save(path);
    ASSERT_TRUE(saved.has_value()) << saved.error();

    auto loaded = Config::from_file(path);
    ASSERT_TRUE(loaded.has_value()) << loaded.error();
    EXPECT_EQ(loaded.value(), original);
}

TEST_F(ConfigTest, EncodeSpecializationAndToYamlAgree) {
    // `to_yaml()` is now defined as "emit convert<Config>::encode". Pin that so
    // a future edit cannot quietly reintroduce a second field list.
    for (const Config& cfg : {make_populated_server_config(), make_populated_client_config(),
                              Config::default_server(), Config::default_client()}) {
        YAML::Emitter out;
        out << YAML::convert<Config>::encode(cfg);
        EXPECT_EQ(cfg.to_yaml(), std::string(out.c_str()));
    }
}

TEST_F(ConfigTest, EncodeSpecializationCarriesServerDisclose) {
    // `convert<Config>::encode` used to drop `server.disclose` while the
    // hand-rolled emitter kept it — the same drift in the other direction.
    Config cfg = Config::default_server();
    cfg.server->disclose.os = true;
    cfg.server->disclose.toxtunnel_version = true;

    const YAML::Node node = YAML::convert<Config>::encode(cfg);
    ASSERT_TRUE(node["server"]["disclose"]) << cfg.to_yaml();
    EXPECT_TRUE(node["server"]["disclose"]["os"].as<bool>());
    EXPECT_TRUE(node["server"]["disclose"]["toxtunnel_version"].as<bool>());
    EXPECT_FALSE(node["server"]["disclose"]["hostname"].as<bool>());
}

// ---------------------------------------------------------------------------
// Decoder-agreement tests
//
// `convert<ClientConfig>::decode` and the client branch of
// `convert<Config>::decode` were separate hand-maintained readers of the same
// field list; `fallback_server_ids` was readable through one and a silent
// no-op through the other. These tests decode identical bodies through every
// entry point and assert the resulting ClientConfig matches.
// ---------------------------------------------------------------------------

namespace {

/// Indent every non-empty line of @p body by two spaces, so a client body can
/// be spliced under a `client:` key.
std::string indent_two(const std::string& body) {
    std::string out;
    std::size_t pos = 0;
    while (pos <= body.size()) {
        const std::size_t eol = body.find('\n', pos);
        const std::string line =
            body.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
        if (!line.empty()) {
            out += "  ";
            out += line;
        }
        out += '\n';
        if (eol == std::string::npos) {
            break;
        }
        pos = eol + 1;
    }
    return out;
}

/// Decode @p body through all three entry points: the standalone
/// `convert<ClientConfig>` specialisation, the nested `client:` layout, and the
/// legacy flat layout. Asserts all three agree and returns the value.
ClientConfig decode_client_every_way(const std::string& body) {
    const ClientConfig standalone = YAML::Load(body).as<ClientConfig>();

    const std::string preamble = "mode: client\ndata_dir: /tmp/decoder-agreement\n";
    auto nested = Config::from_string(preamble + "client:\n" + indent_two(body));
    EXPECT_TRUE(nested.has_value()) << (nested.has_value() ? std::string{} : nested.error());
    auto flat = Config::from_string(preamble + body);
    EXPECT_TRUE(flat.has_value()) << (flat.has_value() ? std::string{} : flat.error());

    if (nested.has_value() && nested.value().client.has_value()) {
        EXPECT_EQ(*nested.value().client, standalone) << "nested `client:` layout disagrees";
    }
    if (flat.has_value() && flat.value().client.has_value()) {
        EXPECT_EQ(*flat.value().client, standalone) << "legacy flat layout disagrees";
    }
    return standalone;
}

constexpr const char* kId0 =
    "0000000000000000000000000000000000000000000000000000000000000000000000000000";
constexpr const char* kId1 =
    "1111111111111111111111111111111111111111111111111111111111111111111111111111";
constexpr const char* kId2 =
    "2222222222222222222222222222222222222222222222222222222222222222222222222222";

}  // namespace

TEST_F(ConfigTest, DecodersAgreeOnScalarServerId) {
    const auto client = decode_client_every_way(std::string("server_id: ") + kId0 + "\n");
    EXPECT_EQ(client.server_id, kId0);
    EXPECT_TRUE(client.fallback_server_ids.empty());
}

TEST_F(ConfigTest, DecodersAgreeOnSequenceServerId) {
    const auto client = decode_client_every_way(std::string("server_id:\n  - ") + kId0 + "\n  - " +
                                                kId1 + "\n  - " + kId2 + "\n");
    EXPECT_EQ(client.server_id, kId0);
    ASSERT_EQ(client.fallback_server_ids.size(), 2u);
    EXPECT_EQ(client.fallback_server_ids[0], kId1);
    EXPECT_EQ(client.fallback_server_ids[1], kId2);
}

TEST_F(ConfigTest, DecodersAgreeOnFallbackSequence) {
    const auto client =
        decode_client_every_way(std::string("server_id: ") + kId0 + "\nfallback_server_ids:\n  - " +
                                kId1 + "\n  - " + kId2 + "\n");
    EXPECT_EQ(client.server_id, kId0);
    ASSERT_EQ(client.fallback_server_ids.size(), 2u);
    EXPECT_EQ(client.fallback_server_ids[1], kId2);
}

TEST_F(ConfigTest, DecodersAgreeOnFallbackScalar) {
    const auto client = decode_client_every_way(std::string("server_id: ") + kId0 +
                                                "\nfallback_server_ids: " + kId1 + "\n");
    ASSERT_EQ(client.fallback_server_ids.size(), 1u);
    EXPECT_EQ(client.fallback_server_ids[0], kId1);
}

TEST_F(ConfigTest, DecodersAgreeOnFallbackNull) {
    const auto client =
        decode_client_every_way(std::string("server_id: ") + kId0 + "\nfallback_server_ids:\n");
    EXPECT_EQ(client.server_id, kId0);
    EXPECT_TRUE(client.fallback_server_ids.empty());
}

TEST_F(ConfigTest, DecodersAgreeOnMixedSequenceAndExplicitFallbacks) {
    // The explicit key is additive on top of the list form; both readers must
    // append rather than one of them replacing.
    const auto client =
        decode_client_every_way(std::string("server_id:\n  - ") + kId0 + "\n  - " + kId1 +
                                "\nfallback_server_ids:\n  - " + kId2 + "\n");
    EXPECT_EQ(client.server_id, kId0);
    ASSERT_EQ(client.fallback_server_ids.size(), 2u);
    EXPECT_EQ(client.fallback_server_ids[0], kId1);
    EXPECT_EQ(client.fallback_server_ids[1], kId2);
}

TEST_F(ConfigTest, DecodersAgreeOnFullClientBody) {
    const auto client = decode_client_every_way(
        std::string("server_id: ") + kId0 + "\nfallback_server_ids:\n  - " + kId1 +
        "\npipe:\n  remote_host: pipe.example\n  remote_port: 4444\n"
        "forwards:\n  - local_port: 2222\n    remote_host: localhost\n    remote_port: 22\n"
        "  - local_port: 8080\n    remote_host: 10.0.0.5\n    remote_port: 80\n"
        "failover:\n  timeout_seconds: 12\n  prefer_primary_grace_seconds: 34\n"
        "socks5:\n  enabled: true\n  listen: 127.0.0.1:1085\n");

    ASSERT_TRUE(client.pipe_target.has_value());
    EXPECT_EQ(client.pipe_target->remote_host, "pipe.example");
    EXPECT_EQ(client.pipe_target->remote_port, 4444);
    ASSERT_EQ(client.forwards.size(), 2u);
    EXPECT_EQ(client.forwards[1].remote_host, "10.0.0.5");
    EXPECT_EQ(client.failover.timeout_seconds, 12u);
    EXPECT_EQ(client.failover.prefer_primary_grace_seconds, 34u);
    EXPECT_TRUE(client.socks5.enabled);
    EXPECT_EQ(client.socks5.listen, "127.0.0.1:1085");
}

TEST_F(ConfigTest, DecodersAgreeOnRejectingMapValuedFallback) {
    // Both readers must fail the same way, not one silently ignoring it.
    const std::string body =
        std::string("server_id: ") + kId0 + "\nfallback_server_ids:\n  some_key: " + kId1 + "\n";
    EXPECT_THROW((void)YAML::Load(body).as<ClientConfig>(), YAML::Exception);
    EXPECT_FALSE(Config::from_string("mode: client\ndata_dir: /tmp/decoder-agreement\nclient:\n" +
                                     indent_two(body))
                     .has_value());
    EXPECT_FALSE(
        Config::from_string("mode: client\ndata_dir: /tmp/decoder-agreement\n" + body).has_value());
}

TEST_F(ConfigTest, ClientEncodeRoundTripsThroughStandaloneDecoder) {
    // The `client:` block that convert<Config>::encode writes is produced by
    // convert<ClientConfig>::encode, so the standalone pair must round-trip.
    const Config populated = make_populated_client_config();
    const YAML::Node node = YAML::convert<ClientConfig>::encode(*populated.client);
    EXPECT_EQ(node.as<ClientConfig>(), *populated.client);
}
