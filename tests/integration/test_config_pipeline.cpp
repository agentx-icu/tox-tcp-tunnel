// Integration tests for the full configuration pipeline: YAML loading,
// validation, CLI override merging, serialization round-trips, and error
// handling.

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "toxtunnel/util/config.hpp"

namespace toxtunnel::integration {
namespace {

// Valid 76-character hex Tox ID (all zeros -- checksum is valid).
constexpr const char* kValidToxId =
    "0000000000000000000000000000000000000000000000000000000000000000000000000000";

// Valid 64-character hex public key.
constexpr const char* kValidPublicKey =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class ConfigPipelineTest : public ::testing::Test {
   protected:
    /// Create a temporary file path for testing.
    std::filesystem::path make_temp_path() {
        const auto unique_suffix =
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
            std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
        return std::filesystem::temp_directory_path() /
               ("toxtunnel_test_config_" + unique_suffix + ".yaml");
    }

    /// Register a path for automatic cleanup.
    std::filesystem::path track_temp(std::filesystem::path p) {
        temp_files_.push_back(p);
        return p;
    }

    void TearDown() override {
        for (const auto& path : temp_files_) {
            std::filesystem::remove(path);
        }
    }

    std::vector<std::filesystem::path> temp_files_;
};

// ---------------------------------------------------------------------------
// 1. ServerConfigYamlRoundTrip
// ---------------------------------------------------------------------------

TEST_F(ConfigPipelineTest, ServerConfigYamlRoundTrip) {
    const std::string yaml = std::string(R"(
mode: server
data_dir: /var/lib/toxtunnel
tcp_port: 44000
udp_enabled: true
logging:
  level: debug
  file: /var/log/toxtunnel.log
)");

    // First load
    auto result1 = Config::from_string(yaml);
    ASSERT_TRUE(result1.has_value()) << result1.error();
    const Config& config1 = result1.value();

    // Validate
    auto validation = config1.validate();
    ASSERT_TRUE(validation.has_value()) << validation.error();

    // Serialize back to YAML
    std::string serialized = config1.to_yaml();
    EXPECT_FALSE(serialized.empty());

    // Second load from the serialized YAML
    auto result2 = Config::from_string(serialized);
    ASSERT_TRUE(result2.has_value()) << result2.error();
    const Config& config2 = result2.value();

    // Verify equality across the round-trip
    EXPECT_EQ(config1.mode, config2.mode);
    EXPECT_EQ(config1.data_dir, config2.data_dir);
    EXPECT_EQ(config1.logging, config2.logging);
    ASSERT_TRUE(config2.server.has_value());
    EXPECT_EQ(config1.server->tcp_port, config2.server->tcp_port);
    EXPECT_EQ(config1.server->udp_enabled, config2.server->udp_enabled);
    EXPECT_EQ(config1, config2);
}

// ---------------------------------------------------------------------------
// 2. ClientConfigYamlRoundTrip
// ---------------------------------------------------------------------------

TEST_F(ConfigPipelineTest, ClientConfigYamlRoundTrip) {
    const std::string yaml = std::string("mode: client\n") +
                             "data_dir: /home/user/.config/toxtunnel\n" +
                             "server_id: " + kValidToxId + "\n" +
                             "forwards:\n"
                             "  - local_port: 2222\n"
                             "    remote_host: localhost\n"
                             "    remote_port: 22\n"
                             "  - local_port: 8080\n"
                             "    remote_host: 192.168.1.100\n"
                             "    remote_port: 80\n"
                             "logging:\n"
                             "  level: warn\n";

    // First load
    auto result1 = Config::from_string(yaml);
    ASSERT_TRUE(result1.has_value()) << result1.error();
    const Config& config1 = result1.value();

    // Validate
    auto validation = config1.validate();
    ASSERT_TRUE(validation.has_value()) << validation.error();

    // Serialize back to YAML
    std::string serialized = config1.to_yaml();
    EXPECT_FALSE(serialized.empty());

    // Second load from the serialized YAML
    auto result2 = Config::from_string(serialized);
    ASSERT_TRUE(result2.has_value()) << result2.error();
    const Config& config2 = result2.value();

    // Verify equality across the round-trip
    EXPECT_EQ(config1.mode, config2.mode);
    EXPECT_EQ(config1.data_dir, config2.data_dir);
    EXPECT_EQ(config1.logging, config2.logging);
    ASSERT_TRUE(config2.client.has_value());
    EXPECT_EQ(config1.client->server_id, config2.client->server_id);
    ASSERT_EQ(config1.client->forwards.size(), config2.client->forwards.size());
    for (std::size_t i = 0; i < config1.client->forwards.size(); ++i) {
        EXPECT_EQ(config1.client->forwards[i], config2.client->forwards[i]);
    }
    EXPECT_EQ(config1, config2);
}

// ---------------------------------------------------------------------------
// 3. ConfigFileSaveAndLoad
// ---------------------------------------------------------------------------

TEST_F(ConfigPipelineTest, ConfigFileSaveAndLoad) {
    Config original = Config::default_server();
    original.data_dir = "/test/save_load";
    original.server->tcp_port = 55555;
    original.server->udp_enabled = false;
    original.logging.level = util::LogLevel::Error;
    original.logging.file = "/tmp/toxtunnel_test.log";

    auto path = track_temp(make_temp_path());

    // Save to file
    auto save_result = original.save(path);
    ASSERT_TRUE(save_result.has_value()) << save_result.error();
    EXPECT_TRUE(std::filesystem::exists(path));

    // Load from file
    auto load_result = Config::from_file(path);
    ASSERT_TRUE(load_result.has_value()) << load_result.error();
    const Config& loaded = load_result.value();

    // Verify equality
    EXPECT_EQ(original.mode, loaded.mode);
    EXPECT_EQ(original.data_dir, loaded.data_dir);
    EXPECT_EQ(original.logging, loaded.logging);
    ASSERT_TRUE(loaded.server.has_value());
    EXPECT_EQ(original.server->tcp_port, loaded.server->tcp_port);
    EXPECT_EQ(original.server->udp_enabled, loaded.server->udp_enabled);
    EXPECT_EQ(original, loaded);
}

// ---------------------------------------------------------------------------
// 4. MergeCliOverrides
// ---------------------------------------------------------------------------

TEST_F(ConfigPipelineTest, MergeCliOverrides) {
    // Base configuration loaded from YAML
    const std::string base_yaml = std::string(R"(
mode: server
data_dir: /var/lib/toxtunnel
tcp_port: 33445
udp_enabled: true
logging:
  level: info
)");

    auto base_result = Config::from_string(base_yaml);
    ASSERT_TRUE(base_result.has_value()) << base_result.error();
    Config base = base_result.value();

    // Verify original values
    EXPECT_EQ(base.data_dir, "/var/lib/toxtunnel");
    EXPECT_EQ(base.logging.level, util::LogLevel::Info);
    ASSERT_TRUE(base.server.has_value());
    EXPECT_EQ(base.server->tcp_port, 33445);
    EXPECT_TRUE(base.server->udp_enabled);

    // Create an overrides config
    Config overrides;
    overrides.mode = Mode::Server;
    overrides.data_dir = "/override/path";
    overrides.logging.level = util::LogLevel::Debug;
    overrides.logging.file = "/var/log/override.log";
    overrides.server = ServerConfig{};
    overrides.server->tcp_port = 443;

    // Merge
    base.merge_cli_overrides(overrides);

    // Overridden values should be updated
    EXPECT_EQ(base.data_dir, "/override/path");
    EXPECT_EQ(base.logging.level, util::LogLevel::Debug);
    ASSERT_TRUE(base.logging.file.has_value());
    EXPECT_EQ(*base.logging.file, "/var/log/override.log");
    ASSERT_TRUE(base.server.has_value());
    EXPECT_EQ(base.server->tcp_port, 443);

    // Non-overridden values should remain unchanged
    EXPECT_EQ(base.mode, Mode::Server);
    EXPECT_TRUE(base.server->udp_enabled);
}

// ---------------------------------------------------------------------------
// 5. DefaultConfigs
// ---------------------------------------------------------------------------

TEST_F(ConfigPipelineTest, DefaultConfigs) {
    // default_server() should produce a valid config
    {
        Config server_cfg = Config::default_server();
        EXPECT_TRUE(server_cfg.is_server());
        EXPECT_FALSE(server_cfg.is_client());
        ASSERT_TRUE(server_cfg.server.has_value());
        EXPECT_FALSE(server_cfg.client.has_value());

        auto validation = server_cfg.validate();
        EXPECT_TRUE(validation.has_value()) << validation.error();
    }

    // default_client() should produce a valid structure (validation may fail
    // because the default has an empty server_id, which is required).
    {
        Config client_cfg = Config::default_client();
        EXPECT_TRUE(client_cfg.is_client());
        EXPECT_FALSE(client_cfg.is_server());
        ASSERT_TRUE(client_cfg.client.has_value());
        EXPECT_FALSE(client_cfg.server.has_value());

        // The default client has an empty server_id, so validation is expected
        // to fail.  This verifies that default_client() at least produces a
        // structurally sound Config.
        auto validation = client_cfg.validate();
        EXPECT_FALSE(validation.has_value());
    }
}

// ---------------------------------------------------------------------------
// 6. ValidationErrors
// ---------------------------------------------------------------------------

TEST_F(ConfigPipelineTest, ValidationErrorClientModeWithoutClientConfig) {
    // Programmatically construct an invalid config: client mode but no client
    // section.
    Config cfg;
    cfg.mode = Mode::Client;
    cfg.data_dir = "/some/path";
    cfg.client.reset();

    auto validation = cfg.validate();
    EXPECT_FALSE(validation.has_value());
}

TEST_F(ConfigPipelineTest, ValidationErrorServerModeWithoutServerConfig) {
    // Programmatically construct an invalid config: server mode but no server
    // section.
    Config cfg;
    cfg.mode = Mode::Server;
    cfg.data_dir = "/some/path";
    cfg.server.reset();

    auto validation = cfg.validate();
    EXPECT_FALSE(validation.has_value());
}

TEST_F(ConfigPipelineTest, ValidationErrorClientInvalidServerIdLength) {
    // server_id that is not 76 hex characters
    const std::string yaml = R"(
mode: client
data_dir: /tmp
server_id: abcdef
forwards:
  - local_port: 2222
    remote_host: localhost
    remote_port: 22
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    auto validation = result.value().validate();
    EXPECT_FALSE(validation.has_value());
}

TEST_F(ConfigPipelineTest, ValidationErrorClientForwardRuleZeroPort) {
    // A client config with a forward rule that has a zero local_port should
    // fail validation.
    Config cfg;
    cfg.mode = Mode::Client;
    cfg.data_dir = "/tmp";
    cfg.client = ClientConfig{};
    cfg.client->server_id = kValidToxId;
    cfg.client->forwards.push_back(ForwardRule{0, "localhost", 22});

    auto validation = cfg.validate();
    EXPECT_FALSE(validation.has_value());
}

// ---------------------------------------------------------------------------
// 7. CompleteServerConfig
// ---------------------------------------------------------------------------

TEST_F(ConfigPipelineTest, CompleteServerConfig) {
    const std::string yaml = std::string(R"(
mode: server
data_dir: /var/lib/toxtunnel
tcp_port: 44000
udp_enabled: false
bootstrap_nodes:
  - address: node1.tox.chat
    port: 33445
    public_key: )") + kValidPublicKey +
                             R"(
  - address: node2.tox.chat
    port: 33446
    public_key: )" + kValidPublicKey +
                             R"(
rules_file: /etc/toxtunnel/rules.yaml
logging:
  level: trace
  file: /var/log/toxtunnel_server.log
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    const Config& cfg = result.value();

    // Mode
    EXPECT_EQ(cfg.mode, Mode::Server);
    EXPECT_TRUE(cfg.is_server());

    // Data dir
    EXPECT_EQ(cfg.data_dir, "/var/lib/toxtunnel");

    // Server config
    ASSERT_TRUE(cfg.server.has_value());
    EXPECT_EQ(cfg.server->tcp_port, 44000);
    EXPECT_FALSE(cfg.server->udp_enabled);

    // Bootstrap nodes
    ASSERT_EQ(cfg.server->bootstrap_nodes.size(), 2u);

    EXPECT_EQ(cfg.server->bootstrap_nodes[0].address, "node1.tox.chat");
    EXPECT_EQ(cfg.server->bootstrap_nodes[0].port, 33445);
    EXPECT_EQ(cfg.server->bootstrap_nodes[0].public_key, kValidPublicKey);

    EXPECT_EQ(cfg.server->bootstrap_nodes[1].address, "node2.tox.chat");
    EXPECT_EQ(cfg.server->bootstrap_nodes[1].port, 33446);
    EXPECT_EQ(cfg.server->bootstrap_nodes[1].public_key, kValidPublicKey);

    // Rules file
    ASSERT_TRUE(cfg.server->rules_file.has_value());
    EXPECT_EQ(*cfg.server->rules_file, "/etc/toxtunnel/rules.yaml");

    // Logging
    EXPECT_EQ(cfg.logging.level, util::LogLevel::Trace);
    ASSERT_TRUE(cfg.logging.file.has_value());
    EXPECT_EQ(*cfg.logging.file, "/var/log/toxtunnel_server.log");

    // Should not have client config
    EXPECT_FALSE(cfg.client.has_value());

    // Overall validation
    auto validation = cfg.validate();
    EXPECT_TRUE(validation.has_value()) << validation.error();
}

// ---------------------------------------------------------------------------
// 8. CompleteClientConfig
// ---------------------------------------------------------------------------

TEST_F(ConfigPipelineTest, CompleteClientConfig) {
    const std::string yaml = std::string("mode: client\n") +
                             "data_dir: /home/user/.config/toxtunnel\n" +
                             "server_id: " + kValidToxId + "\n" +
                             "forwards:\n"
                             "  - local_port: 2222\n"
                             "    remote_host: localhost\n"
                             "    remote_port: 22\n"
                             "  - local_port: 8080\n"
                             "    remote_host: 192.168.1.100\n"
                             "    remote_port: 80\n"
                             "  - local_port: 3306\n"
                             "    remote_host: db.internal\n"
                             "    remote_port: 3306\n"
                             "logging:\n"
                             "  level: warn\n"
                             "  file: /home/user/.local/log/toxtunnel_client.log\n";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();
    const Config& cfg = result.value();

    // Mode
    EXPECT_EQ(cfg.mode, Mode::Client);
    EXPECT_TRUE(cfg.is_client());

    // Data dir
    EXPECT_EQ(cfg.data_dir, "/home/user/.config/toxtunnel");

    // Client config
    ASSERT_TRUE(cfg.client.has_value());
    EXPECT_EQ(cfg.client->server_id, kValidToxId);

    // Forward rules
    ASSERT_EQ(cfg.client->forwards.size(), 3u);

    EXPECT_EQ(cfg.client->forwards[0].local_port, 2222);
    EXPECT_EQ(cfg.client->forwards[0].remote_host, "localhost");
    EXPECT_EQ(cfg.client->forwards[0].remote_port, 22);

    EXPECT_EQ(cfg.client->forwards[1].local_port, 8080);
    EXPECT_EQ(cfg.client->forwards[1].remote_host, "192.168.1.100");
    EXPECT_EQ(cfg.client->forwards[1].remote_port, 80);

    EXPECT_EQ(cfg.client->forwards[2].local_port, 3306);
    EXPECT_EQ(cfg.client->forwards[2].remote_host, "db.internal");
    EXPECT_EQ(cfg.client->forwards[2].remote_port, 3306);

    // Logging
    EXPECT_EQ(cfg.logging.level, util::LogLevel::Warn);
    ASSERT_TRUE(cfg.logging.file.has_value());
    EXPECT_EQ(*cfg.logging.file, "/home/user/.local/log/toxtunnel_client.log");

    // Should not have server config
    EXPECT_FALSE(cfg.server.has_value());

    // Overall validation
    auto validation = cfg.validate();
    EXPECT_TRUE(validation.has_value()) << validation.error();
}

TEST_F(ConfigPipelineTest, CanonicalSharedToxConfigRoundTrip) {
    const std::string yaml = std::string(R"(
mode: server
data_dir: /var/lib/toxtunnel
logging:
  level: info
tox:
  udp_enabled: true
  tcp_port: 44000
  bootstrap_mode: lan
  bootstrap_nodes:
    - address: 192.168.1.50
      port: 33445
      public_key: )") + kValidPublicKey +
                             R"(
server:
  rules_file: /etc/toxtunnel/rules.yaml
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const Config& cfg = result.value();
    EXPECT_EQ(cfg.mode, Mode::Server);
    EXPECT_TRUE(cfg.tox.udp_enabled);
    EXPECT_EQ(cfg.tox.tcp_port, 44000);
    EXPECT_EQ(cfg.tox.bootstrap_mode, BootstrapMode::Lan);
    ASSERT_EQ(cfg.tox.bootstrap_nodes.size(), 1u);
    EXPECT_EQ(cfg.tox.bootstrap_nodes[0].address, "192.168.1.50");
    ASSERT_TRUE(cfg.server.has_value());
    ASSERT_TRUE(cfg.server->rules_file.has_value());
    EXPECT_EQ(*cfg.server->rules_file, "/etc/toxtunnel/rules.yaml");

    std::string serialized = cfg.to_yaml();
    EXPECT_TRUE(serialized.find("tox:") != std::string::npos);
    EXPECT_TRUE(serialized.find("bootstrap_mode: lan") != std::string::npos);

    auto round_trip = Config::from_string(serialized);
    ASSERT_TRUE(round_trip.has_value()) << round_trip.error();
    EXPECT_EQ(round_trip.value().tox.bootstrap_mode, BootstrapMode::Lan);
    EXPECT_EQ(round_trip.value().tox.tcp_port, 44000);
}

TEST_F(ConfigPipelineTest, LegacyServerBootstrapFieldsNormalizeToSharedToxConfig) {
    const std::string yaml = std::string(R"(
mode: server
data_dir: /var/lib/toxtunnel
server:
  tcp_port: 44000
  udp_enabled: false
  bootstrap_nodes:
    - address: node1.tox.chat
      port: 33445
      public_key: )") + kValidPublicKey +
                             R"(
  rules_file: /etc/toxtunnel/rules.yaml
)";

    auto result = Config::from_string(yaml);
    ASSERT_TRUE(result.has_value()) << result.error();

    const Config& cfg = result.value();
    EXPECT_EQ(cfg.tox.tcp_port, 44000);
    EXPECT_FALSE(cfg.tox.udp_enabled);
    ASSERT_EQ(cfg.tox.bootstrap_nodes.size(), 1u);
    EXPECT_EQ(cfg.tox.bootstrap_nodes[0].address, "node1.tox.chat");
    ASSERT_TRUE(cfg.server.has_value());
    ASSERT_TRUE(cfg.server->rules_file.has_value());
    EXPECT_EQ(*cfg.server->rules_file, "/etc/toxtunnel/rules.yaml");
}

}  // namespace
}  // namespace toxtunnel::integration
