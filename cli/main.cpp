#include <CLI/CLI.hpp>
#include <asio.hpp>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <string>
#include <thread>

#include "toxtunnel/app/tunnel_client.hpp"
#include "toxtunnel/app/tunnel_server.hpp"
#include "toxtunnel/tox/tox_adapter.hpp"
#include "toxtunnel/util/config.hpp"
#include "toxtunnel/util/logger.hpp"
#include "toxtunnel/util/qr_code.hpp"
#include "toxtunnel/util/systemd_notify.hpp"
#include "toxtunnel/util/windows_service.hpp"

namespace {

#ifndef TOXTUNNEL_VERSION
#define TOXTUNNEL_VERSION "0.0.0-dev"
#endif

constexpr const char* kVersion = TOXTUNNEL_VERSION;

/// Map from CLI string to LogLevel.
const std::map<std::string, toxtunnel::util::LogLevel> kLogLevelMap = {
    {"trace", toxtunnel::util::LogLevel::Trace}, {"debug", toxtunnel::util::LogLevel::Debug},
    {"info", toxtunnel::util::LogLevel::Info},   {"warn", toxtunnel::util::LogLevel::Warn},
    {"error", toxtunnel::util::LogLevel::Error},
};

/// Parse a log level string into a LogLevel enum value.
/// Returns true on success, false on failure.
bool parse_log_level(const std::string& str, toxtunnel::util::LogLevel& out) {
    auto it = kLogLevelMap.find(str);
    if (it != kLogLevelMap.end()) {
        out = it->second;
        return true;
    }
    return false;
}

/// Run the tunnel server until a signal is received.
int run_server(const toxtunnel::Config& config, bool run_as_service) {
    using Logger = toxtunnel::util::Logger;

    toxtunnel::app::TunnelServer server;

    auto init_result = server.initialize(config);
    if (!init_result.has_value()) {
        Logger::error("Failed to initialize server: {}", init_result.error());
        return 1;
    }

    Logger::info("Server initialized successfully");

    if (config.server) {
        Logger::info("Listening on TCP port {}", config.server->tcp_port);
    }

    // Print the Tox address so clients can connect
    auto tox_address = server.get_tox_address();
    if (!tox_address.empty()) {
        Logger::info("Server Tox address: {}", tox_address);
    }

    // Set up signal handling via asio
    asio::io_context signal_ctx;
    asio::signal_set signals(signal_ctx, SIGINT, SIGTERM);

    signals.async_wait([&server](const asio::error_code& ec, int signum) {
        if (!ec) {
            toxtunnel::util::Logger::info("Received signal {}, shutting down...", signum);
            server.stop();
        }
    });

    // Start the server (non-blocking)
    server.start();
    Logger::info("Server started");
    if (run_as_service) {
        toxtunnel::util::notify_service_ready();
    }

#if defined(_WIN32)
    // For Windows service, poll for stop requests
    if (run_as_service) {
        while (!toxtunnel::util::is_windows_service_stopping()) {
            signal_ctx.poll_one();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        server.stop();
    } else {
        signal_ctx.run();
    }
#else
    // Block on signal wait
    signal_ctx.run();
#endif

    if (run_as_service) {
        toxtunnel::util::notify_service_stopping();
    }
    Logger::info("Server stopped");
    return 0;
}

/// Run the tunnel client until a signal is received.
int run_client(const toxtunnel::Config& config, bool run_as_service) {
    using Logger = toxtunnel::util::Logger;

    toxtunnel::app::TunnelClient client;

    auto init_result = client.initialize(config);
    if (!init_result.has_value()) {
        Logger::error("Failed to initialize client: {}", init_result.error());
        return 1;
    }

    Logger::info("Client initialized successfully");

    if (config.client && !config.client->server_id.empty()) {
        Logger::info("Connecting to server: {}", config.client->server_id);
    }

    // Set up signal handling via asio
    asio::io_context signal_ctx;
    asio::signal_set signals(signal_ctx, SIGINT, SIGTERM);

    signals.async_wait([&client](const asio::error_code& ec, int signum) {
        if (!ec) {
            toxtunnel::util::Logger::info("Received signal {}, shutting down...", signum);
            client.stop();
        }
    });

    // Start the client (non-blocking)
    client.start();
    Logger::info("Client started");
    if (run_as_service) {
        toxtunnel::util::notify_service_ready();
    }

    std::thread signal_thread([&signal_ctx] { signal_ctx.run(); });

#if defined(_WIN32)
    // For Windows service, poll for stop requests
    if (run_as_service) {
        while (!toxtunnel::util::is_windows_service_stopping() && client.is_running()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (client.is_running()) {
            client.stop();
        }
        signal_ctx.stop();
    } else {
        client.wait_until_stopped();
        signal_ctx.stop();
    }
#else
    client.wait_until_stopped();
    signal_ctx.stop();
#endif

    if (signal_thread.joinable()) {
        signal_thread.join();
    }

    if (run_as_service) {
        toxtunnel::util::notify_service_stopping();
    }
    Logger::info("Client stopped");
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    using namespace toxtunnel;
    using Logger = util::Logger;

    // -----------------------------------------------------------------------
    // CLI argument parsing
    // -----------------------------------------------------------------------
    CLI::App app{"ToxTunnel - TCP Tunnel over Tox"};

    std::string config_path;
    std::string mode_str;
    std::string data_dir;
    std::string log_level_str;
    uint16_t port = 0;
    std::string server_id;
    std::string pipe_target;
    std::string print_id_data_dir;
    bool print_id_qr = false;
    bool print_id_color = false;
    bool run_as_service = false;

    auto* print_id_cmd = app.add_subcommand("print-id", "Print local Tox ID");
    print_id_cmd->add_option("-d,--data-dir", print_id_data_dir,
                             "Data directory for loading/creating local Tox identity");
    print_id_cmd->add_flag("--qr", print_id_qr, "Render Tox ID as terminal QR code");
    print_id_cmd->add_flag("--color", print_id_color, "Use ANSI colors with QR output");

    app.add_option("-c,--config", config_path, "Path to YAML config file");

    app.add_option("-m,--mode", mode_str, "Operating mode: server or client")
        ->check(CLI::IsMember({"server", "client"}));

    app.add_option("-d,--data-dir", data_dir, "Override data directory");

    app.add_option("-l,--log-level", log_level_str, "Override log level")
        ->check(CLI::IsMember({"trace", "debug", "info", "warn", "error"}));

    app.add_option("-p,--port", port, "Override TCP port (server mode)")
        ->check(CLI::Range(static_cast<uint16_t>(1), static_cast<uint16_t>(65535)));

    app.add_option("--server-id", server_id, "Override server Tox ID (client mode)");
    app.add_option("--pipe", pipe_target, "Pipe mode target host:port (client mode)");
    app.add_flag("--service", run_as_service, "Run as background service");

    app.set_version_flag("-v,--version", kVersion);

    CLI11_PARSE(app, argc, argv);

    if (*print_id_cmd) {
        if (print_id_color && !print_id_qr) {
            std::cerr << "--color requires --qr\n";
            return 1;
        }

        std::filesystem::path id_data_dir;
        if (!print_id_data_dir.empty()) {
            id_data_dir = print_id_data_dir;
        } else {
            id_data_dir = Config::default_client().data_dir;
        }

        auto tox_id_result = tox::ToxAdapter::get_tox_id_only(id_data_dir);
        if (!tox_id_result.has_value()) {
            std::cerr << "Failed to load Tox ID: " << tox_id_result.error() << "\n";
            return 1;
        }

        if (!print_id_qr) {
            std::cout << tox_id_result.value() << "\n";
            return 0;
        }

        auto qr_result = util::generate_qr_terminal(tox_id_result.value(), print_id_color);
        if (!qr_result.has_value()) {
            std::cerr << "Failed to render QR: " << qr_result.error() << "\n";
            return 1;
        }

        std::cout << qr_result.value();
        std::cout << tox_id_result.value() << "\n";
        return 0;
    }

    // -----------------------------------------------------------------------
    // Load configuration
    // -----------------------------------------------------------------------
    Config config;

    if (!config_path.empty()) {
        // Explicit config file specified
        auto result = Config::from_file(config_path);
        if (!result.has_value()) {
            // Logger not initialized yet, use std::cerr for bootstrap errors
            std::cerr << "Error loading config: " << result.error() << "\n";
            return 1;
        }
        config = std::move(result).value();
    } else {
        // No config specified; use defaults based on mode
        if (mode_str == "client") {
            config = Config::default_client();
        } else {
            config = Config::default_server();
        }
    }

    // -----------------------------------------------------------------------
    // Apply CLI overrides
    // -----------------------------------------------------------------------
    Config overrides;
    bool has_overrides = false;

    if (!mode_str.empty()) {
        if (mode_str == "server") {
            overrides.mode = Mode::Server;
            overrides.server = ServerConfig{};
        } else {
            overrides.mode = Mode::Client;
            overrides.client = ClientConfig{};
        }
        has_overrides = true;
    } else {
        // Keep same mode as loaded config so merge_cli_overrides does not
        // interpret a default Mode::Server as an intentional override.
        overrides.mode = config.mode;
    }

    if (!data_dir.empty()) {
        overrides.data_dir = data_dir;
        has_overrides = true;
    }

    if (!log_level_str.empty()) {
        util::LogLevel level{};
        if (parse_log_level(log_level_str, level)) {
            overrides.logging.level = level;
            has_overrides = true;
        }
    }

    if (port != 0) {
        if (!overrides.server) {
            overrides.server = ServerConfig{};
        }
        overrides.server->tcp_port = port;
        has_overrides = true;
    }

    if (!server_id.empty()) {
        if (!overrides.client) {
            overrides.client = ClientConfig{};
        }
        overrides.client->server_id = server_id;
        has_overrides = true;
    }

    if (!pipe_target.empty()) {
        auto pipe_result = parse_pipe_target(pipe_target);
        if (!pipe_result) {
            std::cerr << "Configuration error: " << pipe_result.error() << "\n";
            return 1;
        }
        if (!overrides.client) {
            overrides.client = ClientConfig{};
        }
        overrides.client->pipe_target = pipe_result.value();
        has_overrides = true;
    }

    if (has_overrides) {
        config.merge_cli_overrides(overrides);
    }

    // -----------------------------------------------------------------------
    // Validate configuration
    // -----------------------------------------------------------------------
    auto validation = config.validate();
    if (!validation.has_value()) {
        std::cerr << "Configuration error: " << validation.error() << "\n";
        return 1;
    }

    // -----------------------------------------------------------------------
    // Initialize logging
    // -----------------------------------------------------------------------
    Logger::init("toxtunnel");
    Logger::set_level(config.logging.level);

    if (config.logging.file.has_value()) {
        Logger::add_file_sink(*config.logging.file);
    }

    Logger::info("ToxTunnel v{} starting in {} mode", kVersion,
                 config.is_server() ? "server" : "client");
    Logger::debug("Data directory: {}", config.data_dir.string());

    // -----------------------------------------------------------------------
    // Run the appropriate mode
    // -----------------------------------------------------------------------
    int exit_code = 0;

#if defined(_WIN32)
    // On Windows, use service framework if --service is specified
    if (run_as_service) {
        exit_code = util::run_windows_service_main("ToxTunnel", [&]() {
            if (config.is_server()) {
                return run_server(config, true);
            } else {
                return run_client(config, true);
            }
        });
    } else {
        if (config.is_server()) {
            exit_code = run_server(config, false);
        } else {
            exit_code = run_client(config, false);
        }
    }
#else
    if (config.is_server()) {
        exit_code = run_server(config, run_as_service);
    } else {
        exit_code = run_client(config, run_as_service);
    }
#endif

    Logger::info("ToxTunnel exiting with code {}", exit_code);
    Logger::shutdown();

    return exit_code;
}
