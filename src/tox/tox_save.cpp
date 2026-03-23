#include "toxtunnel/tox/tox_save.hpp"

#include <cerrno>
#include <cstring>
#include <fstream>

#include "toxtunnel/util/logger.hpp"

namespace toxtunnel::tox {

// ===========================================================================
// Internal helpers
// ===========================================================================

namespace {

/// Convert a TOX_ERR_NEW value to a human-readable string.
std::string local_tox_err_new_to_string(TOX_ERR_NEW err) {
    switch (err) {
        case TOX_ERR_NEW_OK:
            return "OK";
        case TOX_ERR_NEW_NULL:
            return "a parameter was NULL (internal error)";
        case TOX_ERR_NEW_MALLOC:
            return "memory allocation failed";
        case TOX_ERR_NEW_PORT_ALLOC:
            return "unable to bind to a port";
        case TOX_ERR_NEW_PROXY_BAD_TYPE:
            return "invalid proxy type";
        case TOX_ERR_NEW_PROXY_BAD_HOST:
            return "invalid proxy host";
        case TOX_ERR_NEW_PROXY_BAD_PORT:
            return "invalid proxy port";
        case TOX_ERR_NEW_PROXY_NOT_FOUND:
            return "proxy host could not be resolved";
        case TOX_ERR_NEW_LOAD_ENCRYPTED:
            return "save data is encrypted (not supported)";
        case TOX_ERR_NEW_LOAD_BAD_FORMAT:
            return "save data has an invalid format";
        default:
            return "unknown tox_new error (" + std::to_string(static_cast<int>(err)) + ")";
    }
}

/// RAII wrapper for Tox_Options that calls tox_options_free on destruction.
struct ToxOptionsGuard {
    Tox_Options* opts = nullptr;
    bool owned = false;

    ~ToxOptionsGuard() {
        if (owned && opts) {
            tox_options_free(opts);
        }
    }
};

}  // anonymous namespace

// ===========================================================================
// save_tox_data
// ===========================================================================

util::Expected<Success, std::string> save_tox_data(const Tox* tox,
                                                   const std::filesystem::path& filepath) {
    if (!tox) {
        return util::unexpected(std::string("cannot save: Tox instance is null"));
    }

    // Obtain the serialised state from toxcore.
    const std::size_t size = tox_get_savedata_size(tox);
    std::vector<uint8_t> data(size);
    tox_get_savedata(tox, data.data());

    // Write to a temporary file first, then rename for atomicity.
    // This prevents a crash mid-write from corrupting the save file.
    std::filesystem::path tmp_path = filepath;
    tmp_path += ".tmp";

    // Ensure the parent directory exists.
    std::error_code fs_ec;
    if (filepath.has_parent_path()) {
        std::filesystem::create_directories(filepath.parent_path(), fs_ec);
        if (fs_ec) {
            return util::unexpected(std::string("failed to create directory '") +
                                    filepath.parent_path().string() + "': " + fs_ec.message());
        }
    }

    // Write bytes to the temp file.
    {
        std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            return util::unexpected(std::string("failed to open '") + tmp_path.string() +
                                    "' for writing: " + std::strerror(errno));
        }
        ofs.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
        if (!ofs) {
            return util::unexpected(std::string("failed to write save data to '") +
                                    tmp_path.string() + "'");
        }
    }  // ofs is closed here

    // Atomic rename.
    std::filesystem::rename(tmp_path, filepath, fs_ec);
    if (fs_ec) {
        // Best-effort cleanup of the temp file.
        std::filesystem::remove(tmp_path);
        return util::unexpected(std::string("failed to rename temp file to '") + filepath.string() +
                                "': " + fs_ec.message());
    }

    util::Logger::debug("saved Tox state ({} bytes) to '{}'", size, filepath.string());
    return Success{};
}

// ===========================================================================
// load_tox_data
// ===========================================================================

util::Expected<std::vector<uint8_t>, std::string> load_tox_data(
    const std::filesystem::path& filepath) {
    // Check existence up-front for a clear error message.
    std::error_code fs_ec;
    if (!std::filesystem::exists(filepath, fs_ec)) {
        if (fs_ec) {
            return util::unexpected(std::string("failed to stat '") + filepath.string() +
                                    "': " + fs_ec.message());
        }
        return util::unexpected(std::string("save file '") + filepath.string() +
                                "' does not exist");
    }

    // Get file size.
    auto file_size = std::filesystem::file_size(filepath, fs_ec);
    if (fs_ec) {
        return util::unexpected(std::string("failed to get file size of '") + filepath.string() +
                                "': " + fs_ec.message());
    }

    if (file_size == 0) {
        return util::unexpected(std::string("save file '") + filepath.string() + "' is empty");
    }

    // Read the entire file into a byte vector.
    std::ifstream ifs(filepath, std::ios::binary);
    if (!ifs) {
        return util::unexpected(std::string("failed to open '") + filepath.string() +
                                "' for reading: " + std::strerror(errno));
    }

    std::vector<uint8_t> data(static_cast<std::size_t>(file_size));
    ifs.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(file_size));
    if (!ifs) {
        return util::unexpected(std::string("failed to read save data from '") + filepath.string() +
                                "'");
    }

    util::Logger::debug("loaded Tox state ({} bytes) from '{}'", data.size(), filepath.string());
    return data;
}

// ===========================================================================
// create_tox_from_savedata
// ===========================================================================

util::Expected<ToxPtr, std::string> create_tox_from_savedata(const std::vector<uint8_t>& savedata,
                                                             Tox_Options* options) {
    if (savedata.empty()) {
        return util::unexpected(std::string("save data is empty"));
    }

    ToxOptionsGuard guard;

    // If the caller did not provide options, allocate default ones.
    if (!options) {
        TOX_ERR_OPTIONS_NEW opts_err;
        guard.opts = tox_options_new(&opts_err);
        if (!guard.opts) {
            return util::unexpected(std::string("failed to allocate Tox_Options"));
        }
        guard.owned = true;
        options = guard.opts;
    }

    // Configure the save-data fields on the options struct.
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_length(options, savedata.size());
    tox_options_set_savedata_data(options, savedata.data(), savedata.size());

    // Create the Tox instance.
    TOX_ERR_NEW err = TOX_ERR_NEW_OK;
    Tox* tox = tox_new(options, &err);
    if (!tox || err != TOX_ERR_NEW_OK) {
        return util::unexpected(std::string("tox_new failed: ") + local_tox_err_new_to_string(err));
    }

    util::Logger::info("restored Tox instance from save data ({} bytes)", savedata.size());
    return ToxPtr(tox);
}

// ===========================================================================
// create_new_tox
// ===========================================================================

util::Expected<ToxPtr, std::string> create_new_tox(Tox_Options* options) {
    ToxOptionsGuard guard;

    // If the caller did not provide options, allocate default ones.
    if (!options) {
        TOX_ERR_OPTIONS_NEW opts_err;
        guard.opts = tox_options_new(&opts_err);
        if (!guard.opts) {
            return util::unexpected(std::string("failed to allocate Tox_Options"));
        }
        guard.owned = true;
        options = guard.opts;
    }

    // Ensure save-data is not set (fresh identity).
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_NONE);
    tox_options_set_savedata_data(options, nullptr, 0);
    tox_options_set_savedata_length(options, 0);

    // Create the Tox instance.
    TOX_ERR_NEW err = TOX_ERR_NEW_OK;
    Tox* tox = tox_new(options, &err);
    if (!tox || err != TOX_ERR_NEW_OK) {
        return util::unexpected(std::string("tox_new failed: ") + local_tox_err_new_to_string(err));
    }

    util::Logger::info("created new Tox instance with fresh identity");
    return ToxPtr(tox);
}

// ===========================================================================
// create_or_load_tox
// ===========================================================================

util::Expected<ToxPtr, std::string> create_or_load_tox(const std::filesystem::path& filepath,
                                                       Tox_Options* options) {
    std::error_code fs_ec;
    bool file_exists = std::filesystem::exists(filepath, fs_ec);

    ToxPtr tox_instance;

    if (file_exists && !fs_ec) {
        // Attempt to load from existing save file.
        auto load_result = load_tox_data(filepath);
        if (!load_result) {
            return util::unexpected(std::string("failed to load save file: ") +
                                    load_result.error());
        }

        auto create_result = create_tox_from_savedata(load_result.value(), options);
        if (!create_result) {
            return util::unexpected(std::string("failed to restore Tox from save data: ") +
                                    create_result.error());
        }

        tox_instance = std::move(create_result.value());
        util::Logger::info("loaded existing Tox identity from '{}'", filepath.string());
    } else {
        // No save file; create a fresh identity.
        auto create_result = create_new_tox(options);
        if (!create_result) {
            return util::unexpected(create_result.error());
        }

        tox_instance = std::move(create_result.value());
        util::Logger::info("created new Tox identity (save file '{}' will be created)",
                           filepath.string());
    }

    // Always persist the state so the file exists on the next startup.
    auto save_result = save_tox_data(tox_instance.get(), filepath);
    if (!save_result) {
        return util::unexpected(std::string("failed to save initial state: ") +
                                save_result.error());
    }

    return tox_instance;
}

}  // namespace toxtunnel::tox
