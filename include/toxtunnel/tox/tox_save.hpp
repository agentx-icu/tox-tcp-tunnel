#pragma once

#include <toxcore/tox.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "toxtunnel/util/expected.hpp"

namespace toxtunnel::tox {

// ---------------------------------------------------------------------------
// Tox save-data helpers
// ---------------------------------------------------------------------------

/// Custom deleter for Tox instances returned by the factory functions.
struct ToxDeleter {
    void operator()(Tox* t) const noexcept {
        if (t) {
            tox_kill(t);
        }
    }
};

/// Owning smart pointer to a Tox instance.
using ToxPtr = std::unique_ptr<Tox, ToxDeleter>;

/// Lightweight tag type representing a successful void operation.
struct Success {};

// ---------------------------------------------------------------------------
// Save / Load
// ---------------------------------------------------------------------------

/// Serialise the current Tox state to a file.
///
/// Uses `tox_get_savedata()` to obtain the raw bytes and writes them
/// atomically (write-to-temp + rename) so that a crash during the write
/// does not corrupt the existing save file.
///
/// @param tox       A valid, non-null Tox instance.
/// @param filepath  Destination path for the save file.
/// @return          Success on success, or an error description string.
[[nodiscard]] util::Expected<Success, std::string> save_tox_data(
    const Tox* tox, const std::filesystem::path& filepath);

/// Load Tox save-data from a file.
///
/// Reads the raw bytes previously written by `save_tox_data()`.
///
/// @param filepath  Path to an existing save file.
/// @return          The save-data bytes on success, or an error description.
[[nodiscard]] util::Expected<std::vector<uint8_t>, std::string> load_tox_data(
    const std::filesystem::path& filepath);

// ---------------------------------------------------------------------------
// Tox instance creation
// ---------------------------------------------------------------------------

/// Create a new Tox instance from previously saved data.
///
/// The caller may optionally pass a pre-configured `Tox_Options` structure.
/// If @p options is `nullptr`, default options are used (with the save-data
/// fields filled in automatically).
///
/// @param savedata  Raw bytes obtained from `load_tox_data()`.
/// @param options   Optional pre-configured Tox options.  The save-data
///                  fields will be overwritten.
/// @return          An owning pointer to the Tox instance, or an error.
[[nodiscard]] util::Expected<ToxPtr, std::string> create_tox_from_savedata(
    const std::vector<uint8_t>& savedata, Tox_Options* options = nullptr);

/// Create a brand-new Tox instance with a fresh identity.
///
/// @param options  Optional pre-configured Tox options.  If `nullptr`,
///                 defaults are used.
/// @return         An owning pointer to the Tox instance, or an error.
[[nodiscard]] util::Expected<ToxPtr, std::string> create_new_tox(Tox_Options* options = nullptr);

/// Convenience: load an existing save file if it exists, otherwise create
/// a fresh Tox instance.  After creation the state is always saved back
/// to @p filepath so that the file exists for the next startup.
///
/// @param filepath  Path to the save file (created if missing).
/// @param options   Optional pre-configured Tox options.
/// @return          An owning pointer to the Tox instance, or an error.
[[nodiscard]] util::Expected<ToxPtr, std::string> create_or_load_tox(
    const std::filesystem::path& filepath, Tox_Options* options = nullptr);

}  // namespace toxtunnel::tox
