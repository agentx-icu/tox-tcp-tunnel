#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace toxtunnel::util {

inline bool is_plain_filename(std::string_view filename) {
    if (filename.empty() || filename == "." || filename == "..") {
        return false;
    }

    if (filename.find('/') != std::string_view::npos ||
        filename.find('\\') != std::string_view::npos) {
        return false;
    }

    const std::filesystem::path path{std::string(filename)};
    return !path.is_absolute() && !path.has_root_name() && !path.has_parent_path() &&
           path.filename() == path;
}

}  // namespace toxtunnel::util
