#pragma once

#include <string_view>

namespace toxtunnel::util {

inline bool is_plain_filename(std::string_view filename) {
    if (filename.empty() || filename == "." || filename == "..") {
        return false;
    }

    // Pure string checks — no std::filesystem::path decomposition. The
    // manylinux2014 release toolchain (devtoolset GCC 10, COW-string ABI)
    // mis-parses path components (see parent_dir_of in atomic_file.cpp), so
    // relying on has_parent_path()/filename() here could reject the default
    // "tox_save.dat" or accept a traversal. '/' and '\\' cover relative and
    // absolute separators on every platform; ':' rejects Windows root names
    // ("C:foo") and ADS ("name:stream").
    return filename.find('/') == std::string_view::npos &&
           filename.find('\\') == std::string_view::npos &&
           filename.find(':') == std::string_view::npos;
}

}  // namespace toxtunnel::util
