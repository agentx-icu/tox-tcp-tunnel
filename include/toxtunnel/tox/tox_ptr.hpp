#pragma once

#include <toxcore/tox.h>

#include <memory>

namespace toxtunnel::tox {

/// Custom deleter for Tox pointer, used with std::unique_ptr.
struct ToxDeleter {
    void operator()(Tox* tox) const noexcept;
};

/// Owning smart pointer for a Tox instance.
using ToxPtr = std::unique_ptr<Tox, ToxDeleter>;

}  // namespace toxtunnel::tox
