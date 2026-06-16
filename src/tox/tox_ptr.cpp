#include "toxtunnel/tox/tox_ptr.hpp"

namespace toxtunnel::tox {

void ToxDeleter::operator()(Tox* tox) const noexcept {
    if (tox) {
        tox_kill(tox);
    }
}

}  // namespace toxtunnel::tox
