// Stub TU referenced by CMakeLists.txt while the SIGHUP config-reload
// feature (#9) is being implemented in a sibling worktree. The header
// provides an inline pass-through `check_reloadable`; this TU just keeps
// the source list in CMakeLists.txt resolvable so the library can build.

#include "toxtunnel/util/config_reload.hpp"
