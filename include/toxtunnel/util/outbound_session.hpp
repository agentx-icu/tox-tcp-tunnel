#pragma once

#include <mutex>

namespace toxtunnel::util {

/// A one-way fence at the native packet enqueue. A permit must never span a
/// cross-thread dispatch or an application callback.
class OutboundSession {
   public:
    [[nodiscard]] std::unique_lock<std::mutex> acquire() {
        std::unique_lock lock(mutex_);
        if (!open_) {
            return {};
        }
        return lock;
    }

    void close() {
        std::lock_guard lock(mutex_);
        open_ = false;
    }

   private:
    std::mutex mutex_;
    bool open_{true};
};

}  // namespace toxtunnel::util
