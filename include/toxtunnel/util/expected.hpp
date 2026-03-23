#pragma once

#include <stdexcept>
#include <type_traits>
#include <utility>
#include <variant>

namespace toxtunnel::util {

/// Tag wrapper for constructing an Expected in the error state.
/// Disambiguates the error constructor from the value constructor,
/// which is critical when T and E are the same type.
template <typename E>
class unexpected {
   public:
    explicit unexpected(const E& e) : error_(e) {}
    explicit unexpected(E&& e) : error_(std::move(e)) {}

    const E& value() const& { return error_; }
    E& value() & { return error_; }
    E&& value() && { return std::move(error_); }

   private:
    E error_;
};

/// Deduction guide so `unexpected(val)` deduces the template parameter.
template <typename E>
unexpected(E) -> unexpected<E>;

template <typename T, typename E>
class Expected {
   public:
    struct ValueHolder {
        T value;
    };

    struct ErrorHolder {
        E error;
    };

    // Construct with value
    Expected(const T& value) : storage_(ValueHolder{value}) {}
    Expected(T&& value) : storage_(ValueHolder{std::move(value)}) {}

    // Construct with error via unexpected wrapper — resolves ambiguity when T == E
    Expected(const unexpected<E>& u) : storage_(ErrorHolder{u.value()}) {}
    Expected(unexpected<E>&& u) : storage_(ErrorHolder{std::move(u).value()}) {}

    // Check if has value
    [[nodiscard]] bool has_value() const { return std::holds_alternative<ValueHolder>(storage_); }

    [[nodiscard]] explicit operator bool() const { return has_value(); }

    // Access value (throws if error)
    T& value() & {
        if (!has_value()) {
            throw std::runtime_error("Expected contains error");
        }
        return std::get<ValueHolder>(storage_).value;
    }

    const T& value() const& {
        if (!has_value()) {
            throw std::runtime_error("Expected contains error");
        }
        return std::get<ValueHolder>(storage_).value;
    }

    T&& value() && {
        if (!has_value()) {
            throw std::runtime_error("Expected contains error");
        }
        return std::get<ValueHolder>(std::move(storage_)).value;
    }

    // Access error (throws if value)
    E& error() & {
        if (has_value()) {
            throw std::runtime_error("Expected contains value");
        }
        return std::get<ErrorHolder>(storage_).error;
    }

    const E& error() const& {
        if (has_value()) {
            throw std::runtime_error("Expected contains value");
        }
        return std::get<ErrorHolder>(storage_).error;
    }

    E&& error() && {
        if (has_value()) {
            throw std::runtime_error("Expected contains value");
        }
        return std::get<ErrorHolder>(std::move(storage_)).error;
    }

    // Value or default
    T value_or(T&& default_value) const& {
        return has_value() ? value() : std::forward<T>(default_value);
    }

    T value_or(T&& default_value) && {
        return has_value() ? std::get<ValueHolder>(std::move(storage_)).value
                           : std::forward<T>(default_value);
    }

   private:
    std::variant<ValueHolder, ErrorHolder> storage_;
};

/// Partial specialization for Expected<void, E> (operations that can fail
/// but produce no value on success).
template <typename E>
class Expected<void, E> {
   public:
    // Construct in the success state.
    Expected() : has_value_(true) {}

    // Construct with error via unexpected wrapper.
    Expected(const unexpected<E>& u) : has_value_(false), error_(u.value()) {}
    Expected(unexpected<E>&& u) : has_value_(false), error_(std::move(u).value()) {}

    // Check if has value (success)
    [[nodiscard]] bool has_value() const { return has_value_; }

    [[nodiscard]] explicit operator bool() const { return has_value_; }

    // Access error (throws if success)
    E& error() & {
        if (has_value_) {
            throw std::runtime_error("Expected<void> contains value");
        }
        return error_;
    }

    const E& error() const& {
        if (has_value_) {
            throw std::runtime_error("Expected<void> contains value");
        }
        return error_;
    }

    E&& error() && {
        if (has_value_) {
            throw std::runtime_error("Expected<void> contains value");
        }
        return std::move(error_);
    }

   private:
    bool has_value_;
    E error_{};
};

/// Helper function to create an Expected in the error state.
template <typename E>
unexpected<std::decay_t<E>> make_unexpected(E&& e) {
    return unexpected<std::decay_t<E>>(std::forward<E>(e));
}

}  // namespace toxtunnel::util
