#include "toxtunnel/util/qr_code.hpp"

#include <exception>
#include <sstream>

#include "qrcodegen.hpp"

namespace toxtunnel::util {
namespace {

bool module_at(const qrcodegen::QrCode& qr, int x, int y) {
    if (x < 0 || y < 0 || x >= qr.getSize() || y >= qr.getSize()) {
        return false;
    }
    return qr.getModule(x, y);
}

std::string make_cell(bool upper, bool lower, bool use_color) {
    const char* glyph = " ";
    if (upper && lower) {
        glyph = "\xE2\x96\x88";  // FULL BLOCK
    } else if (upper && !lower) {
        glyph = "\xE2\x96\x80";  // UPPER HALF BLOCK
    } else if (!upper && lower) {
        glyph = "\xE2\x96\x84";  // LOWER HALF BLOCK
    }

    if (!use_color) {
        return std::string(glyph);
    }

    if (upper || lower) {
        return std::string("\x1b[38;5;46m") + glyph + "\x1b[0m";
    }
    return std::string(" ");
}

}  // namespace

Expected<std::string, std::string> generate_qr_terminal(std::string_view text, bool use_color) {
    if (text.empty()) {
        return make_unexpected(std::string("cannot generate QR code from empty text"));
    }

    try {
        const qrcodegen::QrCode qr =
            qrcodegen::QrCode::encodeText(std::string(text).c_str(), qrcodegen::QrCode::Ecc::MEDIUM);

        constexpr int kBorder = 2;
        std::ostringstream out;

        for (int y = -kBorder; y < qr.getSize() + kBorder; y += 2) {
            for (int x = -kBorder; x < qr.getSize() + kBorder; ++x) {
                const bool upper = module_at(qr, x, y);
                const bool lower = module_at(qr, x, y + 1);
                out << make_cell(upper, lower, use_color);
            }
            out << '\n';
        }

        return out.str();
    } catch (const std::exception& ex) {
        return make_unexpected(std::string("failed to generate QR code: ") + ex.what());
    } catch (...) {
        return make_unexpected(std::string("failed to generate QR code"));
    }
}

}  // namespace toxtunnel::util
