

#if !defined(B64_HPP_INCLUDED)
#define B64_HPP_INCLUDED

#include <array>
#include <memory>

using b64_charset = std::string;

static const b64_charset b64_chars {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/"
};

static const b64_charset b64_safe_chars {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_"
};

static const char padding_char = '=';

static const size_t line_limit_76 = 76;
static const size_t line_limit_64 = 64;

inline
const std::string b64_encode(const std::unique_ptr<unsigned char[]> &src, const size_t length, const b64_charset& charset = b64_chars) {
    std::string result;
    std::array<unsigned char, 3> src_char;
    std::array<unsigned char, 4> dst_char;

    for (size_t n = 0; n < length / 3; n+=1) {
        src_char[0] = src[n * 3];
        src_char[1] = src[n * 3 + 1];
        src_char[2] = src[n * 3 + 2];

        dst_char[0] = src_char[0] >> 2;
        dst_char[1] = ((src_char[0] & 0x03) << 4) | (src_char[1] >> 4);
        dst_char[2] = ((src_char[1] & 0x0F) << 2) | (src_char[2] >> 6);
        dst_char[3] = src_char[2] & 0x3F;

        for (const auto& c: dst_char) {
            result += charset[c];
        }
    }

    if (length % 3 != 0) {
        auto rem = length % 3;
        auto processed = length - rem;
        for (size_t i = 0; i < rem + 1; i+= 1) {
            src_char[i] = src[processed + i];
        }

        for (size_t i = rem; i < 3; i += 1) {
            src_char[i] = '\0';
        }

        dst_char[0] = src_char[0] >> 2;
        dst_char[1] = ((src_char[0] & 0x03) << 4) | (src_char[1] >> 4);
        dst_char[2] = ((src_char[1] & 0x0F) << 2) | (src_char[2] >> 6);
        dst_char[3] = src_char[2] & 0x3F;

        for (size_t i = 0; i < rem + 1; i+=1) {
            result += charset[dst_char[i]];
        }

        for (size_t i = rem; i < 3; i+=1) {
            result += padding_char;
        }
    }

    return result;
}

// inline const std::string b64_encode(const std::string &src, const b64_charset& charset = b64_chars) {
    // return b64_encode(reinterpret_cast<const unsigned char *>(src.data()), src.length(), charset);
// }

#endif //B64_HPP_INCLUDED
