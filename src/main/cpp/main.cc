
#include <iostream>
#include <boost/format.hpp>

#include "Rijndael.hpp"
#include "Pkcs7Padder.hpp"

#include "b64.hpp"

template<typename T>
auto printData(const T &data, size_t length, std::ostream &out = std::cout) {
    for (size_t i = 0; i < length; i += 1) {
        out << boost::format("%1$02X ") % (int)data[i];
        if ((i + 1) % 16 == 0) {
            out << "\n";
        }
    }
}

int main() {
    const size_t dataLength = 512 / 8;
    constexpr size_t blockSize = 128 / 8;
    constexpr size_t keyLength = 256 / 8;

    using DataType = uint8_t;

    using Pkcs7Padder128 = Pkcs7Padder<blockSize>;
    using AES256 = Rijndael<Pkcs7Padder128, keyLength, DataType>;

    using BufferType = AES256::BufferType;
    using BufferPtr = AES256::BufferPtr;

    BufferPtr data{ new DataType[dataLength] {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
        0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
        0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10,
    }};
    BufferPtr key{ new DataType[keyLength] {
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4,
    }};
    BufferPtr iv{ new DataType[blockSize] {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    }};

    std::cout << "plain text:" << std::endl;
    std::cout << "* hex" << std::endl;
    printData(data, dataLength);

    std::string b64_pt = b64_encode(data, dataLength);
    std::cout << boost::format("* b64 encoded\n%1%\n") % b64_pt << std::endl;

    std::cout << "key:" << std::endl;
    std::cout << "* hex" << std::endl;
    printData(key, keyLength);

    std::string b64_key = b64_encode(key, keyLength);
    std::cout << boost::format("* b64 encoded\n%1%\n") % b64_key << std::endl;

    std::cout << "initial vector:" << std::endl;
    std::cout << "* hex" << std::endl;
    printData(iv, blockSize);

    std::string b64_iv = b64_encode(iv, blockSize);
    std::cout << boost::format("* b64 encoded\n%1%\n") % b64_iv << std::endl;

    std::cout << boost::format("data size = %1% bytes") % dataLength << std::endl;
    std::cout << boost::format("block size = %1% bytes") % blockSize << std::endl;
    std::cout << boost::format("key length = %1% bytes") % keyLength << std::endl << std::endl;

    Pkcs7Padder128 padder{};
    AES256 aes{ padder };

    auto result = aes.enc(data, dataLength, key, iv);
    auto encrypted = std::move(result.first);
    auto encryptedLength = result.second;

    std::cout << boost::format("encrypted size = %1% bytes") % encryptedLength << std::endl;
    std::cout << "cipher text:" << std::endl;
    std::cout << "* hex" << std::endl;
    printData(encrypted, encryptedLength);

    std::string b64_ct = b64_encode(encrypted, encryptedLength);
    std::cout << boost::format("* b64 encoded\n%1%\n") % b64_ct << std::endl;

    return 0;
}
