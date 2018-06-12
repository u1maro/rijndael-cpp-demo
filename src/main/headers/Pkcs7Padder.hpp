

#if !defined(_PKCS7_PADDER_HPP_INCLUDED_)
#define _PKCS7_PADDER_HPP_INCLUDED_

#include "Padder.hpp"

template <const size_t BlockSize>
class Pkcs7Padder: public Padder {
    public:
    Pkcs7Padder(): _blockSize{ BlockSize } {}

    virtual std::pair<std::unique_ptr<unsigned char[]>, size_t>
    pad (const std::unique_ptr<unsigned char[]> &data, const size_t byteLength) const {
		auto rem = byteLength % _blockSize;
		auto lenToPad = _blockSize - rem;

		auto padded = std::unique_ptr<unsigned char[]>(new unsigned char[byteLength + lenToPad]);
		for (size_t i = 0; i < byteLength; i += 1) {
			padded[i] = data[i];
		}

		for (size_t i = 0; i < lenToPad; i += 1) {
			padded[byteLength + i] = lenToPad;
		}

		return std::make_pair(std::move(padded), byteLength + lenToPad);
    }

    virtual const size_t blockSize() const {
        return _blockSize;
    }

    private:
    const size_t _blockSize;
};

#endif // _PKCS7_PADDER_HPP_INCLUDED_
