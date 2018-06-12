

#if !defined(_PADDER_HPP_INCLUDED_)
#define _PADDER_HPP_INCLUDED_

#include <memory>
#include <utility>

class Padder {
    public:
    virtual std::pair<std::unique_ptr<unsigned char[]>, size_t>
    pad (const std::unique_ptr<unsigned char[]> & /* data */, const size_t /* byteLength*/) const = 0;
    virtual ~Padder() {}

    virtual const size_t blockSize() const = 0;
};

#endif // _PADDER_HPP_INCLUDED_
