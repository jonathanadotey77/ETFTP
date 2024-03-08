#ifndef ETFTP_BUFFER_H
#define ETFTP_BUFFER_H

#include <iostream>
#include <string.h>
#include <stdint.h>

namespace ETFTP
{

    class Buffer
    {
    private:
        uint8_t *buffer;
        size_t len;

    public:
        Buffer(size_t len);
        Buffer(const uint8_t *src, size_t len);
        Buffer(const Buffer &other);

        Buffer &operator=(const Buffer &other);

        ~Buffer();

        size_t size() const;

        uint8_t *data();
        void zero();
        void init(size_t len);
        std::string toString() const;

        uint8_t &operator[](size_t i);
        Buffer operator^(const Buffer &other);
        Buffer &operator^=(const Buffer &other);
        bool operator==(const Buffer &other);

    private:
        void copy(const Buffer &other);
    };

    std::ostream &operator<<(std::ostream &os, const Buffer &buffer);

}

#endif