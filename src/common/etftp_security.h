#ifndef ETFTP_SECURITY_H
#define ETFTP_SECURITY_H

#include "etftp_buffer.h"

#include <arpa/inet.h>
#include <string>

namespace ETFTP
{

    uint16_t randomInt16();

    uint32_t randomInt32();

    void randomMask(Buffer &buffer);

    void hashPassword(const std::string &unhashed, std::string &hashed);

    bool validPassword(const std::string &password);

    std::string getSalt();

    std::string saltedHash(const std::string &hashedPassword, const std::string &salt);

    ssize_t secureSend(int fd, const uint8_t *buffer, const struct sockaddr_in6 *address, int* error);

    ssize_t secureRecv(int fd, uint8_t *buffer, size_t len, int* error);
}

#endif