#ifndef ETFTP_SECURITY_H
#define ETFTP_SECURITY_H

#include <string>
#include "etftp_buffer.h"

namespace ETFTP
{
    void randomMask(Buffer& buffer);

    void hashPassword(const std::string &unhashed, std::string &hashed);

    bool validPassword(const std::string& password);
}

#endif