#ifndef ETFTP_SECURITY_H
#define ETFTP_SECURITY_H

#include <string>

namespace ETFTP
{

    void random_mask(unsigned char *buffer);

    bool computeHash(const std::string &unhashed, std::string &hashed);
}

#endif