#ifndef ETFTP_SECURITY_H
#define ETFTP_SECURITY_H

#include <string>

namespace ETFTP
{

    void random_mask(unsigned char *buffer);

    void hashPassword(const std::string &unhashed, std::string &hashed);

    bool validPassword(const std::string& password);
}

#endif