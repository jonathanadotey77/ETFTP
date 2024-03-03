#ifndef ETFTP_MISC_H
#define ETFTP_MISC_H

#include <iostream>
#include <string>
#include <arpa/inet.h>

namespace ETFTP
{

    in_addr_t getIpAddress();
    size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *data);
    std::string getPublicIpAddress();

    std::string bytesToHexString(const unsigned char *bytes, size_t length);

}
#endif