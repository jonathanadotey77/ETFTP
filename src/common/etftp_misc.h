#ifndef ETFTP_MISC_H
#define ETFTP_MISC_H

#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <vector>

namespace ETFTP
{

    std::string bytesToHexString(const uint8_t *bytes, size_t length);

    in6_addr getIpAddress();

    size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *data);

    std::string getPublicIpAddress();

    std::string getIpString(const struct sockaddr_in6 &address);

    std::vector<int> kthPermutation(int n, int k);

    uint32_t factorial(int n);
}
#endif