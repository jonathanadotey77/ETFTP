#ifndef ETFTP_MISC_H
#define ETFTP_MISC_H

#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <vector>

namespace ETFTP
{

    std::string bytesToHexString(const unsigned char *bytes, size_t length);

    in_addr_t getIpAddress();

    size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *data);

    std::string getPublicIpAddress();

    std::string getIpString(const struct sockaddr_in &address);

    std::vector<int> kthPermutation(int n, int k);
}
#endif