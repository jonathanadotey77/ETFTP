#include "etftp_misc.h"
#include <ifaddrs.h>
#include <net/if.h>
#include <curl/curl.h>
#include <sstream>
#include <iomanip>

namespace ETFTP
{

    std::string bytesToHexString(const unsigned char *bytes, size_t length) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < length; ++i) {
            ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
        }
        return ss.str();
    }

    in_addr_t getIpAddress()
    {
        struct ifaddrs *ifAddrStruct = nullptr;
        struct ifaddrs *ifa = nullptr;
        void *tmpAddrPtr = nullptr;

        getifaddrs(&ifAddrStruct);

        for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == nullptr)
            {
                continue;
            }

            if (ifa->ifa_addr->sa_family == AF_INET && (ifa->ifa_flags & IFF_LOOPBACK) == 0)
            {
                tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                char addressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);

                // Assuming the first non-loopback IPv4 address found is the public IP
                freeifaddrs(ifAddrStruct);
                in_addr_t ipAddress;
                inet_pton(AF_INET, addressBuffer, &ipAddress);
                return ipAddress;
            }
        }

        if (ifAddrStruct != nullptr)
        {
            freeifaddrs(ifAddrStruct);
        }

        std::cerr << "Failed to get public IP" << std::endl;
        return INADDR_ANY;
    }

    size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *data)
    {
        size_t totalSize = size * nmemb;
        data->append((char *)contents, totalSize);
        return totalSize;
    }

    std::string getPublicIpAddress()
    {
        CURL *curl;
        CURLcode res;
        std::string response;

        curl = curl_easy_init();
        if (curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, "https://myexternalip.com/raw");

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            res = curl_easy_perform(curl);

            // Check for errors
            if (res != CURLE_OK)
            {
                std::cerr << "Failed to perform GET request: " << curl_easy_strerror(res) << std::endl;
            }

            // Cleanup
            curl_easy_cleanup(curl);
        }
        else
        {
            std::cerr << "Failed to get public IP address" << std::endl;
        }
        return response;
    }

    void applyMask(unsigned char* buffer, const unsigned char* mask, size_t len) {

        for(size_t i = 0; i < len; ++i) {
            buffer[i] = buffer[i] ^ mask[i];
        }
    }

}