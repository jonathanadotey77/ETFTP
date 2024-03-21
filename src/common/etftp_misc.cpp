#include "etftp_misc.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <ifaddrs.h>
#include <iomanip>
#include <net/if.h>
#include <sstream>

namespace ETFTP
{

    std::string bytesToHexString(const uint8_t *bytes, size_t length)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < length; ++i)
        {
            ss << std::setw(2) << static_cast<uint32_t>(bytes[i]);
        }
        return ss.str();
    }

    in6_addr getIpAddress()
    {
        struct ifaddrs *ifAddrStruct = nullptr;
        struct ifaddrs *ifa = nullptr;

        if (getifaddrs(&ifAddrStruct) == -1)
        {
            std::cerr << "Failed to get interface addresses" << std::endl;
            return in6addr_any;
        }

        for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == nullptr)
            {
                continue;
            }

            if (ifa->ifa_addr->sa_family == AF_INET6 && (ifa->ifa_flags & IFF_LOOPBACK) == 0)
            {
                struct sockaddr_in6 *addr = reinterpret_cast<struct sockaddr_in6 *>(ifa->ifa_addr);
                if (!IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr) && !IN6_IS_ADDR_LOOPBACK(&addr->sin6_addr))
                {
                    in6_addr ipAddress = addr->sin6_addr;
                    freeifaddrs(ifAddrStruct);
                    return ipAddress;
                }
            }
        }

        if (ifAddrStruct != nullptr)
        {
            freeifaddrs(ifAddrStruct);
        }

        std::cerr << "Failed to get public IPv6 address" << std::endl;
        return in6addr_any;
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

    std::string getIpString(const struct sockaddr_in6 &address)
    {
        char ip[INET6_ADDRSTRLEN] = {0};
        // inet_ntop(AF_INET, &address.sin_addr.s_addr, ip, 80);
        inet_ntop(AF_INET6, &address.sin6_addr, ip, INET6_ADDRSTRLEN);
        sprintf(ip, "%s:%d", ip, static_cast<int>(ntohs(address.sin6_port)));
        return std::string(ip);
    }

    std::vector<int> kthPermutation(int n, int k)
    {
        printf("{N: %d, K: %d}\n", n, k);
        std::vector<int> ans;
        std::vector<int> v;

        --k;

        int factorial = 1;

        for (int i = 1; i <= n; ++i)
        {
            v.push_back(i);
            factorial *= i;
        }

        for (int i = 0; i < n; ++i)
        {
            factorial /= (n - i);
            int index = k / factorial;
            int t = v[index];
            ans.push_back(t);
            v.erase(v.begin() + index);
            k %= factorial;
        }

        printf("ans:");
        for(int i = 0; i < (int)ans.size(); ++i) {
            printf(" %d", ans[i]);
        }
        printf("\n");

        return ans;
    }

    uint32_t factorial(int n) {
        uint32_t res = 1;
        for (int i=2; i<=n; i++) {
            res *= i;
        }
        return res;
    }

}