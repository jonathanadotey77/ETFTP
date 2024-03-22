#ifndef ETFTP_CLIENT_H
#define ETFTP_CLIENT_H

#include "../common/etftp_misc.h"
#include "../common/etftp_security.h"

#include <string>
#include <vector>

namespace ETFTP
{

    class Client
    {
    public:
        static const in6_addr CLIENT_IP_ADDRESS;

    private:
        struct sockaddr_in6 serverAddress;
        struct sockaddr_in6 clientAddress;
        uint16_t port;

        int sd;

        bool loggedIn;
    
    private:

        std::vector<Buffer> receiveKeys(int n, int* k);

    public:
        Client(uint16_t port);

        bool start();
        void stop();

        bool login(const std::string &username, const std::string &password);
        void logout();
        bool ping(int value);
        void setServer(const std::string &serverIpAddress, uint16_t serverPort);
        void printServerInfo() const;

        void sendAck(uint32_t block);

        int getRequest(const std::string& localPath, const std::string& remotePath);
    };

}
#endif