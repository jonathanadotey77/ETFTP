#ifndef ETFTP_CLIENT_H
#define ETFTP_CLIENT_H

#include "../common/etftp_security.h"
#include "../common/etftp_misc.h"

namespace ETFTP
{

    class Client
    {
    public:
        static const in_addr_t CLIENT_IP_ADDRESS;

    private:
        struct sockaddr_in serverAddress;
        struct sockaddr_in clientAddress;
        uint16_t port;

        int sd;

    public:
        Client(uint16_t port);

        bool start();
        void stop();

        bool login(const std::string &username, const std::string &password);
        bool ping(int value);
        void setServer(const std::string &serverIpAddress, uint16_t serverPort);
        void printServerInfo() const;
    };

}
#endif