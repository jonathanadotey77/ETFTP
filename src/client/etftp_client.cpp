#include <iostream>

#include "etftp_misc.h"
#include <arpa/inet.h>

namespace ETFTP
{
    class Client {
    private:


    struct sockaddr_in serverAddress;
    struct sockaddr_in clientAddress;
    uint16_t port;


    public:
        Client();

        bool login(const std::string& serverIpAddress, uint16_t serverPort);
        bool ping();
    };
}

int main() {

    return 0;
}