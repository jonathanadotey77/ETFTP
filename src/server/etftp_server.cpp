#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <string>
#include "etftp_filesystem.h"

#include "etftp_server.h"

// Login
// Forks

namespace ETFTP
{

Server::Server(unsigned short)
{
}

bool Server::start()
{
    return true;
}

bool Server::stop()
{
    return true;
}

}

int main(int argc, char *argv[])
{


    if (argc != 2)
    {
        fprintf(stderr, "USAGE: %s <port>\n", argv[0]);
        return 1;
    }

    for (char *p = argv[1]; *p != '\0'; ++p)
    {
        if (!isdigit(*p))
        {
            fprintf(stderr, "USAGE: %s <port>\n", argv[0]);
            return 1;
        }
    }

    const unsigned int port = atoi(argv[1]);

    if (port > 65535)
    {
        fprintf(stderr, "USAGE: %s <port>\n", argv[0]);
        return 1;
    }

    ETFTP::Server server(static_cast<unsigned short>(port));

    server.start();

    std::string input;
    while (true)
    {
        std::cin >> input;

        if (input == "quit")
        {
            break;
        }
    }

    server.stop();

    return 0;
}