#include "../client/etftp_client.h"

#include <fstream>
#include <iostream>
#include <poll.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

static void setStdinEcho(bool enable)
{
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
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

    const uint32_t port = atoi(argv[1]);

    if (port > 65535)
    {
        fprintf(stderr, "USAGE: %s <start port> <end port>\n", argv[0]);
        return 1;
    }

    ETFTP::Client client(static_cast<uint16_t>(port));

    if (!client.start())
    {
        fprintf(stderr, "Failed to start\n");
        exit(1);
    }

    std::string input;

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);

    struct timeval timeout;
    timeout.tv_usec = 5;

    while (true)
    {
        struct pollfd fds[1];
        fds[0].fd = STDIN_FILENO;
        fds[0].events = POLLIN;

        int rc = poll(fds, 1, 4000);

        if(rc < 0) {
            printf("poll() failed [%d]\n", errno);
            break;
        } else if(rc == 0) {
            client.ping(0);
            continue;
        }

        std::cin >> input;
        if (input == "quit")
        {
            break;
        }

        if (input == "set_server")
        {
            std::string serverIpAddress;
            uint16_t serverPort;

            std::cin >> serverIpAddress >> serverPort;

            client.setServer(serverIpAddress, serverPort);
            client.printServerInfo();
        }
        else if (input == "ping")
        {
            uint64_t value;
            std::cin >> value;
            value &= (int)UINT16_MAX;
            printf("Pinging server:\n");
            if (client.ping((uint16_t)value))
            {
                std::cout << value << std::endl;
            }
            else
            {
                printf("Ping failed\n");
            }
        }
        else if (input == "login")
        {
            printf("Username: ");
            std::string username;
            std::string password;
            std::cin >> username;

            printf("Password: ");
            setStdinEcho(false);
            std::cin >> password;
            setStdinEcho(true);
            std::cout << std::endl;

            if (client.login(username, password))
            {
                printf("Success\n");
            }
            else
            {
                printf("Login failed\n");
            }
        }
        else if(input == "get")
        {
            std::string remotePath;
            std::string localPath;
            std::cin >> remotePath >> localPath;

            client.getRequest(localPath, remotePath);
        }
        else if(input == "logout")
        {
            client.logout();
        }
        else
        {
            continue;
        }
    }

    client.stop();

    return 0;
}