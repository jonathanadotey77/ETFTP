#include "etftp_server.h"

#include "../common/etftp_misc.h"
#include "../common/etftp_security.h"

#include <fstream>
#include <iostream>

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "USAGE: %s <start port> <end port>\n", argv[0]);
        return 1;
    }

    for (char *p = argv[1]; *p != '\0'; ++p)
    {
        if (!isdigit(*p))
        {
            fprintf(stderr, "USAGE: %s <start port> <end port>\n", argv[0]);
            return 1;
        }
    }

    for (char *p = argv[2]; *p != '\0'; ++p)
    {
        if (!isdigit(*p))
        {
            fprintf(stderr, "USAGE: %s <start port> <end port>\n", argv[0]);
            return 1;
        }
    }

    const uint32_t startPort = atoi(argv[1]);
    const uint32_t endPort = atoi(argv[2]);

    if (startPort > 65535 || endPort > 65535)
    {
        fprintf(stderr, "USAGE: %s <start port> <end port>\n", argv[0]);
        return 1;
    }

    if (endPort <= startPort || endPort - startPort + 1 < 11)
    {
        fprintf(stderr, "Invalid port range, must have at least 11 ports\n");
        return 1;
    }

    ETFTP::Server server(static_cast<uint16_t>(startPort), static_cast<uint16_t>(endPort));

    bool started = server.start();
    if (!started)
    {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }

    std::string input;
    char buffer[80] = {0};
    while (true)
    {
        std::cin >> input;

        if (input == "quit")
        {
            break;
        }

        if (input == "print")
        {
            std::cin >> input;
            if (input == "ip")
            {
                in_addr_t localAddress = ETFTP::getIpAddress();
                inet_ntop(AF_INET, &localAddress, buffer, 80);
                printf("Local  IP Address: %s\n", buffer);
                std::string ip = ETFTP::getPublicIpAddress();
                if (ip.length() != 0)
                {
                    std::cout << "Public IP Address: " << ip << std::endl;
                }
            }
            else
            {
                continue;
            }
        }
        else if (input == "register")
        {
            std::string username;
            std::string password;
            std::string hashedPassword;
            std::cin >> username >> password;

            if (!ETFTP::validPassword(password))
            {
                printf("Invalid password\n");
                continue;
            }

            ETFTP::hashPassword(password, hashedPassword);
            ETFTP::LoginStatus rc = server.registerUser(username, hashedPassword);

            if (rc == ETFTP::LoginStatus::e_LoginSuccess)
            {
                printf("Successfully registered user '%s'\n", username.c_str());
            }
            else
            {
                printf("User '%s' already exists\n", username.c_str());
            }
        }
        else if (input == "check_login")
        {
            std::string username;
            std::string password;
            std::string hashedPassword;
            std::cin >> username >> password;

            ETFTP::hashPassword(password, hashedPassword);

            ETFTP::LoginStatus rc = server.tryLogin(username, hashedPassword);
            if (rc == ETFTP::LoginStatus::e_LoginSuccess)
            {
                printf("Success\n");
            }
            else if (rc == ETFTP::LoginStatus::e_LoginFailed)
            {
                printf("Incorrect password\n");
            }
            else if (rc == ETFTP::LoginStatus::e_NoSuchUser)
            {
                printf("User '%s' does not exist\n", username.c_str());
            }
        }
        else if (input == "change_password")
        {
            std::string username;
            std::string oldPassword;
            std::string newPassword;
            std::string hashedOldPassword;
            std::string hashedNewPassword;
            std::cin >> username >> oldPassword >> newPassword;

            ETFTP::hashPassword(oldPassword, hashedOldPassword);
            ETFTP::hashPassword(newPassword, hashedNewPassword);

            ETFTP::LoginStatus rc = server.changePassword(username, hashedOldPassword, hashedNewPassword);

            if (rc == ETFTP::LoginStatus::e_LoginSuccess)
            {
                printf("Success\n");
            }
            else if (rc == ETFTP::LoginStatus::e_LoginFailed)
            {
                printf("Incorrect password\n");
            }
            else if (rc == ETFTP::LoginStatus::e_NoSuchUser)
            {
                printf("User '%s' does not exist\n", username.c_str());
            }
        }
        else
        {
            printf("Invalid command\n");
        }
    }

    server.stop();

    return 0;
}