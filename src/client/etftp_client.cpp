#include <iostream>
#include <unistd.h>
#include "../common/etftp_buffer.h"
#include "../common/etftp_packet.h"
#include "etftp_client.h"
#include <arpa/inet.h>
#include <poll.h>
#include <termios.h>
#include "../common/etftp_loginstatus.h"

static void setStdinEcho(bool enable) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

namespace ETFTP
{
    const in_addr_t Client::CLIENT_IP_ADDRESS = getIpAddress();

    Client::Client(uint16_t port)
    {
        this->port = port;

        this->serverAddress.sin_family = AF_INET;
        this->serverAddress.sin_addr.s_addr = CLIENT_IP_ADDRESS;
        this->serverAddress.sin_port = htons(10000);

        this->clientAddress.sin_family = AF_INET;
        this->clientAddress.sin_addr.s_addr = CLIENT_IP_ADDRESS;
        this->clientAddress.sin_port = htons(this->port);
        this->sd = 0;
    }

    bool Client::start()
    {
        this->sd = socket(AF_INET, SOCK_DGRAM, 0);

        if(bind(sd, (const sockaddr*)&this->clientAddress, sizeof(this->clientAddress)) < 0) {
            fprintf(stderr, "Bind() failed\n");
            return false;
        }

        this->printServerInfo();

        return true;
    }
    void Client::stop()
    {
        close(this->sd);
    }

    bool Client::login(const std::string &username, const std::string &password)
    {
        LoginRequestPacket loginRequest;
        std::string hashedPassword;
        hashPassword(password, hashedPassword);
        memset(&loginRequest, 0, sizeof(loginRequest));

        loginRequest.packetType = e_LoginRequest;
        loginRequest.step = 1;
        memcpy(loginRequest.data, username.c_str(), std::min(username.size(), static_cast<size_t>(32)));
        memcpy(loginRequest.data + 33, hashedPassword.c_str(), std::min(hashedPassword.size(), static_cast<size_t>(64)));
        Buffer m2(98);
        randomMask(m2);

        for(size_t i = 0; i < 98; ++i) {
            loginRequest.data[i] ^= m2[i];
        }

        uint8_t buffer[512] = {0};

        LoginRequestPacket::serialize(buffer, &loginRequest);
        sendto(this->sd, buffer, LoginRequestPacket::SIZE, 0, (const struct sockaddr*)&this->serverAddress, sizeof(this->serverAddress));

        struct pollfd pfd[1];
        pfd[0].fd = this->sd;
        pfd[0].events = POLLIN;
        pfd[0].revents = 0;

        int rc = poll(pfd, 1, 3000);

        if (rc == -1)
        {
            // Poll Error
            perror("Poll Error");
            return false;
        }
        else if (rc == 0)
        {
            return false;
        }

        struct sockaddr_in sourceAddress;
        socklen_t sourceAddressLen = sizeof(sourceAddress);

        int bytes = recvfrom(this->sd, buffer, LoginResponsePacket::SIZE, 0, (struct sockaddr*)&sourceAddress, &sourceAddressLen);

        if(bytes != LoginResponsePacket::SIZE) {
            printf("Bad size\n");
            return false;
        }

        LoginResponsePacket loginResponse;
        LoginResponsePacket::deserialize(&loginResponse, buffer);

        if(loginResponse.packetType != e_LoginResponse) {
            printf("Bad type\n");
            return false;
        }

        if(loginResponse.step != 1) {
            printf("Not step 1 [%d]\n", (int)loginResponse.step);
            return false;
        }

        loginRequest.step = 2;
        loginRequest.keyId = loginResponse.keyId;
        for(size_t i = 0; i < 98; ++i) {
            loginRequest.data[i] = loginResponse.data[i] ^ m2[i];
        }

        LoginRequestPacket::serialize(buffer, &loginRequest);
        sendto(this->sd, buffer, LoginRequestPacket::SIZE, 0, (const struct sockaddr*)&this->serverAddress, sizeof(this->serverAddress));

        pfd[0].fd = this->sd;
        pfd[0].events = POLLIN;
        pfd[0].revents = 0;

        rc = poll(pfd, 1, 3000);

        if (rc == -1)
        {
            // Poll Error
            perror("Poll Error");
            return false;
        }
        else if (rc == 0)
        {
            return false;
        }

        sourceAddressLen = sizeof(sourceAddress);
        bytes = recvfrom(this->sd, buffer, LoginResponsePacket::SIZE, 0, (struct sockaddr*)&sourceAddress, &sourceAddressLen);

        if(bytes != LoginResponsePacket::SIZE) {
            return false;
        }

        LoginResponsePacket::deserialize(&loginResponse, buffer);

        if(loginResponse.packetType != PacketTypes::e_LoginResponse) {
            printf("Bad type\n");
            return false;
        }

        if(loginResponse.step != 2) {
            printf("Bad step\n");
            return false;
        }

        if(loginResponse.status == LoginStatus::e_Success) {
            return true;
        }

        printf("Bad everything [%d]\n", loginResponse.status);

        return false;
    }

    bool Client::ping(int value)
    {
        PingPacket pingPacket;
        pingPacket.value = value;

        uint8_t buffer[PingPacket::SIZE] = {0};

        PingPacket::serialize(buffer, &pingPacket);

        char ip[80] = {0};
        inet_ntop(AF_INET, &this->serverAddress.sin_addr.s_addr, ip, 80);
        printf("Pinging %s:%d\n", ip, static_cast<int>(ntohs(this->serverAddress.sin_port)));


        sendto(this->sd, buffer, PingPacket::SIZE, 0, (const sockaddr*)&this->serverAddress, sizeof(this->serverAddress));

        struct sockaddr_in address = this->serverAddress;
        socklen_t addressLen = sizeof(address);

        memset(&pingPacket, 0, sizeof(pingPacket));
        memset(buffer, 0, PingPacket::SIZE);

        struct pollfd pfd[1];
        pfd[0].fd = this->sd;
        pfd[0].events = POLLIN;
        pfd[0].revents = 0;

        int rc = poll(pfd, 1, 4000);

        if (rc == -1)
        {
            // Poll Error
            perror("Poll Error");
            return false;
        }
        else if (rc == 0)
        {
            printf("Ping timeout\n");
            return false;
        }
        int bytes = recvfrom(this->sd, buffer, PingPacket::SIZE, 0, (struct sockaddr*)&address, &addressLen);
        if(bytes != PingPacket::SIZE) {
            return false;
        }

        PingPacket::deserialize(&pingPacket, buffer);

        return pingPacket.value == value;
    }
    void Client::setServer(const std::string &serverIpAddress, uint16_t serverPort)
    {
        this->serverAddress.sin_addr.s_addr = inet_addr(serverIpAddress.c_str());
        this->serverAddress.sin_port = htons(serverPort);
    }

    void Client::printServerInfo() const {
        char buffer[80] = {0};
        inet_ntop(AF_INET, &this->serverAddress.sin_addr.s_addr, buffer, 80);
        printf("Server IP Address set to %s:%d\n", buffer, static_cast<int>(ntohs(this->serverAddress.sin_port)));
    }
}

int main(int argc, char* argv[])
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

    if(!client.start()) {
        fprintf(stderr, "Failed to start\n");
        exit(1);
    }

    std::string input;
    while(std::cin >> input) {
        if(input == "quit") {
            break;
        }

        if(input == "set_server") {
            std::string serverIpAddress;
            uint16_t serverPort;

            std::cin >> serverIpAddress >> serverPort;

            client.setServer(serverIpAddress, serverPort);
            client.printServerInfo();
        } else if(input == "ping") {
            uint64_t value;
            std::cin >> value;
            value &= (int)UINT16_MAX;
            if(client.ping((uint16_t)value)) {
                std::cout << value << std::endl;
            } else {
                printf("Ping failed\n");
            }
        } else if(input == "login") {
            printf("Username: ");
            std::string username;
            std::string password;
            std::cin >> username;

            printf("Password: ");
            setStdinEcho(false);
            std::cin >> password;
            setStdinEcho(true);
            std::cout << std::endl;

            if(client.login(username, password)) {
                printf("Success\n");
            } else {
                printf("Login failed\n");
            }

            
        } else {
            continue;
        }
    }

    client.stop();

    return 0;
}