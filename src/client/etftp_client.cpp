#include "etftp_client.h"

#include "../common/etftp_buffer.h"
#include "../common/etftp_loginstatus.h"
#include "../common/etftp_packet.h"

#include <arpa/inet.h>
#include <iostream>
#include <poll.h>
#include <termios.h>
#include <unistd.h>

namespace ETFTP
{
    const in6_addr Client::CLIENT_IP_ADDRESS = getIpAddress();

    Client::Client(uint16_t port)
    {
        this->port = port;

        this->serverAddress.sin6_family = AF_INET6;
        memcpy(&this->serverAddress.sin6_addr, &CLIENT_IP_ADDRESS, sizeof(in6_addr));
        this->serverAddress.sin6_port = htons(10000);
        this->serverAddress.sin6_flowinfo = 0;
        this->serverAddress.sin6_scope_id = 0;

        this->clientAddress.sin6_family = AF_INET6;
        memcpy(&this->clientAddress.sin6_addr, &CLIENT_IP_ADDRESS, sizeof(in6_addr));
        this->clientAddress.sin6_port = htons(this->port);
        this->clientAddress.sin6_flowinfo = 0;
        this->clientAddress.sin6_scope_id = 0;
        this->sd = 0;
    }

    bool Client::start()
    {
        this->sd = socket(AF_INET6, SOCK_DGRAM, 0);

        if (bind(sd, (const sockaddr *)&this->clientAddress, sizeof(this->clientAddress)) < 0)
        {
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

        for (size_t i = 0; i < 98; ++i)
        {
            loginRequest.data[i] ^= m2[i];
        }

        uint8_t buffer[512] = {0};

        LoginRequestPacket::serialize(buffer, &loginRequest);
        sendto(this->sd, buffer, LoginRequestPacket::SIZE, 0, (const struct sockaddr *)&this->serverAddress, sizeof(this->serverAddress));

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

        struct sockaddr_in6 sourceAddress;
        socklen_t sourceAddressLen = sizeof(sourceAddress);

        int bytes = recvfrom(this->sd, buffer, LoginResponsePacket::SIZE, 0, (struct sockaddr *)&sourceAddress, &sourceAddressLen);

        if (bytes != LoginResponsePacket::SIZE)
        {
            printf("Bad size\n");
            return false;
        }

        LoginResponsePacket loginResponse;
        LoginResponsePacket::deserialize(&loginResponse, buffer);

        if (loginResponse.packetType != e_LoginResponse)
        {
            printf("Bad type\n");
            return false;
        }

        if (loginResponse.step != 1)
        {
            printf("Not step 1 [%d]\n", (int)loginResponse.step);
            return false;
        }

        loginRequest.step = 2;
        loginRequest.keyId = loginResponse.keyId;
        for (size_t i = 0; i < 98; ++i)
        {
            loginRequest.data[i] = loginResponse.data[i] ^ m2[i];
        }

        LoginRequestPacket::serialize(buffer, &loginRequest);
        sendto(this->sd, buffer, LoginRequestPacket::SIZE, 0, (const struct sockaddr *)&this->serverAddress, sizeof(this->serverAddress));

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
        bytes = recvfrom(this->sd, buffer, LoginResponsePacket::SIZE, 0, (struct sockaddr *)&sourceAddress, &sourceAddressLen);

        if (bytes != LoginResponsePacket::SIZE)
        {
            return false;
        }

        LoginResponsePacket::deserialize(&loginResponse, buffer);

        if (loginResponse.packetType != PacketTypes::e_LoginResponse)
        {
            printf("Bad type\n");
            return false;
        }

        if (loginResponse.step != 2)
        {
            printf("Bad step\n");
            return false;
        }

        if (loginResponse.status == LoginStatus::e_LoginSuccess)
        {
            this->serverAddress.sin6_port = htons(loginResponse.port);
            printf("Port is %d\n", (int)loginResponse.port);
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
        inet_ntop(AF_INET6, &this->serverAddress.sin6_addr, ip, 80);
        printf("Pinging %s:%d\n", ip, static_cast<int>(ntohs(this->serverAddress.sin6_port)));

        sendto(this->sd, buffer, PingPacket::SIZE, 0, (const sockaddr *)&this->serverAddress, sizeof(this->serverAddress));

        struct sockaddr_in6 address = this->serverAddress;
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
        int bytes = recvfrom(this->sd, buffer, PingPacket::SIZE, 0, (struct sockaddr *)&address, &addressLen);
        if (bytes != PingPacket::SIZE)
        {
            return false;
        }

        PingPacket::deserialize(&pingPacket, buffer);

        return pingPacket.value == value;
    }

    void Client::setServer(const std::string &serverIpAddress, uint16_t serverPort)
    {
        // this->serverAddress.sin_addr.s_addr = inet_addr(serverIpAddress.c_str());
        inet_pton(AF_INET6, serverIpAddress.c_str(), &this->serverAddress.sin6_addr);
        this->serverAddress.sin6_port = htons(serverPort);
    }

    void Client::printServerInfo() const
    {
        char buffer[80] = {0};
        inet_ntop(AF_INET6, &this->serverAddress.sin6_addr, buffer, 80);
        printf("Server IP Address set to %s:%d\n", buffer, static_cast<int>(ntohs(this->serverAddress.sin6_port)));
    }

    void Client::sendAck(uint32_t block) {
        AckPacket ackPacket;
        ackPacket.value = block;

        uint8_t buffer[AckPacket::SIZE] = {0};
        AckPacket::serialize(buffer, &ackPacket);
        sendto(this->sd, buffer, AckPacket::SIZE, 0, (const struct sockaddr*)&this->serverAddress, sizeof(this->serverAddress));
    }

    int Client::getRequest(const std::string& localPath, const std::string& remotePath) {
        printf("Port is %d\n", (int)ntohs(this->serverAddress.sin6_port));
        int numKeys = 4;
        ReadRequestPacket readRequestPacket;
        memset(readRequestPacket.data, 0, sizeof(readRequestPacket.data));
        strcpy((char*)readRequestPacket.data, remotePath.c_str());
        strcpy((char*)readRequestPacket.data + remotePath.size() + 1, "octet");

        readRequestPacket.numKeys = numKeys;
        uint8_t buffer[1024] = {0};
        ReadRequestPacket::serialize(buffer, &readRequestPacket);
        int rc = 0;


        rc = sendto(this->sd, buffer, ReadRequestPacket::SIZE, 0, (const struct sockaddr*)&this->serverAddress, sizeof(this->serverAddress));
        if(rc < 0) {
            fprintf(stderr, "sendto() failed [%d]\n", errno);
            return 1;
        }

        int permutation = 0;
        printf("Getting keys\n");
        std::vector<Buffer> keys = this->receiveKeys(numKeys, &permutation);
        printf("Got keys\n");
        std::vector<int> order = kthPermutation(numKeys, permutation);

        uint32_t block = 1;
        struct sockaddr_in6 srcAddress;
        socklen_t srcAddressLen = sizeof(srcAddress);

        FILE* fp = fopen(localPath.c_str(), "w");
        int totalBytes = 0;
        while(true) {
            printf("Expecting block: %u\n", block);
            int rc = 0;
            rc = recvfrom(this->sd, buffer, 1024, 0, (struct sockaddr*)&srcAddress, &srcAddressLen);
            if(rc < 0) {
                printf("recvfrom() failed [%d]\n", errno);
                exit(1);
            }

            FileDataPacket fileDataPacket;
            FileDataPacket::deserialize(&fileDataPacket, buffer);

            if(fileDataPacket.packetType != e_FileData) {
                continue;
            }

            printf("Received block %d\n", fileDataPacket.blockNumber);

            if(fileDataPacket.blockNumber < block) {
                sendAck(fileDataPacket.blockNumber);
                continue;
            } else if(fileDataPacket.blockNumber > block) {
                continue;
            }

            int keyNumber = order[(block-1)%numKeys];
            printf("Key: %d\n", keyNumber);
            const Buffer& key = keys[keyNumber - 1];

            int len = rc - (sizeof(fileDataPacket.packetType) + sizeof(fileDataPacket.blockNumber));
            totalBytes += len;

            for(int i = 0; i < len; ++i) {
                fileDataPacket.data[i] ^= key[i];
            }

            fwrite(fileDataPacket.data, len, 1, fp);
            printf("Writing %d bytes\n", len);

            this->sendAck(block);

            if(len != 512) {
                break;
            }

            ++block;
        }

        fclose(fp);
        printf("Transfer finished, wrote %d bytes\n", totalBytes);

        return 0;
    }

    std::vector<Buffer> Client::receiveKeys(int n, int* k) {
        std::vector<Buffer> keys;
        uint8_t buffer[1024] = {0};
        for(int i = 0; i < n; ++i) {
            secureRecv(this->sd, buffer, KeyPacket::SIZE);
            KeyPacket keyPacket;
            KeyPacket::deserialize(&keyPacket, buffer);
            Buffer key(keyPacket.data, sizeof(keyPacket.data));
            keys.push_back(key);
            *k = keyPacket.permutation;
            printf("P: %d\n", keyPacket.permutation);
        }
        memset(buffer, 0, 1024);

        return keys;
    }
}