#include "etftp_server.h"

#include "../common/etftp_buffer.h"
#include "../common/etftp_misc.h"
#include "../common/etftp_security.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <ifaddrs.h>
#include <iostream>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <string>
#include <string.h>
#include <unistd.h>

typedef struct ClientThreadArg
{
    ETFTP::Server *server;
    struct sockaddr_in6 clientAddress;
    uint16_t portIdx;
    int sd;
} ClientThreadArg;

static const std::string QUIT_MESSAGE = "QUIT_MESSAGE";

namespace ETFTP
{

    const in6_addr Server::SERVER_IP_ADDRESS = in6addr_any;
    const std::string Server::FILESYSTEM_ROOT = std::string(getenv("ETFTP_ROOT")) + "/filesystem";

    void Server::handleReadRequest(size_t portIdx, const ReadRequestPacket& requestPacket, const struct sockaddr_in6 clientAddress) {
        const socklen_t clientAddressLen = sizeof(clientAddress);
        const uint32_t numKeys = static_cast<uint32_t>(requestPacket.numKeys);
        printf("Handling read request (%d keys)\n", (int)numKeys);

        struct sockaddr_in6 srcAddress;
        socklen_t srcAddressLen = sizeof(srcAddress);

        std::string path, localPath, mode;
        path = std::string(reinterpret_cast<const char*>(requestPacket.data));
        localPath = FILESYSTEM_ROOT + "/" + path;
        mode = std::string(reinterpret_cast<const char*>(requestPacket.data + path.size() + 1));

        if(mode != "octet") {
            //Send error
            std::cerr << "Invalid mode: " << mode << std::endl;
            return;
        }

        int mySocket = this->clientSockets[portIdx];

        uint32_t randPermutation = randomInt32()%factorial(numKeys) + 1;
        std::vector<Buffer> keys = this->createAndSendKeys(numKeys, randPermutation, mySocket, &clientAddress);

        this->acquireReaderLock(path);
        printf("Reader lock acquired\n");
        std::vector<int> order = kthPermutation(numKeys, randPermutation);
        FILE* fp = fopen(localPath.c_str(), "r");
        FileDataPacket fileDataPacket;
        uint32_t block = 1;
        uint8_t buffer[FileDataPacket::SIZE] = {0};
        while(true) {
            printf("Block: %d\n", block);
            int keyNumber = order[(block-1)%numKeys];
            printf("Key: %d\n", keyNumber);
            const Buffer& key = keys[keyNumber - 1];
            std::cout << bytesToHexString(key.data(), 512) << std::endl;
            int i = fread(fileDataPacket.data, 1, 512, fp);
            for(int j = 0; j < 512; ++j) {
                fileDataPacket.data[j] ^= key[j];
            }
            printf("Read %d bytes\n", i);
            fileDataPacket.packetType = e_FileData;
            fileDataPacket.blockNumber = block;

            FileDataPacket::serialize(buffer, &fileDataPacket);
            int rc = 0;
            while(true) {
                rc = sendto(mySocket, buffer, FileDataPacket::SIZE - sizeof(fileDataPacket.data) + i, 0, (const struct sockaddr*) &clientAddress, clientAddressLen);
                if(rc < 0) {
                    printf("sendto() failed [%d]\n", errno);
                    exit(1);
                }
                bool acked = false;
                while(true) {
                    int bytes = recvfrom(mySocket, buffer, 1024, 0, (struct sockaddr*) &srcAddress, &srcAddressLen);
                    if(bytes != AckPacket::SIZE) {
                        continue;
                    }
                    AckPacket ackPacket;
                    AckPacket::deserialize(&ackPacket, buffer);
                    if(ackPacket.value != block) {
                        continue;
                    }
                    acked = true;
                    break;
                }

                if(acked) {
                    break;
                }
            }

            if(i<512 || block == UINT32_MAX) {
                break;
            }

            block++;
        }

        this->releaseReaderLock(path);

        memset(&fileDataPacket, 0, sizeof(FileDataPacket));
    }

    void *Server::clientThread(void *a)
    {
        ClientThreadArg *arg = static_cast<ClientThreadArg *>(a);
        Server *server = arg->server;
        struct sockaddr_in6 clientAddress = arg->clientAddress;
        printf("Family: %d\n", clientAddress.sin6_family);
        uint16_t portIdx = arg->portIdx;
        int sd = arg->sd;
        delete arg;

        std::string clientStr = getIpString(clientAddress);
        printf("Started thread for client %s on port %d\n", clientStr.c_str(), (int)ntohs(server->ports[portIdx].sin6_port));

        struct sockaddr_in6 sourceAddress;
        socklen_t sourceAddressLen = sizeof(sourceAddress);
        uint8_t buffer[1024];

        while (!server->isStopped())
        {
            struct pollfd pfd[1];
            pfd[0].fd = sd;
            pfd[0].events = POLLIN;
            pfd[0].revents = 0;
            memset(buffer, 0, 1024);

            int rc = poll(pfd, 1, 20000);

            if (rc == -1)
            {
                // Poll Error
                perror("Poll Error");
                break;
            }
            else if (rc == 0)
            {
                // Timeout
                break;
            }

            int bytes = recvfrom(sd, buffer, 1024, 0, (struct sockaddr *)&sourceAddress, &sourceAddressLen);
            printf("Received %d bytes from %s\n", bytes, clientStr.c_str());
            printf("Family: %d\n", sourceAddress.sin6_family);

            uint16_t packetType = ntohs(*(reinterpret_cast<uint16_t*>(buffer)));

            if(packetType == e_ReadRequest) {
                ReadRequestPacket readRequestPacket;
                ReadRequestPacket::deserialize(&readRequestPacket, buffer);
                server->handleReadRequest(portIdx, readRequestPacket, clientAddress);
            } else if(packetType == e_Ping) {
                sendto(sd, buffer, PingPacket::SIZE, 0, (const struct sockaddr*)&sourceAddress, sizeof(sourceAddress));
            }
        }

        pthread_mutex_unlock(&server->portMutex[portIdx]);
        server->clientThreadOpened[portIdx] = false;

        printf("Disconnected client %s\n", clientStr.c_str());
        return NULL;
    }

    void *Server::listenerThread(void *a)
    {
        Server *server = static_cast<Server *>(a);
        LFUCache<uint16_t, Buffer> keyTable(1024);

        struct sockaddr_in6 sourceAddr;
        socklen_t sourceAddrLen = sizeof(sourceAddr);
        uint8_t buffer[1024];
        LoginRequestPacket loginRequest;
        LoginResponsePacket loginResponse;
        while (!server->isStopped())
        {
            memset(&buffer, 0, 1024);
            memset(&loginRequest, 0, sizeof(LoginRequestPacket));
            memset(&loginResponse, 0, sizeof(LoginResponsePacket));
            loginResponse.packetType = e_LoginResponse;
            struct pollfd pfd[1];
            pfd[0].fd = server->listenerSocket;
            pfd[0].events = POLLIN;
            pfd[0].revents = 0;

            int rc = poll(pfd, 1, 2000);

            if (rc == -1)
            {
                // Poll Error
                perror("Poll Error");
                break;
            }
            else if (rc == 0)
            {
                // Timeout
                continue;
            }

            int bytes = recvfrom(server->listenerSocket, buffer, 1024, 0, (struct sockaddr *)&sourceAddr, &sourceAddrLen);

            if (bytes < 0)
            {
                if (server->stopped)
                {
                    break;
                }
                fprintf(stderr, "Recvfrom error\n");
                continue;
            }

            if (bytes != LoginRequestPacket::SIZE)
            {
                if (bytes == PingPacket::SIZE)
                {
                    PingPacket pingPacket;
                    PingPacket::deserialize(&pingPacket, buffer);
                    sendto(server->listenerSocket, buffer, bytes, 0, (const sockaddr *)&sourceAddr, sourceAddrLen);
                    printf("PING received from port %d with value %d\n", static_cast<int>(ntohs(sourceAddr.sin6_port)), static_cast<int>(pingPacket.value));
                }
                else
                {
                    printf("Received %d bytes\n", bytes);
                }
                continue;
            }

            printf("Received login request\n");

            LoginRequestPacket::deserialize(&loginRequest, buffer);

            if (loginRequest.packetType != PacketTypes::e_LoginRequest)
            {
                printf("Invalid type\n");
                continue;
            }

            if (loginRequest.step == 1)
            {
                Buffer m1(98);
                randomMask(m1);

                std::cout << m1 << std::endl;

                uint16_t r = randomInt16();
                keyTable.put(r, m1);

                for (size_t i = 0; i < 98; ++i)
                {
                    loginResponse.data[i] = loginRequest.data[i] ^ m1[i];
                }

                loginResponse.keyId = r;
                loginResponse.step = 1;
                LoginResponsePacket::serialize(buffer, &loginResponse);

                sendto(server->listenerSocket, buffer, LoginResponsePacket::SIZE, 0, (const sockaddr *)&sourceAddr, sourceAddrLen);
                continue;
            }
            else if (loginRequest.step == 2)
            {
                Buffer *m1_p = keyTable.get(loginRequest.keyId);
                if (m1_p == NULL)
                {
                    // Key not there
                    continue;
                }
                Buffer &m1 = *m1_p;
                std::cout << m1 << std::endl;
                if (m1.size() != 98)
                {
                    continue;
                }

                for (size_t i = 0; i < 98; ++i)
                {
                    loginRequest.data[i] = loginRequest.data[i] ^ m1[i];
                }
            }
            else
            {
                continue;
            }

            loginResponse.step = 2;

            // Check sucessful login
            char *user = reinterpret_cast<char *>(loginRequest.data);
            char *pass = reinterpret_cast<char *>(loginRequest.data + 33);
            user[32] = '\0';
            pass[64] = '\0';

            std::string username(user);
            std::string password(pass);
            bool loginSuccess = server->tryLogin(username, password) == LoginStatus::e_LoginSuccess;
            if (!loginSuccess)
            {
                // Login failed
                loginResponse.step = 2;
                loginResponse.port = 0;
                loginResponse.status = LoginStatus::e_LoginFailed;
                LoginResponsePacket::serialize(buffer, &loginResponse);
                sendto(server->listenerSocket, buffer, LoginResponsePacket::SIZE, 0, (const sockaddr *)&sourceAddr, sourceAddrLen);
                printf("Login failed, incorrect password\n");
                std::cout << username << std::endl;
                std::cout << username.length() << std::endl;
                continue;
            }

            // Check for open port
            bool found = false;
            uint16_t portIdx = 0;
            for (uint16_t i = 0; i < server->numPorts; ++i)
            {
                int res = pthread_mutex_trylock(&server->portMutex[i]);
                if (res == 0)
                {
                    found = true;
                    portIdx = i;
                    break;
                }
            }

            if (found)
            {
                loginResponse.port = ntohs(server->ports->sin6_port);
                loginResponse.status = LoginStatus::e_LoginSuccess;
                printf("Login success!\n");
                ClientThreadArg *arg = new ClientThreadArg;
                arg->server = server;
                arg->clientAddress = sourceAddr;
                arg->portIdx = portIdx;
                arg->sd = server->clientSockets[portIdx];
                pthread_create(&(server->clientThreads[portIdx]), NULL, clientThread, arg);
                server->clientThreadOpened[portIdx] = true;
            }
            else
            {
                loginResponse.status = LoginStatus::e_NoAvailablePort;
            }

            LoginResponsePacket::serialize(buffer, &loginResponse);

            // Send response
            sendto(server->listenerSocket, buffer, LoginResponsePacket::SIZE, 0, (const sockaddr *)&sourceAddr, sourceAddrLen);
            printf("Sent login response\n");
        }

        return NULL;
    }

    void Server::acquireReaderLock(const std::string& path) {
        serverLock.lock();
        if(this->fileLocks.find(path) == this->fileLocks.end()) {
            this->fileLocks[path];
        }
        serverLock.unlock();
        this->fileLocks[path].acquireReader();
    }

    void Server::releaseReaderLock(const std::string& path) {
        serverLock.lock();
        if(this->fileLocks.find(path) == this->fileLocks.end()) {
            this->fileLocks[path];
        }
        serverLock.unlock();
        this->fileLocks[path].releaseReader();
    }

    std::vector<Buffer> Server::createAndSendKeys(int n, int k, int sd, const struct sockaddr_in6* clientAddress) {
        std::vector<Buffer> keys(n, Buffer(512));
        printf("Sending %d keys\n", n);
        printf("Permutation: %d\n", k);
        
        for (Buffer& key : keys) {
            randomMask(key);
            KeyPacket keyPacket;
            keyPacket.packetType = e_Key;
            for (int i=0; i<512; i++) {
                keyPacket.data[i] = key[i];
            }
            keyPacket.permutation = k;
            uint8_t temp[KeyPacket::SIZE];
            KeyPacket::serialize(temp, &keyPacket);
            secureSend(sd, temp, KeyPacket::SIZE, clientAddress);
            printf("Sent key\n");
            std::cout << "Key sent:\n" << key << std::endl;
            memset(&keyPacket, 0, sizeof(KeyPacket));
            memset(&temp, 0, sizeof(temp));
        }

        printf("Sent %d keys\n", n);

        return keys;
    }

    Server::Server(uint16_t startPort, uint16_t endPort)
    {
        this->listenerPort = startPort;
        this->startPort = startPort + 1;
        this->endPort = endPort;
        this->numPorts = this->endPort - this->startPort + 1;

        this->serverAddress.sin6_family = AF_INET6;
        memcpy(&this->serverAddress.sin6_addr, &SERVER_IP_ADDRESS, sizeof(in6_addr));
        this->serverAddress.sin6_port = htons(this->listenerPort);
        this->serverAddress.sin6_flowinfo = 0;
        this->serverAddress.sin6_scope_id = 0;

        this->ports = new sockaddr_in6[this->numPorts];
        this->portMutex = new pthread_mutex_t[this->numPorts];
        this->clientSockets = new int[this->numPorts];
        this->clientThreads = new pthread_t[this->numPorts];
        this->clientThreadOpened = new bool[this->numPorts];
        this->loginSystem = LoginSystem();
        this->stopped = true;

        const uint16_t p = this->startPort + 1;
        for (uint16_t i = 0; i < this->numPorts; ++i)
        {
            memset(&(this->ports[i]), 0, sizeof(struct sockaddr_in6));
            this->ports[i].sin6_family = AF_INET6;
            memcpy(&this->ports[i].sin6_addr, &SERVER_IP_ADDRESS, sizeof(in6_addr));
            this->ports[i].sin6_port = htons(p + i);
            this->clientThreads[i] = 0;
            this->clientThreadOpened[i] = false;

            pthread_mutex_init(&(this->portMutex[i]), NULL);
        }
    }

    Server::~Server()
    {
        delete[] this->ports;
        delete[] this->portMutex;
        delete[] this->clientSockets;
        delete[] this->clientThreads;
        delete[] this->clientThreadOpened;
    }

    bool Server::isStopped() const
    {
        return this->stopped;
    }

    bool Server::start()
    {
        this->stopped = false;
        if (!this->loginSystem.start())
        {
            std::cerr << "Failed to start login system" << std::endl;
            return false;
        }

        this->listenerSocket = socket(AF_INET6, SOCK_DGRAM, 0);
        if (bind(this->listenerSocket, (const sockaddr *)&this->serverAddress, sizeof(this->serverAddress)) < 0)
        {
            perror("Bind() failed\n");
            return false;
        }

        for (uint16_t i = 0; i < this->numPorts; ++i)
        {
            this->clientSockets[i] = socket(AF_INET6, SOCK_DGRAM, 0);
            if (bind(this->clientSockets[i], (const sockaddr *)&this->ports[i], sizeof(this->ports[i])) < 0)
            {
                printf("Failed to bind socket [%d]\n", errno);
                close(this->clientSockets[i]);
                for (uint16_t j = 0; j < i; ++j)
                {
                    close(this->clientSockets[j]);
                }

                return false;
            }
        }

        pthread_create(&this->listenerThreadId, NULL, Server::listenerThread, static_cast<void *>(this));

        std::cout << "Start successful" << std::endl;

        return true;
    }

    bool Server::stop()
    {
        printf("Stopping server...\n");
        this->loginSystem.stop();
        this->stopped = true;
        close(this->listenerSocket);
        pthread_join(this->listenerThreadId, NULL);

        for (int i = 0; i < this->numPorts; ++i)
        {
            pthread_mutex_lock(&this->portMutex[i]);
            if (this->clientThreadOpened[i])
            {
                pthread_join(this->clientThreads[i], NULL);
            }
        }

        for (int i = 0; i < this->numPorts; ++i)
        {
            close(this->clientSockets[i]);
        }

        printf("Server stopped\n");
        return true;
    }

    LoginStatus Server::tryLogin(const std::string &username, const std::string &password)
    {
        return this->loginSystem.tryLogin(username, password);
    }

    LoginStatus Server::registerUser(const std::string &username, const std::string &password)
    {
        return this->loginSystem.registerUser(username, password);
    }

    LoginStatus Server::changePassword(const std::string &username,
                                       const std::string &oldPassword,
                                       const std::string &newPassword)
    {
        return this->loginSystem.changePassword(username, oldPassword, newPassword);
    }

}