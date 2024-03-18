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
    struct sockaddr_in clientAddress;
    uint16_t portIdx;
    int sd;
} ClientThreadArg;

namespace ETFTP
{

    const in_addr_t Server::SERVER_IP_ADDRESS = INADDR_ANY;
    const std::string Server::FILESYSTEM_ROOT = std::string(getenv("ETFTP_ROOT")) + "/filesystem";

    void Server::handleReadRequest(size_t portIdx, const ReadRequestPacket& requestPacket, struct sockaddr_in clientAddress) {
        const socklen_t clientAddressLen = sizeof(struct sockaddr);
        uint32_t numKeys = requestPacket.numKeys;

        struct sockaddr_in srcAddress;
        socklen_t srcAddressLen = sizeof(srcAddress);

        int mySocket = this->clientSockets[portIdx];

        std::vector<Buffer> keys(numKeys, Buffer(512));
        uint32_t randPermutation = randomInt32()%factorial(numKeys);
        for (Buffer& key : keys) {
            randomMask(key);
            KeyPacket keyPacket;
            keyPacket.packetType = e_Key;
            for (int i=0; i<512; i++) {
                keyPacket.data[i] = key[i];
            }
            keyPacket.permutation = randPermutation;
            uint8_t temp[KeyPacket::SIZE];
            KeyPacket::serialize(temp, &keyPacket);
            secureSend(mySocket, temp, KeyPacket::SIZE, (struct sockaddr*) &clientAddress);
            memset(&keyPacket, 0, sizeof(KeyPacket));
            memset(&temp, 0, sizeof(temp));
        }

        std::string path, mode;
        path = std::string(reinterpret_cast<const char*>(requestPacket.data));
        mode = std::string(reinterpret_cast<const char*>(requestPacket.data + path.size() + 1));

        if(mode != "octet") {
            return;
        }

        this->acquireReaderLock(path);
        std::vector<int> order = kthPermutation(numKeys, randPermutation);
        FILE* fp = fopen(path.c_str(), "r");
        FileDataPacket fileDataPacket;
        uint32_t block = 1;
        uint8_t buffer[FileDataPacket::SIZE] = {0};
        while(true) {
            int i = 0;
            int8_t ch = fgetc(fp);
            Buffer& key = keys[order[(block-1)%numKeys] - 1];
            for (; i<512 && ch != EOF; i++, ch=fgetc(fp)) {
                fileDataPacket.data[i] = ch ^ key[i];
            }

            FileDataPacket::serialize(buffer, &fileDataPacket);
            while(true) {
                sendto(mySocket, buffer, FileDataPacket::SIZE - sizeof(fileDataPacket.data) + i, 0, (const struct sockaddr*) &clientAddress, clientAddressLen);
                bool acked = false;
                while(true) {
                    int bytes = recvfrom(mySocket, buffer, AckPacket::SIZE, 0, (struct sockaddr*) &srcAddress, &srcAddressLen);
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

        memset(&fileDataPacket, 0, sizeof(FileDataPacket));
    }

    void *Server::clientThread(void *a)
    {
        ClientThreadArg *arg = static_cast<ClientThreadArg *>(a);
        Server *server = arg->server;
        struct sockaddr_in clientAddress = arg->clientAddress;
        uint16_t portIdx = arg->portIdx;
        int sd = arg->sd;
        delete arg;

        std::string clientStr = getIpString(clientAddress);
        printf("Started thread for client %s\n", clientStr.c_str());

        struct sockaddr_in sourceAddress;
        socklen_t sourceAddressLen = sizeof(sourceAddress);
        uint8_t buffer[518];

        while (!server->isStopped())
        {
            struct pollfd pfd[1];
            pfd[0].fd = sd;
            pfd[0].events = POLLIN;
            pfd[0].revents = 0;
            memset(buffer, 0, 518);

            int rc = poll(pfd, 1, 10000);

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

            int bytes = recvfrom(sd, buffer, 518, 0, (struct sockaddr *)&sourceAddress, &sourceAddressLen);
            printf("Received %d bytes from %s\n", bytes, clientStr.c_str());

            uint16_t packetType = ntohs(*(reinterpret_cast<uint16_t*>(buffer)));

            if(packetType == e_ReadRequest) {
                ReadRequestPacket readRequestPacket;
                ReadRequestPacket::deserialize(&readRequestPacket, buffer);
                server->handleReadRequest(portIdx, readRequestPacket, clientAddress);
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

        struct sockaddr_in sourceAddr;
        socklen_t sourceAddrLen = sizeof(sourceAddr);
        uint8_t buffer[1024];
        LoginRequestPacket loginRequest;
        LoginResponsePacket loginResponse;
        while (!server->isStopped())
        {
            memset(&buffer, 0, LoginRequestPacket::SIZE);
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

            int bytes = recvfrom(server->listenerSocket, buffer, LoginRequestPacket::SIZE, 0, (struct sockaddr *)&sourceAddr, &sourceAddrLen);

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
                    printf("PING received from port %d with value %d\n", static_cast<int>(ntohs(sourceAddr.sin_port)), static_cast<int>(pingPacket.value));
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
                loginResponse.port = server->ports->sin_port;
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

    Server::Server(uint16_t startPort, uint16_t endPort)
    {
        this->listenerPort = startPort;
        this->startPort = startPort + 1;
        this->endPort = endPort;
        this->numPorts = this->endPort - this->startPort + 1;
        this->serverAddress.sin_family = AF_INET;
        this->serverAddress.sin_addr.s_addr = SERVER_IP_ADDRESS;
        this->serverAddress.sin_port = htons(this->listenerPort);
        this->ports = new sockaddr_in[this->numPorts];
        this->portMutex = new pthread_mutex_t[this->numPorts];
        this->clientSockets = new int[this->numPorts];
        this->clientThreads = new pthread_t[this->numPorts];
        this->clientThreadOpened = new bool[this->numPorts];
        this->loginSystem = LoginSystem();
        this->stopped = true;

        const uint16_t p = this->startPort + 1;
        for (int i = 0; i < this->numPorts; ++i)
        {
            memset(&(this->ports[i]), 0, sizeof(struct sockaddr_in));
            this->ports[i].sin_family = AF_INET;
            this->ports[i].sin_addr.s_addr = Server::SERVER_IP_ADDRESS;
            this->ports[i].sin_port = htons(p + i);
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

        this->listenerSocket = socket(AF_INET, SOCK_DGRAM, 0);
        if (bind(this->listenerSocket, (const sockaddr *)&this->serverAddress, sizeof(this->serverAddress)) < 0)
        {
            perror("Bind() failed\n");
            return false;
        }

        for (uint16_t i = 0; i < this->numPorts; ++i)
        {
            this->clientSockets[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (bind(this->clientSockets[i], (const sockaddr *)&this->ports[i], sizeof(this->ports[i])) < 0)
            {
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