#include <iostream>
#include <poll.h>
#include <unistd.h>
#include <string>
#include <pthread.h>
#include <string>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "etftp_server.h"
#include "../common/etftp_security.h"
#include "../common/etftp_packet.h"

// Login
// Forks

in_addr_t getIpAddress() {
    // char hostname[256];
    // if (gethostname(hostname, sizeof(hostname)) != 0) {
    //     std::cerr << "Error getting hostname" << std::endl;
    //     exit(EXIT_FAILURE);
    // }

    // struct hostent* host = gethostbyname(hostname);
    // if (host == nullptr || host->h_addr_list[0] == nullptr) {
    //     std::cerr << "Error getting host IP" << std::endl;
    //     exit(EXIT_FAILURE);
    // }

    // return *((in_addr_t*)host->h_addr_list[0]);

    struct ifaddrs* ifAddrStruct = nullptr;
    struct ifaddrs* ifa = nullptr;
    void* tmpAddrPtr = nullptr;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET && (ifa->ifa_flags & IFF_LOOPBACK) == 0) {
            tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);

            // Assuming the first non-loopback IPv4 address found is the public IP
            freeifaddrs(ifAddrStruct);
            in_addr_t ipAddress;
            inet_pton(AF_INET, addressBuffer, &ipAddress);
            return ipAddress;
        }
    }
    
    if (ifAddrStruct != nullptr) {
        freeifaddrs(ifAddrStruct);
    }

    std::cerr << "Failed to get public IP" << std::endl;
    // exit(EXIT_FAILURE);
    return INADDR_ANY;
}

namespace ETFTP
{

const in_addr_t Server::SERVER_IP_ADDRESS = getIpAddress();
const std::string Server::FILESYSTEM_ROOT = std::string(getenv("ETFTP_ROOT")) + "/filesystem";

void* Server::clientThread(void* a) {
    if(!a) {
        return NULL;
    }
    return NULL;
}

void* Server::listenerThread(void* a) {
    Server* server = static_cast<Server*>(a);

    struct sockaddr_in source_addr;
    socklen_t source_addr_len;
    LoginRequestPacket_t loginRequest;
    LoginResponsePacket_t loginResponse;
    while(!server->isStopped()) {
        memset(&loginRequest, 0, sizeof(LoginRequestPacket_t));
        memset(&loginResponse, 0, sizeof(LoginResponsePacket_t));
        loginRequest.packetType = e_LoginRequest;
        loginResponse.packetType = e_LoginResponse;
        struct pollfd pfd[1];
        pfd[0].fd = server->listenerSocket;
        pfd[0].events = POLLIN;
        pfd[0].revents = 0;

        int rc = poll(pfd, 1, 2000);

        if(rc == -1) {
            //Poll Error
            perror("Poll Error");
            break;
        } else if(rc == 0) {
            //Timeout
            continue;
        }

        int bytes = recvfrom(server->listenerSocket, &loginRequest, sizeof(loginRequest), 0, (struct sockaddr*)&source_addr, &source_addr_len);

        if(bytes < 0) {
            //Error
            continue;
        }

        if(bytes != sizeof(LoginRequestPacket_t)) {
            //Error
            continue;
        }

        loginRequest.packetType = ntohs(loginRequest.packetType); 
        loginRequest.username[32] = '\0';
        loginRequest.password[64] = '\0';

        if(loginRequest.packetType != PacketTypes::e_LoginRequest) {
            //Error
            continue;
        }

        //Check sucessful login
        std::string username(loginRequest.username);
        std::string password(loginRequest.password);
        loginResponse.packetType = PacketTypes::e_LoginResponse;
        bool loginSuccess = server->loginSystem.tryLogin(username, password) == 1;
        if(!loginSuccess) {
            //Login failed
            loginResponse.port = 0;
            loginResponse.status = 0;
            sendto(server->listenerSocket, &loginResponse, sizeof(loginResponse), 0, (const sockaddr*)&source_addr, source_addr_len);
            continue;
        }

        //Check for open port
        bool found = false;
        uint16_t portIdx = 0;
        for(uint16_t i = 0; i < server->numPorts; ++i) {
            int res = pthread_mutex_trylock(&server->portMutex[i]);
            if(res == 0) {
                found = true;
                portIdx = i;
                break;
            }
        }

        if(!found) {
            //No port found
            loginResponse.port = 0;
            loginResponse.status = htons(2);
            sendto(server->listenerSocket, &loginResponse, sizeof(loginResponse), 0, (const sockaddr*)&source_addr, source_addr_len);
            continue;
        }

        //Send success with port
        loginResponse.port = htons(portIdx);
        loginResponse.status = htons(1);
        sendto(server->listenerSocket, &loginResponse, sizeof(loginResponse), 0, (const sockaddr*)&source_addr, source_addr_len); 
    }

    return NULL;
}

Server::Server(uint16_t startPort, uint16_t endPort)
{
    this->listenerPort = startPort;
    this->startPort = startPort+1;
    this->endPort = endPort;
    this->numPorts = this->endPort - this->startPort + 1;
    this->serverAddress.sin_family = AF_INET;
    this->serverAddress.sin_addr.s_addr = SERVER_IP_ADDRESS;
    this->serverAddress.sin_port = htons(this->startPort);
    this->ports = new sockaddr_in[this->numPorts];
    this->portMutex = new pthread_mutex_t[this->numPorts];
    this->clientSockets = new int[this->numPorts];
    this->clientThreads = new pthread_t[this->numPorts];
    this->loginSystem = LoginSystem();
    this->stopped = true;

    const uint16_t p = this->startPort + 1;
    for(int i = 0; i < this->numPorts; ++i) {
        memset(&(this->ports[i]), 0, sizeof(struct sockaddr_in));
        this->ports[i].sin_family = AF_INET;
        this->ports[i].sin_addr.s_addr = Server::SERVER_IP_ADDRESS;
        this->ports[i].sin_port = htons(p + i);

        pthread_mutex_init(&(this->portMutex[i]), NULL);
    }
}

Server::~Server()
{
    delete [] this->ports;
    delete [] this->portMutex;
    delete [] this->clientSockets;
    delete [] this->clientThreads;
}

bool Server::isStopped() const {
    return this->stopped;
}

bool Server::start()
{
    this->stopped = false;
    if(!this->loginSystem.start()) {
        std::cerr << "Failed to start login system" << std::endl;
        return false;
    }

    this->listenerSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if(bind(this->listenerSocket, (const sockaddr*)&this->serverAddress, sizeof(this->serverAddress)) < 0) {
        return false;
    }

    for(uint16_t i = 0; i < this->numPorts; ++i) {
        this->clientSockets[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if(bind(this->clientSockets[i], (const sockaddr*)&this->ports[i], sizeof(this->ports[i])) < 0) {
            close(this->clientSockets[i]);
            for(uint16_t j = 0; j < i; ++j) {
                close(this->clientSockets[j]);
            }

            return false;
        }
    }

    pthread_create(&this->listenerThreadId, NULL, Server::listenerThread, static_cast<void*>(this));

    std::cout << "Start successful" << std::endl;

    return true;
}

bool Server::stop()
{
    this->loginSystem.stop();
    this->stopped = true;
    close(this->listenerSocket);
    for(int i = 0; i < this->numPorts; ++i) {
        close(this->clientSockets[i]);
    }

    pthread_join(this->listenerThreadId, NULL);
    return true;
}

ETFTP::LoginSystem::Status Server::registerUser(const std::string& username, const std::string& password) {
    return this->loginSystem.registerUser(username, password);
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

    if(endPort <= startPort || endPort - startPort + 1 < 11) {
        fprintf(stderr, "Invalid port range, must have at least 11 ports\n");
        return 1;
    }



    ETFTP::Server server(static_cast<uint16_t>(startPort), static_cast<uint16_t>(endPort));

    bool started = server.start();
    if(!started) {
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

        if(input == "print") {
            std::cin >> input;
            if(input == "ip") {
                inet_ntop(AF_INET, &ETFTP::Server::SERVER_IP_ADDRESS, buffer, 80);
                printf("%s\n", buffer);
            } else {
                continue;
            }
        } else if(input == "register") {
            std::string username;
            std::string password, hashedPassword;
            std::cin >> username >> password;
            ETFTP::computeHash(password, hashedPassword);
            ETFTP::LoginSystem::Status rc = server.registerUser(username, hashedPassword);

            if(rc == ETFTP::LoginSystem::Status::e_Success) {
                printf("Successfully registered user '%s'\n", username.c_str());
            } else {
                printf("User '%s' already exists\n", username.c_str());
            }

        }
    }

    server.stop();

    return 0;
}