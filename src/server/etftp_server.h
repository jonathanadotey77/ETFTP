#ifndef ETFTP_SERVER_H
#define ETFTP_SERVER_H

#include "etftp_filemutex.h"
#include "../common/etftp_loginsystem.h"
#include "etftp_lfucache.h"
#include "../common/etftp_buffer.h"

#include <arpa/inet.h>
#include <mutex>
#include <pthread.h>
#include <stdint.h>
#include <unordered_map>

namespace ETFTP
{

    class Server
    {
    public:
        static const in_addr_t SERVER_IP_ADDRESS;
        static const std::string FILESYSTEM_ROOT;

    private:
        struct sockaddr_in *ports;
        pthread_mutex_t *portMutex;
        int *clientSockets;
        pthread_t *clientThreads;
        volatile bool *clientThreadOpened;

        pthread_t listenerThreadId;
        uint16_t numPorts;
        int listenerSocket = -1;
        uint16_t listenerPort;
        uint16_t startPort;
        uint16_t endPort;

        struct sockaddr_in serverAddress;

        std::mutex serverLock;
        std::unordered_map<std::string, FileMutex> fileLocks;

        LoginSystem loginSystem;

        volatile bool stopped;

    public:
        Server(uint16_t startPort, uint16_t endPort);
        ~Server();

        bool start();
        bool stop();
        bool isStopped() const;

        LoginSystem::Status tryLogin(const std::string &username, const std::string &password);
        LoginSystem::Status registerUser(const std::string &username, const std::string &password);
        LoginSystem::Status changePassword(const std::string &username,
                                           const std::string &oldPassword,
                                           const std::string &newPassword);

    public:
        static void *listenerThread(void *a);
        static void *clientThread(void *a);
    };

}

#endif