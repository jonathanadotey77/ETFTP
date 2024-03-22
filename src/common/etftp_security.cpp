#include "etftp_security.h"

#include "etftp_misc.h"
#include "etftp_packet.h"

#include <arpa/inet.h>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <poll.h>
#include <random>
#include <sstream>
#include <string>
#include <string.h>

namespace ETFTP
{

    static bool randInitialized = false;

    uint16_t randomInt16()
    {
        if (!randInitialized)
        {
            RAND_poll();
            randInitialized = true;
        }

        uint16_t r = 0;
        RAND_bytes(reinterpret_cast<unsigned char *>(&r), 2);

        return r;
    }

    uint32_t randomInt32() {
        if (!randInitialized)
        {
            RAND_poll();
            randInitialized = true;
        }

        uint32_t r = 0;
        RAND_bytes(reinterpret_cast<unsigned char *>(&r), 4);

        return r;
    }

    void randomMask(Buffer &buffer)
    {
        if (buffer.size() == 0)
        {
            buffer.init(512);
        }

        if (!randInitialized)
        {
            RAND_poll();
            randInitialized = true;
        }
        RAND_bytes(buffer.data(), buffer.size());
    }

    void hashPassword(const std::string &password, std::string &hashedPassword)
    {
        unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        unsigned int md_len;

        OpenSSL_add_all_algorithms();
        md = EVP_get_digestbyname("sha256");

        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, password.c_str(), password.length());
        EVP_DigestFinal_ex(mdctx, digest, &md_len);
        EVP_MD_CTX_free(mdctx);

        hashedPassword = bytesToHexString(digest, SHA256_DIGEST_LENGTH);
    }

    bool validPassword(const std::string &password)
    {
        if (password.length() < 8 || password.length() > 32)
        {
            return false;
        }

        return true;
    }

    std::string getSalt()
    {
        uint8_t buffer[8] = {0};
        RAND_bytes(buffer, 8);
        return bytesToHexString(buffer, 8);
    }

    std::string saltedHash(const std::string &hashedPassword, const std::string &salt)
    {
        std::string salted;
        hashPassword(hashedPassword + salt, salted);
        return salted;
    }

    // For secureSend and secureRecv, error is set to:
    // 0 if operation completed successfully
    // 1 if operation if there was a timeout
    // 2 if there was a poll error

    ssize_t secureSend(int fd, const uint8_t *buffer, const struct sockaddr_in6 *address, int* error)
    {
        size_t dataLen = sizeof(HandshakePacket::data);
        Buffer mask(dataLen);
        randomMask(mask);

        HandshakePacket packet;
        memset(&packet, 0, sizeof(HandshakePacket));
        packet.step = 1;
        for (size_t i=0; i<dataLen; i++) {
            packet.data[i] = buffer[i] ^ mask[i];
        }

        uint8_t temp[HandshakePacket::SIZE] = {0};
        socklen_t addressLen = sizeof(struct sockaddr_in6);

        HandshakePacket::serialize(temp, &packet);

        int rc = 0;

        rc = sendto(fd, temp, HandshakePacket::SIZE, 0, (const struct sockaddr*)address, addressLen);
        if(rc < 0) {
            printf("sendto() failed [%d]\n", errno);
            return -1;
        }

        struct sockaddr_in6 srcAddr;
        socklen_t srcAddrLen = sizeof(srcAddr);

        if(error != NULL) {
            *error = 0;
        }
        
        struct pollfd fds[1];
        fds[0].fd = fd;
        fds[0].events = POLLIN;

        rc = poll(fds, 1, 3000);

        if(rc < 0) {
            if(error != NULL) {
                *error = 2;
            }
            printf("poll() error\n");
            return -1;
        } else if(rc == 0) {
            if(error != NULL) {
                *error = 1;
            }
            return -1;
        }

        rc = recvfrom(fd, temp, HandshakePacket::SIZE, 0, (struct sockaddr*) &srcAddr, &srcAddrLen);
        if(rc < 0) {
            printf("recvfrom() failed [%d]\n", errno);
            return -1;
        }
        HandshakePacket::deserialize(&packet, temp);
        
        packet.step = 3;
        for (size_t i=0; i<dataLen; i++) {
            packet.data[i] ^= mask[i];
        }

        HandshakePacket::serialize(temp, &packet);
        rc = sendto(fd, temp, HandshakePacket::SIZE, 0, (const struct sockaddr*)address, addressLen);
        if(rc < 0) {
            printf("sendto() failed [%d]\n", errno);
        }

        return rc;
    }

    ssize_t secureRecv(int fd, uint8_t *buffer, size_t len, int* error) {
        size_t dataLen = sizeof(HandshakePacket::data);
        Buffer mask(dataLen);
        randomMask(mask);
        uint8_t temp[HandshakePacket::SIZE] = {0};

        struct sockaddr_in6 address;
        socklen_t addressLen = sizeof(address);

        HandshakePacket packet;
        memset(&packet, 0, sizeof(packet));

        int rc = 0;

        struct pollfd fds[1];
        fds[0].fd = fd;
        fds[0].events = POLLIN;

        if(error != NULL) {
            *error = 0;
        }

        rc = poll(fds, 1, 3000);

        if(rc < 0) {
            if(error != NULL) {
                *error = 2;
            }
            printf("poll() error\n");
            return -1;
        } else if(rc == 0) {
            if(error != NULL) {
                *error = 1;
            }
            return -1;
        }

        rc = recvfrom(fd, temp, HandshakePacket::SIZE, 0, (struct sockaddr*) &address, &addressLen);    
        if(rc < 0) {
            printf("recvfrom() failed [%d]\n", errno);
        }

        HandshakePacket::deserialize(&packet, temp);
        packet.step = 2;
        for (size_t i = 0; i<dataLen; i++) {
            packet.data[i] ^= mask[i];
        }

        HandshakePacket::serialize(temp, &packet);
        rc = sendto(fd, temp, HandshakePacket::SIZE, 0, (struct sockaddr*) &address, addressLen);
        if(rc < 0) {
            printf("sendto() failed [%d]\n", errno);
        }

        fds[0].fd = fd;
        fds[0].events = POLLIN;

        rc = poll(fds, 1, 3000);

        if(rc < 0) {
            if(error != NULL) {
                *error = 2;
            }
            printf("poll() error\n");
            return -1;
        } else if(rc == 0) {
            if(error != NULL) {
                *error = 1;
            }
            return -1;
        }

        ssize_t bytes = recvfrom(fd, temp, HandshakePacket::SIZE, 0, (struct sockaddr*) &address, &addressLen);
        if(rc < 0) {
            printf("recvfrom() failed [%d]\n", errno);
        }
        HandshakePacket::deserialize(&packet, temp);
        packet.step = 4;
        for (size_t i=0; i<len; i++) {
            buffer[i] = packet.data[i] ^ mask[i];
        }

        return bytes;
    }
}