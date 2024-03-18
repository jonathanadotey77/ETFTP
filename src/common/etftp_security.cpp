#include "etftp_security.h"

#include "etftp_misc.h"
#include "etftp_packet.h"

#include <arpa/inet.h>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
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

    void randomMask(Buffer &buffer)
    {
        if (buffer.size() != 512)
        {
            buffer.init(512);
        }

        if (!randInitialized)
        {
            RAND_poll();
            randInitialized = true;
        }
        RAND_bytes(buffer.data(), 512);
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

    ssize_t secureSend(int fd, const uint8_t *buffer, size_t len, const struct sockaddr *address)
    {
        Buffer mask(len);
        randomMask(mask);

        HandshakePacket packet;
        packet.step = 1;
        for (size_t i=0; i<len; i++) {
            packet.data[i] = buffer[i] ^ mask[i];
        }

        uint8_t temp[HandshakePacket::SIZE] = {0};
        socklen_t addressLen = sizeof(struct sockaddr);

        HandshakePacket::serialize(temp, &packet);
        sendto(fd, temp, HandshakePacket::SIZE, 0, address, addressLen);

        struct sockaddr_in srcAddr;
        socklen_t srcAddrLen = sizeof(srcAddr);
        
        recvfrom(fd, temp, HandshakePacket::SIZE, 0, (struct sockaddr*) &srcAddr, &srcAddrLen);
        HandshakePacket::deserialize(&packet, temp);
        
        packet.step = 3;
        for (size_t i=0; i<len; i++) {
            packet.data[i] = buffer[i] ^ mask[i];
        }

        HandshakePacket::serialize(temp, &packet);
        return sendto(fd, temp, HandshakePacket::SIZE, 0, address, addressLen);
    }

    ssize_t secureRecv(int fd, uint8_t *buffer, size_t len) {
        Buffer mask(len);
        randomMask(mask);
        uint8_t temp[HandshakePacket::SIZE] = {0};

        struct sockaddr_in address;
        socklen_t addressLen = sizeof(struct sockaddr);

        HandshakePacket packet;
        memset(&packet, 0, sizeof(packet));
        recvfrom(fd, temp, len, 0, (struct sockaddr*) &address, &addressLen);
        HandshakePacket::deserialize(&packet, temp);
        packet.step = 2;
        for (size_t i=0; i<len; i++) {
            packet.data[i] = temp[i] ^ mask[i];
        }

        HandshakePacket::serialize(temp, &packet);
        sendto(fd, temp, HandshakePacket::SIZE, 0, (struct sockaddr*) &address, addressLen);

        ssize_t bytes = recvfrom(fd, temp, len, 0, (struct sockaddr*) &address, &addressLen);
        HandshakePacket::deserialize(&packet, temp);
        packet.step = 4;
        for (size_t i=0; i<len; i++) {
            buffer[i] = packet.data[i] ^ mask[i];
        }
        return bytes;
    }
}