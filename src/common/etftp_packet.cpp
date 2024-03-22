#include "etftp_packet.h"

#include <arpa/inet.h>
#include <string.h>

namespace ETFTP
{

    void ReadRequestPacket::serialize(uint8_t *dest, const ReadRequestPacket *src)
    {
        uint16_t *packetType = reinterpret_cast<uint16_t *>(dest);
        uint8_t *numKeys = reinterpret_cast<uint8_t *>(dest + 2);

        *packetType = htons(src->packetType);
        *numKeys = src->numKeys;
        memcpy(dest + 3, src->data, 515);
    }
    void ReadRequestPacket::deserialize(ReadRequestPacket *dest, const uint8_t *src)
    {
        const uint16_t *packetType = reinterpret_cast<const uint16_t *>(src);
        const uint8_t *numKeys = reinterpret_cast<const uint8_t *>(src + 2);

        dest->packetType = ntohs(*packetType);
        dest->numKeys = *numKeys;
        memcpy(dest->data, src + 3, 515);
    }

    void FileDataPacket::serialize(uint8_t *dest, const FileDataPacket *src)
    {
        uint16_t *packetType = reinterpret_cast<uint16_t *>(dest);
        uint32_t *blockNumber = reinterpret_cast<uint32_t *>(dest + 2);

        *packetType = htons(src->packetType);
        *blockNumber = htonl(src->blockNumber);
        memcpy(dest + 6, src->data, 512);
    }
    void FileDataPacket::deserialize(FileDataPacket *dest, const uint8_t *src)
    {
        uint16_t packetType = ntohs(*(reinterpret_cast<const uint16_t *>(src)));
        uint32_t blockNumber = ntohl(*(reinterpret_cast<const uint32_t *>(src + 2)));

        dest->packetType = packetType;
        dest->blockNumber = blockNumber;
        memcpy(dest->data, src + 6, 512);
    }

    void AckPacket::serialize(uint8_t *dest, const AckPacket *src)
    {
        uint16_t *packetType = reinterpret_cast<uint16_t *>(dest);
        uint32_t *value = reinterpret_cast<uint32_t *>(dest + 2);

        *packetType = htons(src->packetType);
        *value = htonl(src->value);
    }
    void AckPacket::deserialize(AckPacket *dest, const uint8_t *src)
    {
        uint16_t packetType = ntohs(*(reinterpret_cast<const uint16_t *>(src)));
        uint32_t value = ntohl(*(reinterpret_cast<const uint32_t *>(src + 2)));

        dest->packetType = packetType;
        dest->value = value;
    }

    void LoginRequestPacket::serialize(uint8_t *dest, const LoginRequestPacket *src)
    {
        uint16_t *packetType = reinterpret_cast<uint16_t *>(dest);
        uint16_t *step = reinterpret_cast<uint16_t *>(dest + 2);
        uint16_t *keyId = reinterpret_cast<uint16_t *>(dest + 4);

        *packetType = htons(src->packetType);
        *step = htons(src->step);
        *keyId = htons(src->keyId);
        memcpy(dest + 6, src->data, 98);
    }
    void LoginRequestPacket::deserialize(LoginRequestPacket *dest, const uint8_t *src)
    {
        uint16_t packetType = ntohs(*(reinterpret_cast<const uint16_t *>(src)));
        uint16_t step = ntohs(*(reinterpret_cast<const uint16_t *>(src + 2)));
        uint16_t keyId = ntohs(*(reinterpret_cast<const uint16_t *>(src + 4)));

        dest->packetType = packetType;
        dest->step = step;
        dest->keyId = keyId;
        memcpy(dest->data, src + 6, 98);
    }

    void LoginResponsePacket::serialize(uint8_t *dest, const LoginResponsePacket *src)
    {
        uint16_t *packetType = reinterpret_cast<uint16_t *>(dest);
        uint16_t *step = reinterpret_cast<uint16_t *>(dest + 2);
        uint16_t *keyId = reinterpret_cast<uint16_t *>(dest + 4);
        uint16_t *status = reinterpret_cast<uint16_t *>(dest + 6);
        uint16_t *port = reinterpret_cast<uint16_t *>(dest + 8);

        *packetType = htons(src->packetType);
        *step = htons(src->step);
        *keyId = htons(src->keyId);
        *status = htons(src->status);
        *port = htons(src->port);
        memcpy(dest + 10, src->data, 98);
    }

    void LoginResponsePacket::deserialize(LoginResponsePacket *dest, const uint8_t *src)
    {
        uint16_t packetType = ntohs(*(reinterpret_cast<const uint16_t *>(src)));
        uint16_t step = ntohs(*(reinterpret_cast<const uint16_t *>(src + 2)));
        uint16_t keyId = ntohs(*(reinterpret_cast<const uint16_t *>(src + 4)));
        uint16_t status = ntohs(*(reinterpret_cast<const uint16_t *>(src + 6)));
        uint16_t port = ntohs(*(reinterpret_cast<const uint16_t *>(src + 8)));

        dest->packetType = packetType;
        dest->step = step;
        dest->keyId = keyId;
        dest->status = status;
        dest->port = port;
        memcpy(dest->data, src + 10, 98);
    }

    void PingPacket::serialize(uint8_t *dest, const PingPacket *src)
    {
        uint16_t *packetType = reinterpret_cast<uint16_t *>(dest);
        uint16_t *value = reinterpret_cast<uint16_t *>(dest + 2);

        *packetType = htons(src->packetType);
        *value = htons(src->value);
    }

    void PingPacket::deserialize(PingPacket *dest, const uint8_t *src)
    {
        uint16_t packetType = ntohs(*(reinterpret_cast<const uint16_t *>(src)));
        uint16_t value = ntohs(*(reinterpret_cast<const uint16_t *>(src + 2)));

        dest->packetType = packetType;
        dest->value = value;
    }

    void LogoutPacket::serialize(uint8_t *dest, const LogoutPacket *src)
    {
        uint16_t *packetType = reinterpret_cast<uint16_t *>(dest);

        *packetType = htons(src->packetType);
    }

    void LogoutPacket::deserialize(LogoutPacket *dest, const uint8_t *src)
    {
        uint16_t packetType = ntohs(*(reinterpret_cast<const uint16_t *>(src)));

        dest->packetType = packetType;
    }

    void KeyPacket::serialize(uint8_t *dest, const KeyPacket *src)
    {
        uint16_t *packetType = reinterpret_cast<uint16_t *>(dest);
        uint16_t *step = reinterpret_cast<uint16_t *>(dest + 2);
        uint32_t *permutation = reinterpret_cast<uint32_t *>(dest + 4);

        *packetType = htons(src->packetType);
        *step = htons(src->step);
        *permutation = htonl(src->permutation);
        memcpy(dest + 8, src->data, 512);
    }

    void KeyPacket::deserialize(KeyPacket *dest, const uint8_t *src)
    {
        uint16_t packetType = ntohs(*(reinterpret_cast<const uint16_t *>(src)));
        uint16_t step = ntohs(*(reinterpret_cast<const uint16_t *>(src + 2)));
        uint32_t permutation = ntohl(*(reinterpret_cast<const uint32_t *>(src + 4)));

        dest->packetType = packetType;
        dest->step = step;
        dest->permutation = permutation;
        memcpy(dest->data, src + 8, 512);
    }

    void HandshakePacket::serialize(uint8_t *dest, const HandshakePacket *src)
    {
        uint16_t *packetType = reinterpret_cast<uint16_t *>(dest);
        uint16_t *step = reinterpret_cast<uint16_t *>(dest + 2);

        *packetType = htons(src->packetType);
        *step = htons(src->step);
        memcpy(dest + 4, src->data, 520);
    }

    void HandshakePacket::deserialize(HandshakePacket *dest, const uint8_t *src)
    {
        uint16_t packetType = ntohs(*(reinterpret_cast<const uint16_t *>(src)));
        uint16_t step = ntohs(*(reinterpret_cast<const uint16_t *>(src + 2)));

        dest->packetType = packetType;
        dest->step = step;
        memcpy(dest->data, src + 4, 520);
    }
}