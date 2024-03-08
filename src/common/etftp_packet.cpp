#include "etftp_packet.h"
#include "string.h"
#include <arpa/inet.h>

namespace ETFTP
{
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
        uint32_t permutation = ntohs(*(reinterpret_cast<const uint32_t *>(src + 4)));

        dest->packetType = packetType;
        dest->step = step;
        dest->permutation = permutation;
        memcpy(dest->data, src + 8, 512);
    }
}