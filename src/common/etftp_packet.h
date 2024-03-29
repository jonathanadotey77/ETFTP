#ifndef ETFTP_PACKET_H
#define ETFTP_PACKET_H

#include <stdint.h>
#include <string.h>

namespace ETFTP
{

    enum PacketTypes
    {
        e_ReadRequest = 1,
        e_WriteRequest = 2,
        e_FileData = 3,
        e_Ack = 4,
        e_Error = 5,
        e_Logout = 6,
        e_LoginRequest = 7,
        e_LoginResponse = 8,
        e_Ping = 9,
        e_Key = 10,
        e_Handshake = 11
    };

    typedef struct ReadRequestPacket
    {
        uint16_t packetType = e_ReadRequest;
        uint8_t numKeys;
        int8_t data[515];

        static const size_t SIZE = sizeof(packetType) + sizeof(numKeys) + sizeof(data);
        static void serialize(uint8_t* dest, const ReadRequestPacket* src);
        static void deserialize(ReadRequestPacket* dest, const uint8_t* src);
    } ReadRequestPacket;

    typedef struct WriteRequestPacket
    {
        uint16_t packetType = e_WriteRequest;
        uint8_t numKeys;
        int8_t data[515];

        static const size_t SIZE = sizeof(packetType) + sizeof(numKeys) + sizeof(data);
    } WriteRequestPacket;

    typedef struct ErrorPacket
    {
        uint16_t packetType = e_Error;
        uint16_t errorCode;
        int8_t message[257];

        static const size_t SIZE = sizeof(packetType) + sizeof(errorCode) + sizeof(message);
        static void serialize(uint8_t* dest, const ErrorPacket* src);
        static void deserialize(ErrorPacket* dest, const uint8_t* src);
    } ErrorPacket;

    typedef struct FileDataPacket
    {
        uint16_t packetType = e_FileData;
        uint32_t blockNumber;
        uint8_t data[512];

        static const size_t SIZE = sizeof(packetType) + sizeof(blockNumber) + sizeof(data);
        static void serialize(uint8_t* dest, const FileDataPacket* src);
        static void deserialize(FileDataPacket* dest, const uint8_t* src);
    } FileDataPacket;

    typedef struct AckPacket
    {
        uint16_t packetType = e_Ack;
        uint32_t value;

        static const size_t SIZE = sizeof(packetType) + sizeof(value);
        static void serialize(uint8_t* dest, const AckPacket* src);
        static void deserialize(AckPacket* dest, const uint8_t* src);
    } AckPacket;

    typedef struct LoginRequestPacket
    {
        uint16_t packetType = e_LoginRequest;
        uint16_t step;
        uint16_t keyId;
        uint8_t data[98];

        static const size_t SIZE = sizeof(packetType) + sizeof(step) + sizeof(keyId) + sizeof(data);
        static void serialize(uint8_t* dest, const LoginRequestPacket* src);
        static void deserialize(LoginRequestPacket* dest, const uint8_t* src);
    } LoginRequestPacket;

    //Status is 0 when login fails, 1 when login succeeds,
    //  2 if login succeeds but no port is available,
    //  and 3 if handshake failed;
    typedef struct LoginResponsePacket
    {
        uint16_t packetType = e_LoginResponse;
        uint16_t step;
        uint16_t keyId;
        uint16_t status;
        uint16_t port;
        uint8_t data[98];

        static const size_t SIZE = sizeof(packetType) + sizeof(step) + sizeof(keyId) + sizeof(status) + sizeof(port) + sizeof(data);
        static void serialize(uint8_t* dest, const LoginResponsePacket* src);
        static void deserialize(LoginResponsePacket* dest, const uint8_t* src);
    } LoginResponsePacket;

    typedef struct PingPacket {
        uint16_t packetType = e_Ping;
        uint16_t value;

        static const size_t SIZE = sizeof(packetType) + sizeof(value);
        static void serialize(uint8_t* dest, const PingPacket* src);
        static void deserialize(PingPacket* dest, const uint8_t* src);
    } PingPacket;

    typedef struct LogoutPacket {
        uint16_t packetType = e_Logout;

        static const size_t SIZE = sizeof(packetType);
        static void serialize(uint8_t* dest, const LogoutPacket* src);
        static void deserialize(LogoutPacket* dest, const uint8_t* src);
    } LogoutPacket;

    typedef struct KeyPacket {
        uint16_t packetType = e_Key;
        uint16_t step;
        uint32_t permutation;
        uint8_t data[512];

        static const size_t SIZE = sizeof(packetType) + sizeof(step) + sizeof(permutation) + sizeof(data);
        static void serialize(uint8_t* dest, const KeyPacket* src);
        static void deserialize(KeyPacket* dest, const uint8_t* src);
    } KeyPacket;

    typedef struct HandshakePacket {
        uint16_t packetType = e_Handshake;
        uint16_t step;
        uint8_t data[580];

        static const size_t SIZE = sizeof(packetType) + sizeof(step) + sizeof(data);
        static void serialize(uint8_t* dest, const HandshakePacket* src);
        static void deserialize(HandshakePacket* dest, const uint8_t* src);
    } HandshakePacket;

}
#endif