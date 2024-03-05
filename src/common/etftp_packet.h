#ifndef ETFTP_PACKET_H
#define ETFTP_PACKET_H

#include <string.h>
#include <stdint.h>

namespace ETFTP
{

    enum PacketTypes
    {
        e_None,
        e_ReadRequest,
        e_WriteRequest,
        e_DeleteRequest,
        e_FileData,
        e_Ack,
        e_Error,
        e_LoginRequest,
        e_LoginResponse,
        e_ListRequest,
        e_ListResponse,
        e_Ping,
        e_Logout
    };

    typedef struct ReadRequestPacket
    {
        uint16_t packetType = e_ReadRequest;
        int8_t filePath[257];

        static const size_t SIZE = sizeof(packetType) + sizeof(filePath);
    } ReadRequestPacket;

    typedef struct WriteRequestPacket
    {
        uint16_t packetType = e_WriteRequest;
        int8_t filePath[257];
        
        static const size_t SIZE = sizeof(packetType) + sizeof(filePath);
    } WriteRequestPacket;

    typedef struct DeleteRequestPacket
    {
        uint16_t packetType = e_DeleteRequest;
        int8_t filePath[257];

        static const size_t SIZE = sizeof(packetType) + sizeof(filePath);
    } DeleteRequestPacket;

    typedef struct ErrorPacket
    {
        uint16_t packetType = e_Error;
        uint16_t errorCode;
        int8_t message[257];

        static const size_t SIZE = sizeof(packetType) + sizeof(errorCode) + sizeof(message);
    } ErrorPacket;

    typedef struct FileDataPacket
    {
        uint16_t packetType = e_FileData;
        uint32_t blockNumber;
        uint8_t data[512];

        static const size_t SIZE = sizeof(packetType) + sizeof(blockNumber) + sizeof(data);
    } FileDataPacket;

    typedef struct AckPacket
    {
        uint16_t packetType = e_Ack;
        uint32_t code;

        static const size_t SIZE = sizeof(packetType) + sizeof(code);
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

}
#endif