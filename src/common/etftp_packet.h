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
        e_Ping
    };

    typedef struct ReadRequestPacket
    {
        static const size_t SIZE = 259;
        uint16_t packetType = e_ReadRequest;
        char filePath[257];
    } ReadRequestPacket;

    typedef struct WriteRequestPacket
    {
        static const size_t SIZE = 259;
        uint16_t packetType = e_WriteRequest;
        char filePath[257];
    } WriteRequestPacket;

    typedef struct DeleteRequestPacket
    {
        static const size_t SIZE = 259;
        uint16_t packetType = e_DeleteRequest;
        char filePath[257];
    } DeleteRequestPacket;

    typedef struct ErrorPacket
    {
        static const size_t SIZE = 259;
        uint16_t packetType = e_Error;
        uint16_t errorCode;
        char message[257];
    } ErrorPacket;

    typedef struct FileDataPacket
    {
        static const size_t SIZE = 518;
        uint16_t packetType = e_FileData;
        uint32_t blockNumber;
        uint8_t data[512];
    } FileDataPacket;

    typedef struct AckPacket
    {
        static const size_t SIZE = 6;
        uint16_t packetType = e_Ack;
        uint32_t code;
    } AckPacket;

    typedef struct LoginRequestPacket
    {
        static const size_t SIZE = 104;
        static void serialize(uint8_t* dest, const LoginRequestPacket* src);
        static void deserialize(LoginRequestPacket* dest, const uint8_t* src);
        uint16_t packetType = e_LoginRequest;
        uint16_t step;
        uint16_t keyId;
        unsigned char data[98];
    } LoginRequestPacket;

    //Status is 0 when login fails, 1 when login succeeds,
    //  2 if login succeeds but no port is available,
    //  and 3 if handshake failed;
    typedef struct LoginResponsePacket
    {
        static const size_t SIZE = 118;
        static void serialize(uint8_t* dest, const LoginResponsePacket* src);
        static void deserialize(LoginResponsePacket* dest, const uint8_t* src);
        uint16_t packetType = e_LoginResponse;
        uint16_t step;
        uint16_t keyId;
        uint16_t status;
        uint16_t port;
        unsigned char data[98];
    } LoginResponsePacket;

    typedef struct ListRequestPacket
    {
        static const size_t SIZE = 24;
        uint16_t packetType = e_ListRequest;
        
    } ListRequestPacket;

    typedef struct ListResponsePacket
    {
        static const size_t SIZE = 24;
        uint16_t packetType = e_ListResponse;
    } ListResponsePacket;

    typedef struct PingPacket {
        static void serialize(uint8_t* dest, const PingPacket* src);
        static void deserialize(PingPacket* dest, const uint8_t* src);
        static const size_t SIZE = 6;
        uint16_t packetType = e_Ping;
        uint16_t value;
    } PingPacket;

}
#endif