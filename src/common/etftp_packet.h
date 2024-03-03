#ifndef ETFTP_PACKET_H
#define ETFTP_PACKET_H

#include <stdint.h>

namespace ETFTP
{

    enum PacketTypes
    {
        e_None,
        e_Get,
        e_Post,
        e_Put,
        e_Delete,
        e_CD,
        e_Error,
        e_FileData,
        e_Ack,
        e_LoginRequest,
        e_LoginResponse,
        e_ListRequest,
        e_ListResponse,
        e_Ping
    };

    typedef struct PingPacket_t {
        uint16_t packetType;
        uint8_t value;
    } PingPacket_t;

    typedef struct GetRequestPacket_t
    {
        uint16_t packetType = e_Get;
    } GetRequestPacket_t;

    typedef struct PostRequestPacket_t
    {
        uint16_t packetType = e_Post;
    } PostRequestPacket_t;

    typedef struct PutRequestPacket_t
    {
        uint16_t packetType = e_Put;
    } PutRequestPacket_t;

    typedef struct DeleteRequestPacket_t
    {
        uint16_t packetType = e_Delete;
    } DeleteRequestPacket_t;

    typedef struct CDRequestPacket_t
    {
        uint16_t packetType = e_CD;

    } CDRequestPacket_t;

    typedef struct ErrorPacket_t
    {
        uint16_t packetType = e_Error;
        uint16_t errorCode;
        char message[514];
    } ErrorPacket_t;

    typedef struct FileDataPacket_t
    {
        uint16_t packetType = e_FileData;
        uint32_t blockNumber;
        uint8_t data[512];
    } FileDataPacket_t;

    typedef struct AckPacket_t
    {
        uint16_t packetType = e_Ack;
        uint32_t code;
    } AckPacket_t;

    typedef struct LoginRequestPacket_t
    {
        uint16_t packetType = e_LoginRequest;
        char username[33];
        char password[65];
    } LoginRequestPacket_t;

    //Status is 0 when login fails, 1 when login succeeds,
    //  and 2 if login succeeds but no port is available
    typedef struct LoginResponsePacket_t
    {
        uint16_t packetType = e_LoginResponse;
        uint16_t step;
        uint16_t status;
        uint16_t port;
    } LoginResponsePacket_t;

    typedef struct ListRequestPacket_t
    {
        uint16_t packetType = e_ListRequest;
        
    } ListRequestPacket_t;

    typedef struct ListResponsePacket_t
    {
        uint16_t packetType = e_ListResponse;
    } ListResponsePacket_t;

}
#endif