#pragma once

#include "packet_flags.h"

#include <cstdint>

#pragma pack(push, 1)
struct FileTransferPacket
{
    uint32_t magic_;
    uint16_t version_;
    uint64_t session_id_;
    uint32_t packetType_;
    uint64_t fileSize_;
    uint32_t payloadLen_;
    uint32_t currentBlock_;
    uint16_t flags_;
    uint8_t payload[4096 + 32]; // allocate a little more for AES padding
    uint8_t sha256[32];
};
#pragma pack(pop)
