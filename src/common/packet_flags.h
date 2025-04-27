#pragma once

#include <cstdint>

namespace PacketFlag
{
extern uint16_t NONE;
extern uint16_t HELLO;
extern uint16_t NONCE;
extern uint16_t HMAC;
extern uint16_t PUB_KEY;
extern uint16_t AES_KEY;
extern uint16_t DATA;
extern uint16_t E_O_F;
extern uint16_t RESUME;
extern uint16_t RESUME_OK;
extern uint16_t RESUME_DENIED;
extern uint16_t ACK;
extern uint16_t ERROR;
}

inline bool hasFlag(uint16_t value, uint16_t flag) {
    return (value & flag) != 0;
}
