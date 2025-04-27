#include "packet_flags.h"

namespace PacketFlag
{
uint16_t NONE          = 0x0000;
uint16_t HELLO         = 0x0001;
uint16_t NONCE         = 0x0002;
uint16_t HMAC          = 0x0004;
uint16_t PUB_KEY       = 0x0008;
uint16_t AES_KEY       = 0x0010;
uint16_t DATA          = 0x0020;
uint16_t E_O_F         = 0x0040;
uint16_t RESUME        = 0x0080;
uint16_t RESUME_OK     = 0x0100;
uint16_t RESUME_DENIED = 0x0200;
uint16_t ACK           = 0x0400;
uint16_t ERROR         = 0x0800;
}
