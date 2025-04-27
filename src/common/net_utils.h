#include "file_transfer_packet.h"

#include <stddef.h>

bool writeAll(int fd, const void* buf, size_t count);
bool readAll(int fd, void* buf, size_t count);
FileTransferPacket receivePacket(int socket);
void sendPacket(int socket, const FileTransferPacket& packetToSend);
