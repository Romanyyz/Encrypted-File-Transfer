#include "net_utils.h"

#include <unistd.h>
#include <arpa/inet.h>


bool writeAll(int fd, const void* buf, size_t count)
{
    const char* p = static_cast<const char*>(buf);
    while (count > 0)
    {
        ssize_t written = write(fd, p, count);
        if (written <= 0)
            return false;

        p += written;
        count -= written;
    }

    return true;
}


bool readAll(int fd, void* buf, size_t count)
{
    char* p = static_cast<char*>(buf);
    while (count > 0)
    {
        ssize_t read_bytes = read(fd, p, count);
        if (read_bytes <= 0)
            return false;

        p += read_bytes;
        count -= read_bytes;
    }

    return true;
}


FileTransferPacket receivePacket(int socket)
{
    FileTransferPacket packet{};
    readAll(socket, &packet, sizeof(packet));

    packet.magic_ = ntohl(packet.magic_);
    packet.version_ = ntohl(packet.version_);
    packet.session_id_ = ntohl(packet.session_id_);
    packet.packetType_ = ntohl(packet.packetType_);
    packet.fileSize_ = ntohl(packet.fileSize_);
    packet.payloadLen_ = ntohl(packet.payloadLen_);
    packet.currentBlock_ = ntohl(packet.currentBlock_);
    packet.flags_ = ntohs(packet.flags_);

    return packet;
}


void sendPacket(int socket, const FileTransferPacket& packetToSend)
{
    FileTransferPacket packet = packetToSend;

    packet.magic_ = htonl(packet.magic_);
    packet.version_ = htonl(packet.version_);
    packet.session_id_ = htonl(packet.session_id_);
    packet.packetType_ = htonl(packet.packetType_);
    packet.fileSize_ = htonl(packet.fileSize_);
    packet.payloadLen_ = htonl(packet.payloadLen_);
    packet.currentBlock_ = htonl(packet.currentBlock_);
    packet.flags_ = htons(packet.flags_);

    writeAll(socket, &packet, sizeof(packet));
}
