#include "connection_manager.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <endian.h>
#include <sys/stat.h>

#include <iostream>
#include <string>
#include <mutex>

#include <openssl/hmac.h>

#include "../common/crypto_utils.h"
#include "../common/file_transfer_packet.h"
#include "../common/net_utils.h"


constexpr int MAX_CONN_BUFFER_SIZE = 4 * 1024 * 1024;
constexpr int QUEUE_SIZE = 4096;


static bool fileExistsAndSize(const std::string& fileName, off_t& outSize)
{
    struct stat buffer;
    if (stat(fileName.c_str(), &buffer) != 0)
    {
        return false;
    }
    if (!S_ISREG(buffer.st_mode))
    {
        return false;
    }

    outSize = buffer.st_size;
    return true;
}


void ConnectionManager::cqeHandlerThread(io_uring* ring)
{
    while (!stopFlag_)
    {
        io_uring_cqe* cqe;
        int ret = io_uring_wait_cqe(ring, &cqe);
        if (ret < 0)
        {
            std::cerr << "wait_cqe failed\n";
            continue;
        }

        if (cqe->res < 0)
        {
            std::cerr << "SQE failed code = " << cqe->res << '\n';
            io_uring_cqe_seen(ring, cqe);
            continue;
        }

        UserData* ud = reinterpret_cast<UserData*>(cqe->user_data);

        {
            const std::lock_guard<std::mutex> lock(ud->conn->writeBuffersMutex_);
            ud->conn->handleCompletion(ud->buf_idx, cqe);
            // also need to know if all io uring ops was finished
            /*if (ud->conn->isAllRead())
            {
                //ud->conn->closeConnection();
                //removeConnection(ud->conn->getSockFd());
            }*/
            if (ud->conn->isPaused() && ud->conn->shouldResumeReading())
            {
                ud->conn->resumeReading();
            }
        }

        delete ud;
        io_uring_cqe_seen(ring, cqe);
    }
}


ConnectionManager::ConnectionManager() noexcept
{
    std::memset(&params, 0, sizeof(params));
    io_uring_queue_init_params(QUEUE_SIZE, &ring, &params);
    complitionThread_= std::thread(&ConnectionManager::cqeHandlerThread, this, &ring);
}


ConnectionManager::~ConnectionManager() noexcept
{
    stopFlag_ = true;
    if (complitionThread_.joinable())
    {
        complitionThread_.join();
    }
    io_uring_queue_exit(&ring);
    closeAllConnections();
}


void ConnectionManager::closeAllConnections() noexcept
{
    for (auto& pair : connections)
    {
        pair.second.closeConnection();
    }
}


bool ConnectionManager::onSockRead(int fd)
{
    Connection& conn = connections[fd];
    std::vector<uint8_t> incomingBuffer;

    uint8_t tmp[2048];
    while (true)
    {
        ssize_t read_bytes = read(fd, tmp, sizeof(tmp));
        if (read_bytes > 0)
        {
            incomingBuffer.insert(incomingBuffer.end(), tmp, tmp + read_bytes);
            continue;
        }
        if (read_bytes == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                break; // ok, try later
            }
            std::cerr<<"Unexpected error when reading from socket\n";
            conn.closeConnection();
            removeConnection(fd);
            return false; // bad
        }
        if (read_bytes == 0)
        {
            conn.appendToSockBuffer(incomingBuffer);
            conn.setAllRead();
            return true; // closed on other side
        }
    }

    conn.appendToSockBuffer(incomingBuffer);
    return true;
}


Connection& ConnectionManager::getConnection(int sock_fd)
{
    return connections[sock_fd];
}


bool ConnectionManager::processConnection(int sock_fd)
{
    if (!onSockRead(sock_fd))
    {
        return false;
    }

    auto& conn = connections[sock_fd];
    if (conn.processSockBuffer() == -1)
    {
        conn.pauseReading();
    }
    conn.processWriteBuffer();
    if (conn.readyToWrite())
    {
        conn.submitToUring(&ring);
    }
    return true;
}


void ConnectionManager::removeConnection(int sock_fd)
{
    connections.erase(sock_fd);
}


bool ConnectionManager::startConnection(int sock_fd, int epoll_fd)
{
    connections.emplace(sock_fd, Connection{sock_fd, epoll_fd});
    if (!doHandshake(sock_fd))
    {
        std::cerr<<"Handshake failed\n";
        return false;
    }
    if (!receiveFileName(sock_fd))
    {
        std::cerr<<"Failed to receive file name\n";
        return false;
    }

    return true;
}


bool ConnectionManager::receiveFileName(int sock_fd)
{
    Connection& conn = connections[sock_fd];
    FileTransferPacket recievedPacket = receivePacket(sock_fd);

    uint32_t netFileNameLen;
    std::memcpy(&netFileNameLen, recievedPacket.payload, sizeof(netFileNameLen));

    uint32_t fileNameLen = ntohl(netFileNameLen);
    auto begin = reinterpret_cast<char*>(recievedPacket.payload + sizeof(netFileNameLen));
    std::vector<uint8_t> encryptedFileName(begin, begin + fileNameLen);
    if (encryptedFileName.empty())
    {
        std::cerr << "Received empty file name\n";
        return false;
    }
    conn.setFileName(encryptedFileName);
    conn.openTargetFile();

    uint64_t sizeToSend;
    off_t size;
    if (fileExistsAndSize(conn.getFileName(), size))
    {
        if (size < 0)
        {
            std::cerr << "Failed to get file size\n";
            return 3;
        }
        sizeToSend = static_cast<uint64_t>(size);
    }
    else
    {
        sizeToSend = 0;
    }

    uint64_t netSizeToSend = htobe64(sizeToSend);
    FileTransferPacket packetToSend{};
    std::memcpy(packetToSend.payload, &netSizeToSend, sizeof(netSizeToSend));

    packetToSend.flags_ = PacketFlag::ACK;
    sendPacket(sock_fd, packetToSend);

    return true;
}


bool ConnectionManager::doHandshake(int sock_fd)
{
    Connection& conn = connections[sock_fd];
    while (true)
    {
        FileTransferPacket recievedPacket = receivePacket(sock_fd);
        if (hasFlag(recievedPacket.flags_, PacketFlag::HELLO)
            && hasFlag(recievedPacket.flags_, PacketFlag::NONCE))
        {
            std::array<uint8_t, 16> clientNonce;
            std::memcpy(clientNonce.data(), recievedPacket.payload, clientNonce.size());

            auto serverNonce = generateNonce();
            if (serverNonce.empty())
                return false;

            std::array<uint8_t, 32> combinedNonce;
            std::memcpy(combinedNonce.data(), clientNonce.data(), clientNonce.size());
            std::memcpy(combinedNonce.data() + clientNonce.size(), serverNonce.data(), serverNonce.size());

            std::array<unsigned char, EVP_MAX_MD_SIZE> hmac;
            uint32_t hmacLen = 0;
            HMAC(EVP_sha256(),
                 secret, std::strlen(secret),
                 combinedNonce.data(), combinedNonce.size(),
                 hmac.data(), &hmacLen);

            FileTransferPacket packetToSend{};

            uint32_t netHmacLen = htonl(hmacLen);
            std::memcpy(packetToSend.payload, serverNonce.data(), serverNonce.size());
            std::memcpy(packetToSend.payload + serverNonce.size(), &netHmacLen, sizeof(netHmacLen));
            std::memcpy(packetToSend.payload + serverNonce.size() + sizeof(netHmacLen), hmac.data(), hmacLen);

            packetToSend.flags_ = PacketFlag::NONCE | PacketFlag::HMAC;
            sendPacket(sock_fd, packetToSend);

            continue;
        }
        if (hasFlag(recievedPacket.flags_, PacketFlag::PUB_KEY))
        {
            unsigned char key[32];
            if (!generateAESKey(key, sizeof(key)))
            {
                return false;
            }

            std::vector<uint8_t> decryptedAESKey(32);
            std::copy(key, key + 32, decryptedAESKey.begin());
            conn.setAESKey(decryptedAESKey);

            // read key size
            uint32_t netKeySize;
            std::memcpy(&netKeySize, recievedPacket.payload, sizeof(netKeySize));

            // read key itself
            uint32_t keySize = ntohl(netKeySize);
            std::string pubKey(reinterpret_cast<char*>(recievedPacket.payload + sizeof(netKeySize)), keySize);

            auto encryptedAesKey = enctyptAESKey(key, sizeof(key), pubKey);
            if (encryptedAesKey.empty())
            {
                return false;
            }

            FileTransferPacket packetToSend{};

            uint32_t encryptedAesKeySize = encryptedAesKey.size();
            uint32_t netEncryptedAesKeySize = htonl(encryptedAesKeySize);
            std::memcpy(packetToSend.payload, &netEncryptedAesKeySize, sizeof(netEncryptedAesKeySize));
            std::memcpy(packetToSend.payload + sizeof(netEncryptedAesKeySize), encryptedAesKey.data(), encryptedAesKey.size());
            packetToSend.flags_ = PacketFlag::AES_KEY;

            sendPacket(sock_fd, packetToSend);

            break;
        }
    }

    return true;
}
