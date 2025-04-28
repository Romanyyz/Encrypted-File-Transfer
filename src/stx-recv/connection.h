#pragma once

#include <array>
#include <bitset>
#include <vector>
#include <atomic>
#include <cstdint>
#include <stddef.h>
#include <mutex>

#include <liburing.h>

#include "../common/file_transfer_packet.h"

constexpr uint8_t BUFFERS_NUM = 4;
class Connection;

struct UserData
{
    Connection* conn;
    size_t buf_idx;
};

class Connection
{
public:
    Connection() noexcept = default;
    Connection(int sock_fd, int epoll_fd);
    ~Connection() noexcept;

    Connection(const Connection&) = delete;
    Connection(Connection&&) noexcept;

    Connection& operator=(const Connection&) = delete;
    Connection& operator=(Connection&&) noexcept;

    void submitToUring(io_uring* ring);
    bool readyToWrite();
    void handleCompletion(size_t currBufferIdx, io_uring_cqe* cqe);
    bool isPaused() const;
    bool shouldResumeReading();
    void resumeReading();
    void pauseReading();
    size_t getFreeBuffers() const;
    void setEpollEvents(uint32_t epollEvents);
    void closeConnection() noexcept;
    int getSockFd();

    int appendToWriteBuffer(const FileTransferPacket& packet);
    void appendToSockBuffer(const std::vector<uint8_t>& incomingBuffer);
    bool hasEnough(size_t needed);
    void setAESKey(std::vector<uint8_t>& decryptedAESKey);
    int processSockBuffer();
    void processWriteBuffer();
    void setAllRead();
    bool isAllRead() const;
    void setFileName(const std::vector<uint8_t>& encryptedFileName);
    std::string getFileName() const;
    void openTargetFile();

    mutable std::mutex writeBuffersMutex_;

private:
    uint64_t connId_{0};
    int sockFd_{-1};
    int targetFileFd_{-1};
    int epollFd_{-1};
    size_t bytesReceived_{0};
    bool readyToWrite_{false};
    bool isPaused_{false};
    uint32_t currentEpollEvents_{0};
    bool allRead_{false};
    bool wholeFileReceived_{false};
    std::string targetFileName_;

    std::array<std::vector<uint8_t>, BUFFERS_NUM> writeBuffers_;
    std::bitset<BUFFERS_NUM> isBufferBusy_;
    size_t currentBufferIdx_{0};
    std::vector<uint8_t> sockBuffer_;
    std::vector<uint8_t> decryptedAESKey_;
};
