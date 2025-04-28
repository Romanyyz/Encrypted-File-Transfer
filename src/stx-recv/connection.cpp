#include "connection.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include <string>
#include <fstream>
#include <iostream>

#include "../common/crypto_utils.h"
#include "../common/file_transfer_packet.h"


Connection::Connection(int sock_fd, int epoll_fd) : sockFd_{sock_fd}, epollFd_{epoll_fd}
{
}

Connection::Connection(Connection&& other) noexcept :
    connId_{other.connId_},
    sockFd_{other.sockFd_},
    targetFileFd_{other.targetFileFd_},
    epollFd_{other.epollFd_},
    bytesReceived_{other.bytesReceived_},
    readyToWrite_{other.readyToWrite_},
    isPaused_{other.isPaused_},
    currentEpollEvents_{other.currentEpollEvents_},
    allRead_{other.allRead_},
    wholeFileReceived_{other.wholeFileReceived_},
    writeBuffers_{std::move(other.writeBuffers_)},
    isBufferBusy_{std::move(other.isBufferBusy_)},
    currentBufferIdx_{other.currentBufferIdx_},
    sockBuffer_{std::move(other.sockBuffer_)},
    decryptedAESKey_{std::move(other.decryptedAESKey_)}
{
    other.connId_ = 0;
    other.sockFd_ = -1;
    other.targetFileFd_ = -1;
    other.epollFd_ = -1;
    other.bytesReceived_ = 0;
    other.readyToWrite_ = 0;
    other.isPaused_ = false;
    other.currentEpollEvents_ = 0;
    other.allRead_ = false;
    other.wholeFileReceived_ = false;
    other.currentBufferIdx_ = 0;
}


Connection& Connection::operator=(Connection&& rhs) noexcept
{
    connId_ = rhs.connId_;
    rhs.connId_ = 0;

    sockFd_ = rhs.sockFd_;
    rhs.sockFd_ = -1;

    targetFileFd_ = rhs.targetFileFd_;
    rhs.targetFileFd_ = -1;

    epollFd_ = rhs.epollFd_;
    rhs.epollFd_ = -1;

    bytesReceived_ = rhs.bytesReceived_;
    rhs.bytesReceived_ = 0;

    readyToWrite_ = rhs.readyToWrite_;
    rhs.readyToWrite_ = 0;

    isPaused_ = rhs.isPaused_;
    rhs.isPaused_ = false;

    currentEpollEvents_ = rhs.currentEpollEvents_;
    rhs.currentEpollEvents_ = 0;

    allRead_ = rhs.allRead_;
    rhs.allRead_ = false;

    wholeFileReceived_ = rhs.wholeFileReceived_;
    rhs.wholeFileReceived_ = false;

    writeBuffers_ = std::move(rhs.writeBuffers_);
    isBufferBusy_ = std::move(rhs.isBufferBusy_);

    currentBufferIdx_ = rhs.currentBufferIdx_;
    rhs.currentBufferIdx_ = 0;

    sockBuffer_ = std::move(rhs.sockBuffer_);
    decryptedAESKey_ = std::move(rhs.decryptedAESKey_);

    return *this;
}


Connection::~Connection() noexcept
{
    closeConnection();
}


void Connection::appendToSockBuffer(const std::vector<uint8_t>& incomingBuffer)
{
    sockBuffer_.insert(sockBuffer_.end(), incomingBuffer.begin(), incomingBuffer.end());
}


int Connection::processSockBuffer()
{
    while (sockBuffer_.size() >= sizeof(FileTransferPacket))
    {
        FileTransferPacket packet;
        std::memcpy(&packet, sockBuffer_.data(), sizeof(packet));

        // check hash
        uint32_t payloadLen = ntohl(packet.payloadLen_);
        auto calcHash = calcSHA256(std::vector<uint8_t>{packet.payload, packet.payload + payloadLen});
        if (CRYPTO_memcmp(packet.sha256, calcHash.data(), calcHash.size()) != 0)
        {
            sockBuffer_.erase(sockBuffer_.begin(), sockBuffer_.begin() + sizeof(packet));
            continue;
        }

        const auto processResult = appendToWriteBuffer(packet);
        if (processResult < 0)
        {
            if (processResult == -1)
            {
                // buffers are full, need to slow down
                return -1;
            }
            return processResult;
        }
        sockBuffer_.erase(sockBuffer_.begin(), sockBuffer_.begin() + sizeof(packet));
    }
    return 0;
}


int Connection::appendToWriteBuffer(const FileTransferPacket& packet)
{
    const std::lock_guard<std::mutex> lock(writeBuffersMutex_);
    int targetBuf = -1;
    if (isBufferBusy_.test(currentBufferIdx_))
    {
        return -2;
    }
    else
    {
        targetBuf = currentBufferIdx_;
    }

    if (targetBuf == -1)
    {
        // need to stop receiving events for a while...
        return -1;
    }

    uint32_t payloadLen = ntohl(packet.payloadLen_);
    std::vector<unsigned char> encryptedBuffer(packet.payload, packet.payload + payloadLen);
    auto decryptedData = aesDecrypt(encryptedBuffer, reinterpret_cast<const unsigned char*>(decryptedAESKey_.data()));
    if (decryptedData.empty())
        return -2;

    uint16_t flags = ntohs(packet.flags_);
    if (hasFlag(flags, PacketFlag::E_O_F))
    {

    }

    auto& buf = writeBuffers_[targetBuf];
    buf.insert(buf.end(), decryptedData.begin(), decryptedData.begin() + decryptedData.size());

    return 0;
}


void Connection::processWriteBuffer()
{
    const std::lock_guard<std::mutex> lock(writeBuffersMutex_);
    constexpr size_t writeSize = 4096 * 5;
    auto& buf = writeBuffers_[currentBufferIdx_];
    if (buf.size() >= writeSize || allRead_)
    {
        // will write later via io uring
        readyToWrite_ = true;
    }
    else
    {
        readyToWrite_ = false;
    }
}


void Connection::setAESKey(std::vector<uint8_t>& decryptedAESKey)
{
    decryptedAESKey_ = std::move(decryptedAESKey);
}

bool Connection::readyToWrite()
{
    return readyToWrite_;
}


void Connection::submitToUring(io_uring* ring)
{
    const std::lock_guard<std::mutex> lock(writeBuffersMutex_);
    if (writeBuffers_[currentBufferIdx_].empty()
        || isBufferBusy_.test(currentBufferIdx_))
    {
        return;
    }

    auto& buf = writeBuffers_[currentBufferIdx_];

    if (targetFileFd_ == -1)
    {
        targetFileFd_ = open(targetFileName_.c_str(), O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (targetFileFd_ == -1)
            return;
    }

    bytesReceived_ += buf.size();

    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe)
    {
        std::cerr << "Failed to get SQE\n";
        return;
    }

    UserData* ud = new UserData{this, currentBufferIdx_};
    io_uring_sqe_set_data64(sqe, reinterpret_cast<uint64_t>(ud));
    io_uring_sqe_set_flags(sqe, IOSQE_IO_DRAIN);
    io_uring_prep_write(sqe, targetFileFd_, buf.data(), buf.size(), 0);

    isBufferBusy_.set(currentBufferIdx_);
    currentBufferIdx_ = (currentBufferIdx_ + 1) % writeBuffers_.size();

    if (io_uring_submit(ring) < 0)
    {
        isBufferBusy_.reset(currentBufferIdx_);
        delete ud;
        std::cerr << "Submission to io_uring failed\n";
    }
}


void Connection::handleCompletion(size_t currBufferIdx, io_uring_cqe* cqe)
{
    auto& buf = writeBuffers_[currBufferIdx];

    if (static_cast<size_t>(cqe->res) < buf.size())
    {
        ssize_t bytes_written = write(targetFileFd_, buf.data() + cqe->res, buf.size() - cqe->res);
        if (bytes_written < 0)
        {
            std::cerr << "write() failed: " << bytes_written << "\n";
            return;
        }

        if (static_cast<size_t>(bytes_written) < (buf.size() - cqe->res))
        {
            std::cerr << "Partial manual write\n";
            buf.erase(buf.begin(), buf.begin() + cqe->res + bytes_written);
            return;
        }
    }

    buf.clear();
    isBufferBusy_.reset(currBufferIdx);
}


bool Connection::isPaused() const
{
    return isPaused_;
}


bool Connection::shouldResumeReading()
{
    return getFreeBuffers() >= 2;
}


void Connection::resumeReading()
{
    struct epoll_event event;
    event.events = currentEpollEvents_ | EPOLLIN;
    event.data.fd = sockFd_;
    epoll_ctl(epollFd_, EPOLL_CTL_MOD, sockFd_, &event);
    currentEpollEvents_ = event.events;
    isPaused_ = false;
}

void Connection::pauseReading()
{
    struct epoll_event event;
    event.events = currentEpollEvents_ & ~EPOLLIN;
    event.data.fd = sockFd_;
    epoll_ctl(epollFd_, EPOLL_CTL_MOD, sockFd_, &event);
    currentEpollEvents_ = event.events;
    isPaused_ = true;
}


size_t Connection::getFreeBuffers() const
{
    size_t freeBuffs{0};
    for (size_t i = 0; i < writeBuffers_.size(); ++i)
    {
        if (!isBufferBusy_.test(i))
            ++freeBuffs;
    }
    return freeBuffs;
}


void Connection::setEpollEvents(uint32_t epollEvents)
{
    currentEpollEvents_ = epollEvents;
}


void Connection::setAllRead()
{
    allRead_ = true;
}


bool Connection::isAllRead() const
{
    return allRead_;
}


void Connection::setFileName(const std::vector<uint8_t>& encryptedFileName)
{
    auto decryptedFileName = aesDecrypt(encryptedFileName, reinterpret_cast<const unsigned char*>(decryptedAESKey_.data()));
    if (decryptedFileName.empty())
        return;

    std::string fileName{decryptedFileName.begin(), decryptedFileName.end()};

    targetFileName_ = std::move(fileName);
}


std::string Connection::getFileName() const
{
    return targetFileName_;
}


void Connection::openTargetFile()
{
    targetFileFd_ = open(targetFileName_.c_str(), O_WRONLY | O_APPEND | O_CREAT, 0644);
}


void Connection::closeConnection() noexcept
{
    epoll_ctl(epollFd_, EPOLL_CTL_DEL, sockFd_, nullptr);
    if (sockFd_ != -1)
    {
        close(sockFd_);
    }
    if (targetFileFd_ != -1)
    {
        close(targetFileFd_);
    }
    sockFd_ = -1;
    targetFileFd_ = -1;
}


int Connection::getSockFd()
{
    return sockFd_;
}
