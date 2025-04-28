#pragma once

#include <unordered_map>
#include <thread>

#include <liburing.h>

#include "connection.h"

class ConnectionManager
{
public:
    ConnectionManager() noexcept;
    ~ConnectionManager() noexcept;

    ConnectionManager(const ConnectionManager&) = delete;
    ConnectionManager& operator=(const ConnectionManager&) = delete;

    ConnectionManager(ConnectionManager&&) = delete;
    ConnectionManager& operator=(ConnectionManager&&) = delete;

    bool startConnection(int sock_fd, int epoll_fd);
    void removeConnection(int sock_fd);
    bool processConnection(int sock_fd);
    bool doHandshake(int sock_fd);
    bool onSockRead(int fd);
    Connection& getConnection(int sock_fd);
    bool receiveFileName(int sock_fd);
    void closeAllConnections() noexcept;

private:
    void cqeHandlerThread(io_uring* ring);

    std::unordered_map<int, Connection> connections;
    io_uring ring{};
    io_uring_params params{};
    std::thread complitionThread_;
    std::atomic<bool> stopFlag_{false};
};
