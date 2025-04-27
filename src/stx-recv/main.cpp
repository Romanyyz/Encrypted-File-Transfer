#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <liburing.h>
#include <sys/epoll.h>

#include <iostream>
#include <cstring>
#include <fstream>
#include <string>

#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#include "connection_manager.h"
#include "../common/crypto_utils.h"
#include "../common/file_transfer_packet.h"

constexpr int MAX_EVENTS = 1024;

int main(int argc, char* argv[])
{
    if (argc != 5)
    {
        std::cerr << "Usage: stx-recv --listen <port> --out <directory>" << '\n';
        return 1;
    }

    std::string listenPort;
    std::string outDir;
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--listen" && i + 1 < argc)
        {
            listenPort = argv[++i];
        } else if (arg == "--out" && i + 1 < argc)
        {
            outDir = argv[++i];
        } else
        {
            std::cerr << "Unknown argument " << arg << '\n';
            return 1;
        }
    }
    if (listenPort.empty() || outDir.empty())
    {
        std::cerr << "Usage: stx-recv --listen <port> --out <directory>" << '\n';
        return 1;
    }

    int port;
    try
    {
        port = std::stoi(listenPort);
    }
    catch(...)
    {
        std::cerr << "Failed to convert port\n";
        return 3;
    }

    if (chdir(outDir.c_str()) != 0)
    {
        std::cerr << "Failed to change directory: " << '\n';
        return 4;
    }

    std::cout << "Started, listeninig on port: " << port << '\n';

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1)
    {
        std::cerr << "Failed to create epoll\n";
        return 1;
    }

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1)
    {
        std::cerr << "Failed to create socket\n";
        return 1;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    fcntl(server_sock, F_SETFL, O_NONBLOCK);

    if (bind(server_sock, (struct sockaddr*)&address, sizeof(address)) < 0)
    {
        std::cerr<<"Failed to bind\n";
        close(server_sock);
        return 1;
    }

    if (listen(server_sock, SOMAXCONN) == -1)
    {
        std::cerr<<"Failed to listen\n";
        close(server_sock);
        return 1;
    }

    ConnectionManager connManager;
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = server_sock;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_sock, &ev);
    while (true)
    {
        struct epoll_event events[MAX_EVENTS];
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; ++i)
        {
            if (events[i].data.fd == server_sock)
            {
                while (true)
                {
                    int client_sock = accept(server_sock, NULL, NULL);
                    if (client_sock == -1)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        else
                            std::cerr<<"Failed to accept\n";
                    }
                    if (connManager.startConnection(client_sock, epoll_fd))
                    {
                        fcntl(client_sock, F_SETFL, O_NONBLOCK);

                        struct epoll_event cev;
                        cev.events = EPOLLIN | EPOLLET;

                        uint32_t initialEvents = cev.events;
                        connManager.getConnection(client_sock).setEpollEvents(initialEvents);

                        cev.data.fd = client_sock;
                        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_sock, &cev);
                    }
                    else
                    {
                        std::cerr<<"Failed to establish connection\n";
                        connManager.removeConnection(client_sock);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_sock, NULL);
                        close(client_sock);
                    }
                }
            }
            else
            {
                int client_sock = events[i].data.fd;
                // check for errors
                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))
                {
                    connManager.getConnection(client_sock).closeConnection();
                    connManager.removeConnection(client_sock);
                    continue;
                }
                if (events[i].events & EPOLLIN)
                {
                    connManager.processConnection(client_sock);
                }
            }
        }
        //connManager.handleSQOverload(epoll_fd);
    }

    close(server_sock);
    return 0;
}
