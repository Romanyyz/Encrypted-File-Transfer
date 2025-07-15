# Encrypted File Transfer: Custom Secure File Transfer Protocol

## Overview

Encrypted File Transfer is a project consisting of a custom Layer 7 protocol along with a server and client implementation.
Its core function is to enable clients to securely upload files to the server using end-to-end encryption.

This project began as a coding challenge and is planned to be further developed into a full-fledged, robust solution in the future.

Current Status: All core functionality is currently working. You can launch the server,
connect multiple clients, and they will successfully transfer files to the server in an encrypted format.

**Important Note: Work on this project is currently paused but will resume in the future.**

## Implemented Features

This project features an implementation of a custom Layer 7 protocol for file transfer, showcasing networking and security concepts:
- Custom Layer 7 Protocol: A proprietary file transfer protocol designed from the ground up.
- Secure Handshake Mechanism: The protocol includes a custom handshake process for server authentication and secure key exchange, establishing a trusted communication channel.
- Functional Client-Server Architecture: Both the client and server are fully implemented and operate according to the defined custom protocol.
- Concurrent Connections: The server is capable of listening for and handling multiple simultaneous client connections, allowing several clients to upload files concurrently.
- Efficient Asynchronous I/O:
  - The server utilizes an `epoll` event loop for high-performance handling of incoming network connections, enabling it to manage thousands of concurrent connections.
  - `io_uring` is used for asynchronous disk I/O, allowing the server to write incoming client data to disk in the background without blocking network operations.
- Backpressure Mechanism: An intelligent flow control mechanism is implemented to pause network data reception temporarily if the disk I/O subsystem falls behind. This prevents buffer overflow and resumes data reception once pending disk writes are completed.
- Cryptography Integration:
  - RSA is used for the secure exchange of symmetric keys during the handshake.
  - AES (Advanced Encryption Standard) is utilized as the symmetric encryption algorithm for file data.
  - Encryption functionalities are provided by the OpenSSL library.

## Planned Improvements

Work on this project will resume in the future with a focus on enhancing security, robustness, and efficiency:
- Protocol Refinement: Further development and hardening of the custom protocol.
- Security Enhancements:
  - Replace the current AES-ECB mode with a more secure and robust mode (e.g., AES-GCM or AES-CTR with HMAC) to address known vulnerabilities.
- Server Robustness:
  - Implement graceful shutdown for the server, ensuring all active transfers are completed or properly terminated before shutting down.
  - Enable parallel disk writes for different chunks of the same file. Currently, io_uring is used with a sequential flag. Future work will involve manual offset tracking to allow concurrent writes of file segments, significantly improving write performance.
  - Server to correctly close completed connections.
- Client Resilience:
  - Implement client-side reconnection logic for resumable transfers. The protocol already supports sending remaining data after a connection break, but the client currently lacks the logic to automatically reconnect and resume.

## Current Compromises

- Weak AES Mode: The current use of AES-ECB is a known security compromise and will be replaced with a more secure mode in future iterations.
- Sequential File Writes: Files are currently written to disk sequentially (chunk by chunk), even with io_uring. Future improvements will enable parallel writes for parts of the same file to enhance throughput.

## Building and Running

### Requirements

1. Linux Kernel 5.15+
2. `gcc`
3. `cmake`
4. `make`
5. `pkgconf`

### Dependencies

1. OpenSSL
2. liburing
   
### Building the Project

1. Clone the repository
```bash
git clone git@github.com:Romanyyz/Encrypted-File-Transfer.git
cd Encrypted-File-Transfer
```
2. Create and enter build directory:
```bash
mkdir build
cd build
```
3. Configure with CMake and build:
```bash
cmake ..
make
```

## Running the Application

1. Run the Server:
```bash
./stx-recv --listen <port> --out <out directory>
```
Example: `./stx-recv --listen 5656 --out /tmp/received_files`

2. Run the Client:
```bash
./stx-send <host> <port> path/to/file.bin
```
Example: `./stx-send localhost 5656 /home/user/document.pdf`

For a more detailed description of the design, please check out the [DESIGN.md](DESIGN.md)

## Contact

If you have any questions or suggestions, feel free to reach out:

Email: roman.khokhlachov@tuta.io
