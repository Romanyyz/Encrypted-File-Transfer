#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

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

#include "../common/crypto_utils.h"
#include "../common/file_transfer_packet.h"
#include "../common/net_utils.h"

static EVP_PKEY* g_pkey = nullptr;
static std::vector<uint8_t> decryptedAESKey;

static void sendFileEncrypted(int fd, const std::string& filePath, uint64_t offset, const unsigned char* key);
static EVP_PKEY* generatePkey();
static std::string getPubKeyStr(EVP_PKEY* pkey);
static bool processHandshake(int socket);
static int sendFileName(int sock_fd, const std::string& fileName);
static std::string getFileNameFromPath(const std::string& srt);


int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: stx-send <host> <port> <path/to/file>" << '\n';
        return 1;
    }

    std::string host{argv[1]};
    int port = 0;

    try
    {
        port = std::stoi(argv[2]);
    }
    catch (...)
    {
        std::cerr << "Failed to convert port\n";
        return 1;
    }

    std::string filePath{argv[3]};

    std::cout << "Connecting to " << host << ':' << port <<'\n';

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        std::cerr << "Failed to create socket\n";
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0)
    {
        std::cerr << "Invalid address\n";
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Failed to connect\n";
        close(sock);
        return 1;
    }

    if (!processHandshake(sock))
    {
        std::cerr << "Handshake failed on client\n";
        close(sock);
        return 2;
    }

    int offset = sendFileName(sock, getFileNameFromPath(filePath));
    if (offset == -1)
    {
        std::cerr << "Failed to send file name\n";
        return 1;
    }

    sendFileEncrypted(sock, filePath, offset, reinterpret_cast<const unsigned char*>(decryptedAESKey.data()));

    std::cout<<"Done.\n";

    EVP_PKEY_free(g_pkey);
    close(sock);
    return 0;
}


static void sendFileEncrypted(int fd, const std::string& filePath, uint64_t pos, const unsigned char* key)
{
    constexpr size_t BLOCK_SIZE = 4096;

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open())
    {
        return;
    }

    file.seekg(pos);
    std::vector<unsigned char> buffer(BLOCK_SIZE);
    while (true)
    {
        FileTransferPacket packet{};
        file.read(reinterpret_cast<char*>(buffer.data()), BLOCK_SIZE);
        size_t bytesRead = file.gcount();
        if (bytesRead == 0)
            break;

        auto encryptedBuffer = aesEncrypt(std::vector<unsigned char>(buffer.begin(), buffer.begin() + bytesRead), key);
        if (encryptedBuffer.empty())
        {
            return;
        }

        uint32_t netDataSize = htonl(encryptedBuffer.size());
        packet.payloadLen_ = netDataSize;
        std::memcpy(packet.payload, encryptedBuffer.data(), encryptedBuffer.size());

        auto hash = calcSHA256(encryptedBuffer);
        std::memcpy(packet.sha256, hash.data(), hash.size());

        if (!writeAll(fd, &packet, sizeof(packet)))
        {
            return;
        }
    }

    FileTransferPacket packet{};
    uint16_t flags = PacketFlag::E_O_F;
    packet.flags_ = htons(flags);
    writeAll(fd, &packet, sizeof(packet));

    file.close();
}


static EVP_PKEY* generatePkey()
{
    if (g_pkey)
        return g_pkey;

    constexpr int bits = 2048;
    g_pkey = EVP_RSA_gen(bits);
    if (!g_pkey)
    {
        return nullptr;
    }

    return g_pkey;
}


static std::string getPubKeyStr(EVP_PKEY* pkey)
{
    if (!pkey)
        return {};

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio)
        return "";

    if (!PEM_write_bio_PUBKEY(bio, pkey))
    {
        BIO_free(bio);
        return "";
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pubKeyStr(data, len);
    BIO_free(bio);
    return pubKeyStr;
}


static bool processHandshake(int socket)
{
    FileTransferPacket packetToSend{};

    auto clientNonce = generateNonce();
    if (clientNonce.empty())
        return false;


    std::memcpy(packetToSend.payload, clientNonce.data(), clientNonce.size());
    packetToSend.flags_ = PacketFlag::NONCE | PacketFlag::HELLO;

    sendPacket(socket, packetToSend);

    while (true)
    {
        FileTransferPacket recievedPacket = receivePacket(socket);
        if (hasFlag(recievedPacket.flags_, PacketFlag::NONCE)
            && hasFlag(recievedPacket.flags_, PacketFlag::HMAC))
        {
            // read server nonce
            std::array<uint8_t, 16> serverNonce;
            std::memcpy(serverNonce.data(), recievedPacket.payload, serverNonce.size());

            // create a combined nonce
            std::array<uint8_t, 32> combinedNonce;
            std::memcpy(combinedNonce.data(), clientNonce.data(), clientNonce.size());
            std::memcpy(combinedNonce.data() + clientNonce.size(), serverNonce.data(), serverNonce.size());

            // read hmac size
            uint32_t netRecievedHmacSize;
            std::memcpy(&netRecievedHmacSize, recievedPacket.payload + serverNonce.size(), sizeof(netRecievedHmacSize));

            // read remote hmac
            uint32_t recievedHmacSize = ntohl(netRecievedHmacSize);
            std::array<unsigned char, EVP_MAX_MD_SIZE> recievedHmac;
            std::memcpy(recievedHmac.data(), recievedPacket.payload + serverNonce.size() + sizeof(netRecievedHmacSize), recievedHmacSize);

            // create local hmac
            std::array<unsigned char, EVP_MAX_MD_SIZE> localHmac;
            uint32_t hmacLen = 0;
            HMAC(EVP_sha256(),
                 secret, std::strlen(secret),
                 combinedNonce.data(), combinedNonce.size(),
                 localHmac.data(), &hmacLen);

            // compare hmac's
            if (CRYPTO_memcmp(recievedHmac.data(), localHmac.data(), hmacLen) != 0)
            {
                std::cerr<<"HMAC is wrong\n";
                return false;
            }

            FileTransferPacket packetToSend{};

            EVP_PKEY* pkey = generatePkey();
            std::string pubKey = getPubKeyStr(pkey);

            uint32_t keySize = pubKey.size();
            uint32_t netKeySize = htonl(keySize);

            std::memcpy(packetToSend.payload, &netKeySize, sizeof(netKeySize));
            std::memcpy(packetToSend.payload + sizeof(netKeySize), pubKey.data(), pubKey.size());
            packetToSend.flags_ = PacketFlag::PUB_KEY;

            sendPacket(socket, packetToSend);
            continue;
        }
        if (hasFlag(recievedPacket.flags_, PacketFlag::AES_KEY))
        {
            uint32_t netKeySize;
            std::memcpy(&netKeySize, recievedPacket.payload, sizeof(netKeySize));
            uint32_t keySize = ntohl(netKeySize);



            std::vector<uint8_t> encryptedKey(keySize);
            std::memcpy(encryptedKey.data(), recievedPacket.payload + sizeof(netKeySize), keySize);

            decryptedAESKey = decryptAESKey(encryptedKey, g_pkey);

            break;
        }
    }

    return true;
}


static int sendFileName(int sock_fd, const std::string& fileName)
{
    FileTransferPacket packetToSend{};

    auto encryptedFileName = aesEncrypt(std::vector<unsigned char>(fileName.begin(), fileName.end()),
                                        reinterpret_cast<const unsigned char*>(decryptedAESKey.data()));
    if (encryptedFileName.empty())
    {
        return -1;
    }

    uint32_t fileNameLen = encryptedFileName.size();
    uint32_t netFileNameLen = htonl(fileNameLen);

    std::memcpy(packetToSend.payload, &netFileNameLen, sizeof(netFileNameLen));
    std::memcpy(packetToSend.payload + sizeof(netFileNameLen), encryptedFileName.data(), encryptedFileName.size());

    sendPacket(sock_fd, packetToSend);

    FileTransferPacket recievedPacket = receivePacket(sock_fd);
    if (!hasFlag(recievedPacket.flags_, PacketFlag::ACK))
    {
        std::cerr << "Did not receive acknowledgement from server\n";
        return -1;
    }

    uint64_t netFileOffset;
    std::memcpy(&netFileOffset, recievedPacket.payload, sizeof(netFileOffset));
    uint64_t fileOffset = be64toh(netFileOffset);
    return fileOffset;
}


static std::string getFileNameFromPath(const std::string& srt)
{
    auto const pos = srt.find_last_of('/');
    return srt.substr(pos + 1);
}
