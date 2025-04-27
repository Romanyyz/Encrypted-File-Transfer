#pragma once

#include <iomanip>
#include <vector>
#include <string>
#include <cstdint>
#include <array>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/pem.h>

[[maybe_unused]]
static const char* secret = "E9f7c1B2a3D5_48eF-9zXaQ!7Uv@Wm4K";

std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& plainData, const unsigned char* key);
std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& encryptedText, const unsigned char* key);
std::array<uint8_t, 16> generateNonce();
bool generateAESKey(unsigned char* key, size_t key_size);
std::vector<uint8_t> enctyptAESKey(unsigned char* key, int aesKeySize, const std::string& pubKey);
std::vector<uint8_t> decryptAESKey(const std::vector<uint8_t>& encryptedKey, EVP_PKEY* pkey);
std::vector<uint8_t> calcSHA256(const std::vector<uint8_t>& input);
