#include "crypto_utils.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <iostream>

std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& plainData, const unsigned char* key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> encryptedText;
    encryptedText.resize(plainData.size() + AES_BLOCK_SIZE);
    int len = 0;
    int ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);

    EVP_EncryptUpdate(ctx, encryptedText.data(), &len,
                      reinterpret_cast<const unsigned char*>(plainData.data()), plainData.size());
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, encryptedText.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    encryptedText.resize(ciphertext_len);
    return encryptedText;
}


std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& encryptedText, const unsigned char* key)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> plainData;
    plainData.reserve(encryptedText.size() + AES_BLOCK_SIZE);
    int len = 0;
    int plainDataLen = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);

    EVP_DecryptUpdate(ctx, plainData.data(), &len, encryptedText.data(), encryptedText.size());
    plainDataLen = len;

    EVP_DecryptFinal_ex(ctx, plainData.data() + len, &len);
    plainDataLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return {plainData.begin(), plainData.begin() + plainDataLen};
}


bool generateAESKey(unsigned char* key, size_t key_size)
{
    if (RAND_bytes(key, key_size) != 1)
    {
        std::cerr << "Failed to generate aes key\n";
        return false;
    }
    return true;
}


std::array<uint8_t, 16> generateNonce()
{
    std::array<uint8_t, 16> nonce;
    if (RAND_bytes(nonce.data(), nonce.size()) != 1)
    {
        return {};
    }

    return nonce;
}


std::vector<uint8_t> enctyptAESKey(unsigned char* key, int aesKeySize, const std::string& pubKey)
{
    std::vector<uint8_t> encryptedKey;
    std::vector<uint8_t> aesKey(aesKeySize);
    std::memcpy(aesKey.data(), key, aesKeySize);
    EVP_PKEY* pkey = nullptr;

    BIO* bio = BIO_new_mem_buf(pubKey.data(), static_cast<int>(pubKey.size()));
    if (!bio)
        return {};

    pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey)
        return {};

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx)
    {
        EVP_PKEY_free(pkey);
        return {};
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0
        || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return {};
    }

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, aesKey.data(), aesKey.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return {};
    }

    encryptedKey.resize(outlen);

    if (EVP_PKEY_encrypt(ctx, encryptedKey.data(), &outlen, aesKey.data(), aesKey.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return {};
    }

    encryptedKey.resize(outlen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return encryptedKey;
}


std::vector<uint8_t> decryptAESKey(const std::vector<uint8_t>& encryptedKey, EVP_PKEY* pkey)
{
    std::vector<uint8_t> decryptedKey;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx)
        return {};

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    size_t outLen = 0;

    if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, encryptedKey.data(), encryptedKey.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    decryptedKey.resize(outLen);

    if (EVP_PKEY_decrypt(ctx, decryptedKey.data(), &outLen, encryptedKey.data(), encryptedKey.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    decryptedKey.resize(outLen);

    EVP_PKEY_CTX_free(ctx);
    return decryptedKey;
}


std::vector<uint8_t> calcSHA256(const std::vector<uint8_t>& input)
{
    std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
    unsigned int hashLen = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, hash.data(), &hashLen);
    EVP_MD_CTX_free(ctx);

    hash.resize(hashLen);
    return hash;
}
