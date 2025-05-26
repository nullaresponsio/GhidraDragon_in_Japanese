// src/softtpm.hpp
#ifndef SOFTTPM_HPP
#define SOFTTPM_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <fstream>

// OpenSSL headers
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/bio.h>

struct Quote {
    std::vector<std::string> pcrs;
    std::vector<uint8_t> sig;
    std::vector<uint8_t> nonce;
};

class SoftTPM {
public:
    SoftTPM(const std::string& path = ".softtpm");
    void extendPCR(uint32_t index, const std::vector<uint8_t>& data);
    Quote quote(const std::vector<uint8_t>& nonce, const std::vector<uint32_t>& mask);
    std::vector<uint8_t> getRandom(size_t n);
    std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
    std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& iv,
                                    const std::vector<uint8_t>& data);
    std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& iv,
                                    const std::vector<uint8_t>& data);
    std::vector<uint8_t> ecdh(const std::vector<uint8_t>& peerPubDer);
    void nvWrite(uint32_t index, const std::vector<uint8_t>& data);
    std::vector<uint8_t> nvRead(uint32_t index);
    uint64_t incCounter();

private:
    std::string basePath;
    void initKey();
    void loadKey();
    void saveKey();
    void initPCR();
    void savePCR();
    void initCounter();
    void saveCounter();

    std::vector<std::string> pcrs;
    uint64_t counter;
    EVP_PKEY* privKey;
};

#endif // SOFTTPM_HPP
