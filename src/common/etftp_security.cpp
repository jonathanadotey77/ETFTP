#include "etftp_security.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string>
#include <string.h>
#include <sstream>
#include <iomanip>

static std::string bytesToHexString(const unsigned char *bytes, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return ss.str();
}

namespace ETFTP
{

    void randomMask(unsigned char *buffer)
    {
        static bool initialized = false;
        if (!initialized)
        {
            RAND_poll();
            initialized = true;
        }
        RAND_bytes(buffer, 512);
    }

    void hashPassword(const std::string& password, std::string& hashedPassword) {
        unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        unsigned int md_len;

        OpenSSL_add_all_algorithms();
        md = EVP_get_digestbyname("sha256");

        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, password.c_str(), password.length());
        EVP_DigestFinal_ex(mdctx, digest, &md_len);
        EVP_MD_CTX_free(mdctx);

        hashedPassword = bytesToHexString(digest, SHA256_DIGEST_LENGTH);
    }


    bool validPassword(const std::string& password) {
        if(password.length() < 8 || password.length() > 32) {
            return false;
        }

        return true;
    }

}