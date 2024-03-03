#include "etftp_security.h"
#include "etftp_misc.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string>
#include <string.h>
#include <sstream>
#include <iomanip>


namespace ETFTP
{

    void randomMask(Buffer& buffer)
    {
        if(buffer.size() != 512) {
            buffer.init(512);
        }
        static bool initialized = false;
        if (!initialized)
        {
            RAND_poll();
            initialized = true;
        }
        RAND_bytes(buffer.data(), 512);
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