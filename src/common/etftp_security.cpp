#include "etftp_security.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string>
#include <sstream>
#include <iomanip>

namespace ETFTP
{

    void random_mask(unsigned char *buffer)
    {
        static bool initialized = false;
        if (!initialized)
        {
            RAND_poll();
            initialized = true;
        }
        RAND_bytes(buffer, 512);
    }

    bool computeHash(const std::string &unhashed, std::string &hashed)
    {
        bool success = false;

        EVP_MD_CTX *context = EVP_MD_CTX_new();

        if (context != NULL)
        {
            if (EVP_DigestInit_ex(context, EVP_sha256(), NULL))
            {
                if (EVP_DigestUpdate(context, unhashed.c_str(), unhashed.length()))
                {
                    unsigned char hash[EVP_MAX_MD_SIZE];
                    unsigned int lengthOfHash = 0;

                    if (EVP_DigestFinal_ex(context, hash, &lengthOfHash))
                    {
                        std::stringstream ss;
                        for (unsigned int i = 0; i < lengthOfHash; ++i)
                        {
                            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                        }

                        hashed = ss.str();
                        success = true;
                    }
                }
            }

            EVP_MD_CTX_free(context);
        }

        return success;
    }

}