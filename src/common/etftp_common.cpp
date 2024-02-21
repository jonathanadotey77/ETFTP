#include "etftp_common.h"
#include <openssl/rand.h>

namespace ETFTP
{

    void random_mask(unsigned char *buffer)
    {
        RAND_poll();
        RAND_bytes(buffer, 512);
    }

}