#include "etftp_filemutex.h"
#include <limits.h>

namespace ETFTP
{
    void FileMutex::acquireWriter()
    {
        while(true) {
            lock.lock();

            if(this->value == 0) {
                this->value = ULLONG_MAX;
            }

            lock.unlock();
        }
    }

    void FileMutex::acquireReader()
    {
        while(true) {
            lock.lock();

            if(this->value != ULLONG_MAX) {
                this->value++;
            }

            lock.unlock();
        }
    }

    void FileMutex::releaseWriter()
    {
        while(true) {
            lock.lock();

            this->value = 0;

            lock.unlock();
        }
    }

    void FileMutex::releaseReader()
    {
        while(true) {
            lock.lock();

            this->value--;

            lock.unlock();
        }
    }

    bool FileMutex::canDestroy() {
        lock.lock();

        if(this->value == 0) {
            return true;
        }

        lock.unlock();
        return false;
    }

}