#include "etftp_filemutex.h"

#include <limits.h>

namespace ETFTP
{
    FileMutex::FileMutex() {
        this->value = 0;
    }
    
    void FileMutex::acquireWriter()
    {
        lock.lock();

        if (this->value == 0)
        {
            this->value = ULLONG_MAX;
        }

        lock.unlock();
    
    }

    void FileMutex::acquireReader()
    {
        lock.lock();

        if (this->value != ULLONG_MAX)
        {
            this->value++;
        }

        lock.unlock();
    }

    void FileMutex::releaseWriter()
    {
        lock.lock();

        this->value = 0;

        lock.unlock();
    
    }

    void FileMutex::releaseReader()
    {
        lock.lock();

        this->value--;

        lock.unlock();
    }

    bool FileMutex::canDestroy()
    {
        lock.lock();

        if (this->value == 0)
        {
            return true;
        }

        lock.unlock();
        return false;
    }

}