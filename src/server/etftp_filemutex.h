#ifndef ETFTP_FILESYSTEM_H
#define ETFTP_FILESYSTEM_H

#include <cstdlib>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace ETFTP
{

    class FileMutex
    {
    public:
        std::mutex lock;
        volatile uint64_t value;

    public:
        FileMutex() : value(0){};

        void acquireWriter();
        void acquireReader();
        void releaseWriter();
        void releaseReader();

        bool canDestroy();
    };

}

#endif