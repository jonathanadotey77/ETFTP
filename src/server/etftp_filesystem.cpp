#include "etftp_filesystem.h"

namespace ETFTP
{

const std::string FileSystem::FILESYSTEM_ROOT =
    std::string(std::getenv("ETFTP_ROOT")) + "/filesystem";

bool FileSystem::init()
{
    return true;
}

}