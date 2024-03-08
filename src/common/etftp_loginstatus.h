#ifndef ETFTP_LOGINSTATUS_H
#define ETFTP_LOGINSTATUS_H

namespace ETFTP
{
    enum LoginStatus
    {
        e_LoginFailed = 0,
        e_LoginSuccess = 1,
        e_NoAvailablePort = 2,
        e_NoSuchUser = 3,
        e_UserAlreadyExists = 4
    };
}

#endif