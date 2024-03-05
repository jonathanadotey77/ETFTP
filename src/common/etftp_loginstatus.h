#ifndef ETFTP_LOGINSTATUS_H
#define ETFTP_LOGINSTATUS_H

namespace ETFTP
{
    enum LoginStatus
    {
        e_Success,
        e_IncorrectPassword,
        e_NoSuchUser,
        e_NoAvailablePort,
        e_UserAlreadyExists
    };
}

#endif