#ifndef ETFTP_LOGINSYSTEM_H
#define ETFTP_LOGINSYSTEM_H

#include <string>
#include <fstream>
#include <sqlite3.h>
#include "../common/etftp_loginstatus.h"

namespace ETFTP
{
    class LoginSystem
    {

    private:
        static const std::string LOGIN_FILE;
        sqlite3 *dbHandle;

    public:
        LoginSystem() {}

        bool start();

        void stop();

        LoginStatus tryLogin(const std::string &username, const std::string &password);

        LoginStatus registerUser(const std::string &username, const std::string &password);

        LoginStatus changePassword(const std::string &username,
                                   const std::string &oldPassword,
                                   const std::string &newPassword);
    };
}

#endif