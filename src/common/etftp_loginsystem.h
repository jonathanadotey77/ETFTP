#ifndef ETFTP_LOGINSYSTEM_H
#define ETFTP_LOGINSYSTEM_H

#include <string>
#include <fstream>
#include <sqlite3.h>

namespace ETFTP
{
    class LoginSystem
    {
    public:
        enum Status
        {
            e_Success,
            e_IncorrectPassword,
            e_NoSuchUser,
            e_NoAvailablePort,
            e_UserAlreadyExists,
            e_Error
        };

    private:
        static const std::string LOGIN_FILE;
        sqlite3 *dbHandle;

    public:
        LoginSystem() {}

        bool start();

        void stop();

        Status tryLogin(const std::string &username, const std::string &password);

        Status registerUser(const std::string &username, const std::string &password);

        Status changePassword(const std::string &username,
                              const std::string &oldPassword,
                              const std::string &newPassword);
    };
}

#endif