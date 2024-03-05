#include "etftp_loginsystem.h"
#include <string.h>

typedef struct LoginStruct
{
    ETFTP::LoginStatus status; // 0 if user not found; 1 if login success; 2 if incorrect password
    const std::string *password;
} LoginStruct;

static int loginCallback(void *data, int argc, char **argv, char **)
{
    LoginStruct *loginStruct = static_cast<LoginStruct *>(data);

    for (int i = 0; i < argc; ++i)
    {
        std::string temp(argv[i]);
        if (temp == *loginStruct->password)
        {
            loginStruct->status = ETFTP::LoginStatus::e_Success;
        }
        else
        {
            loginStruct->status = ETFTP::LoginStatus::e_IncorrectPassword;
        }
    }
    return 0;
}

namespace ETFTP
{
    const std::string LoginSystem::LOGIN_FILE = std::string(getenv("ETFTP_ROOT")) + "/login/login.db";
    bool LoginSystem::start()
    {
        int rc = sqlite3_open(LOGIN_FILE.c_str(), &dbHandle);
        if (rc)
        {
            fprintf(stderr, "Couldn't open database\n");
            sqlite3_close(dbHandle);
            return false;
        }
        char *error = NULL;

        const char *sql = "CREATE TABLE IF NOT EXISTS USERS ("
                          "username TEXT PRIMARY KEY,"
                          "password TEXT NOT NULL);";
        sqlite3_exec(dbHandle, sql, NULL, NULL, &error);
        if (error)
        {
            fprintf(stderr, "|%s|\n", error);

            return false;
        }

        return true;
    }

    void LoginSystem::stop()
    {
        sqlite3_close(dbHandle);
    }

    LoginStatus LoginSystem::tryLogin(const std::string &username, const std::string &password)
    {
        char sql[512] = {0};
        sprintf(sql, "SELECT password FROM USERS WHERE username = '%s';", username.c_str());
        LoginStruct loginStruct;
        loginStruct.status = LoginStatus::e_NoSuchUser;
        loginStruct.password = &password;
        sqlite3_exec(dbHandle, sql, loginCallback, &loginStruct, NULL);
        memset(sql, 0, 512);

        return loginStruct.status;
    }

    LoginStatus LoginSystem::registerUser(const std::string &username, const std::string &password)
    {
        LoginStatus rc = this->tryLogin(username, password);
        if (rc != e_NoSuchUser)
        {
            return LoginStatus::e_UserAlreadyExists;
        }

        char sql[512] = {0};

        sprintf(sql, "INSERT INTO USERS (username, password) VALUES ('%s', '%s')", username.c_str(), password.c_str());
        sqlite3_exec(dbHandle, sql, NULL, NULL, NULL);
        memset(sql, 0, 512);

        return LoginStatus::e_Success;
    }

    LoginStatus LoginSystem::changePassword(const std::string &username,
                                                    const std::string &oldPassword,
                                                    const std::string &newPassword)
    {
        LoginStatus rc = this->tryLogin(username, oldPassword);
        if(rc == e_IncorrectPassword || rc == e_NoSuchUser) {
            return rc;
        }

        char sql[512] = {0};

        sprintf(sql, "UPDATE USERS SET password = '%s' WHERE username = '%s';", newPassword.c_str(), username.c_str());
        sqlite3_exec(dbHandle, sql, NULL, NULL, NULL);
        memset(sql, 0, 512);

        return LoginStatus::e_Success;
    }

};