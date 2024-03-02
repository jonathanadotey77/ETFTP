#include "etftp_loginsystem.h"
#include <string.h>

typedef struct LoginStruct {
    int status; //0 if user not found; 1 if login success; 2 if incorrect password
    const std::string* password;
} LoginStruct;

static int loginCallback(void* data, int argc, char** argv, char**) {
    LoginStruct* loginStruct = static_cast<LoginStruct*>(data);

    for(int i = 0; i < argc; ++i) {
        std::string temp(argv[i]);
        if(temp == *loginStruct->password) {
            loginStruct->status = 1;
        } else {
            loginStruct->status = ETFTP::LoginSystem::Status::e_IncorrectPassword;
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
        if(rc) {
            fprintf(stderr, "Couldn't open database\n");
            sqlite3_close(dbHandle);
            return false;
        }
        char* error = NULL;

        const char *sql = "CREATE TABLE IF NOT EXISTS USERS ("
                          "username TEXT PRIMARY KEY,"
                          "password TEXT NOT NULL);";
        sqlite3_exec(dbHandle, sql, NULL, NULL, &error);
        if(error) {
            fprintf(stderr, "|%s|\n", error);

            return false;
        }
        printf("T\n");

        return true;
    }

    void LoginSystem::stop()
    {
        sqlite3_close(dbHandle);
    }

    LoginSystem::Status LoginSystem::tryLogin(const std::string &username, const std::string &password)
    {
        char sql[512] = {0};
        sprintf(sql, "SELECT password FROM USERS WHERE username = '%s';", username.c_str());
        LoginStruct loginStruct;
        loginStruct.status = ETFTP::LoginSystem::Status::e_NoSuchUser;
        loginStruct.password = &password;
        sqlite3_exec(dbHandle, sql, loginCallback, &loginStruct, NULL);
        memset(sql, 0, 512);

        switch (loginStruct.status)
        {
        case 0:
            return e_IncorrectPassword;
        case 1:
            return e_Success;
        case 2:
            return e_NoSuchUser;
        default:
            return e_Error;
        }
    }

    LoginSystem::Status LoginSystem::registerUser(const std::string &username, const std::string &password) {
        LoginSystem::Status rc = this->tryLogin(username, password);
        if(rc != e_NoSuchUser) {
            return e_UserAlreadyExists;
        }

        char sql[512] = {0};

        sprintf(sql, "INSERT INTO USERS (username, password) VALUES ('%s', '%s')", username.c_str(), password.c_str());
        sqlite3_exec(dbHandle, sql, NULL, NULL, NULL);
        memset(sql, 0, 512);

        return e_Success;
    }
};