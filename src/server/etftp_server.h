#ifndef ETFTP_SERVER_H
#define ETFTP_SERVER_H

namespace ETFTP
{

class Server {
public:

    Server(unsigned short port);

    bool start();
    bool stop();

};

}

#endif