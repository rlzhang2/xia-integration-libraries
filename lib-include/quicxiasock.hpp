#ifndef QUIC_XIA_SOCK_H
#define QUIC_XIA_SOCK_H

#include "xiaapi.hpp"

#include <string>
#include <vector>
#include <unordered_set>

class QUICXIASocket {
    public:
        QUICXIASocket(const std::string& aid);
        ~QUICXIASocket();
        GraphPtr serveCID(const std::string& cid);
        bool unserveCID(const std::string& cid);
        int fd();
        int fillAddress(sockaddr_x& addr);
    private:
        std::string _aid;
        std::unordered_set<std::string> cids_served;
        int sockfd = -1;
        GraphPtr our_addr;
};
#endif //QUIC_XIA_SOCK_H
