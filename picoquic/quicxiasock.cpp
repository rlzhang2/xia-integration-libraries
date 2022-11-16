#include <quicxiasock.hpp>

#include "xiaapi.hpp"

#include <unistd.h> // close()
#include <iostream> // cout, endl
using namespace std;

QUICXIASocket::QUICXIASocket(const std::string& aid) {
    sockfd = picoquic_xia_open_server_socket(aid.c_str(), our_addr);
    if (sockfd == -1) {
        throw "ERROR opening server socket";
    }
    _aid = aid;
}

QUICXIASocket::~QUICXIASocket() {
    cout << __FUNCTION__ << " closing QUIC socket " << endl;
    for(auto cid : cids_served) {
        if (picoquic_xia_unserve_cid(cid.c_str())) {
            cout << "ERROR removing route for " << cid << endl;
        }
    }
    if (picoquic_xia_unserve_aid(_aid.c_str())) {
        cout << "ERROR removing route for Xcache " << _aid << endl;
    }
    if (sockfd != -1) {
        close(sockfd);
    }
}

GraphPtr QUICXIASocket::serveCID(const std::string& cid) {
    GraphPtr cid_addr;
    if (picoquic_xia_serve_cid(sockfd, cid.c_str(), cid_addr)) {
        cout << "ERROR setting up route for " << cid << endl;
        return cid_addr;
    }
    cids_served.insert(cid);
    return cid_addr;
}

bool QUICXIASocket::unserveCID(const std::string& cid) {
    if (picoquic_xia_unserve_cid(cid.c_str())) {
        cout << "ERROR removing route for CID: " << cid << endl;
        return false;
    }
    return true;
}

int QUICXIASocket::fillAddress(sockaddr_x& addr) {
    our_addr->fill_sockaddr(&addr);
    return 0;
}

int QUICXIASocket::fd() {
    return sockfd;
}
