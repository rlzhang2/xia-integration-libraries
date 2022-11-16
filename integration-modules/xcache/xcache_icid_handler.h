#ifndef _XCACHE_ICID_HANDLER_H
#define _XCACHE_ICID_HANDLER_H

#include "xcache_quic_server.h"

#define ICID_HANDLER_PORT 7994
#define ICID_MAXBUF 2048

class XcacheICIDHandler {
public:
    XcacheICIDHandler(XcacheQUICServer& server);
    ~XcacheICIDHandler();
    int fd();
    int handleICIDRequest();
private:
    XcacheQUICServer& _server;
    int _sockfd = {-1};
};
#endif //_XCACHE_ICID_HANDLER_H
