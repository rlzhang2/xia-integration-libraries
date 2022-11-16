#include "localconfig.hpp"

//#include <string>
#include <memory>
#include <atomic>
#include <iostream>

#include <signal.h>

#include "quicxiasock.hpp"          // QUICXIASocket
#include "dagaddr.hpp"              // Graph
#include "xcache_quic_server.h"     // XcacheQUICServer
#include "xcache_icid_handler.h"    // XcacheICIDHandler
#include "fd_manager.h"             // FdManager

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"

#define CONFFILE "xcache.local.conf"
#define XCACHE_AID "XCACHE_AID"
#define TEST_CID "TEST_CID"

#define TEST_CHUNK_SIZE 8192

using namespace std;

// Cleanup on interrupt
atomic<bool> stop(false);

// Simply flip the 'stop' switch so main loop will exit and clean up
void sigint_handler(int) {
    stop.store(true);
}

void installSIGINTHandler() {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = sigint_handler;
    sigfillset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
}

int main()
{
    installSIGINTHandler();

    // Get XIDs from local config file
    auto conf = LocalConfig(CONFFILE);
    auto xcache_aid = conf.get(XCACHE_AID);
    auto test_cid = conf.get(TEST_CID);
    if (xcache_aid.size() == 0) {
        cout << "ERROR: XCACHE_AID entry missing in " << CONFFILE << endl;
        return -1;
    }
    if (test_cid.size() == 0) {
        cout << "ERROR: TEST_CID entry missing in " << CONFFILE << endl;
        return -1;
    }
    
    // We give a fictitious AID for now, and get a dag in my_addr
    XcacheQUICServer server(xcache_aid);
    XcacheICIDHandler icid_handler(server);

    // This is how we tell the server that a CID is available
    // and it creates a route for it on the router
    GraphPtr dummy_cid_addr = server.serveCID(test_cid);

    // Wait for packets
    int64_t delay_max = 10000000;      // max wait 10 sec.
    int64_t delta_t;

    FdManager fd_mgr;
    fd_mgr.addDescriptor(server.fd());
    fd_mgr.addDescriptor(icid_handler.fd());

    while (true) {
        delta_t = server.nextWakeDelay(delay_max);
        std::vector<int> ready_fds;
        int ret = fd_mgr.waitForData(delta_t, ready_fds);

        if (stop.load()) {
            std::cout << "Interrupted. Cleaning up..." << std::endl;
            break;
        }

        if (ret < 0) {      // error
            std::cout << "ERROR polling for data" << endl;
        }
        if (ret == 0) {     // timed out
            continue;
        }

        for (auto fd : ready_fds) {
            if (fd == server.fd()) {
                server.incomingPacket();
            }
            if (fd == icid_handler.fd()) {
                icid_handler.handleICIDRequest();
                continue;
            }
        }

    }

    // Server ended. Return success
    return 0;
}
