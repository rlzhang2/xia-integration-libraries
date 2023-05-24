#include "localconfig.hpp"

//#include <string>
#include <memory>
#include <atomic>
#include <iostream>

#include <signal.h>

#include "../xia-api-lib/quicxiasock.hpp"          // QUICXIASocket
#include "dagaddr.hpp"              // Graph
#include "../contentchunk-lib/chunkapi.h"               //chunk content
#include "../contentchunk-lib/chunkhash.h"              //chunk hashtable
#include "xcache_quic_server.h"     // XcacheQUICServer
#include "xcache_icid_handler.h"    // XcacheICIDHandler
#include "fd_manager.h"             // FdManager

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"

#define CONFFILE "./conf/local.conf"
#define XCACHE_AID "XCACHE_AID"
#define TEST_CID "TEST_CID"
#define CONTENT_STORE "CONTENT_STORE"


using namespace std;

// Cleanup on interrupt
atomic<bool> stop(false);

int main()
{
cout <<"HERE get chunking xids for xcache!!!"<<endl;
auto conf = LocalConfig(CONFFILE);
auto xcache_aid = conf.get(XCACHE_AID);

//sockets
 XcacheQUICServer server(xcache_aid);
 XcacheICIDHandler icid_handler(server);

//auto test_cid = conf.get(TEST_CID);
std::string proc_type ="PUT";
std::string homepath = getenv("HOME");
#ifdef WORKDIR
	homepath.assign(WORKDIR);
#endif
//1. load chunk cids onto xcache
std::string xContent_f = homepath  + conf.get(CONTENT_STORE);
vector <string> xid_lst;
xid_lst = contentChunkIDs(xContent_f);
if (xid_lst.empty()) {
	proc_type="GET";
	//neet check if available locally, return to client; otherwise retrieve from endServer 
} else {
	print_chunklst(xid_lst);

	//2. build chunking xid route entry to router forwarding table
    	for (int i=0; i<xid_lst.size(); i++) {
    	cout << "Check the chunkID passing to BuilldRoute " << xid_lst[i] << endl;
    	std::vector<uint8_t> rawf_chunk;
    	std::pair<string, uint8_t*> Tpair = get_chunkhash(xid_lst[i].c_str(), rawf_chunk);
    	cout << "PUT chunk cid on xcache  path "<< Tpair.first.c_str()<<endl;
    	GraphPtr dummy_cid_addr = server.serveCID(xid_lst[i].c_str());
    	}
}

    if (xcache_aid.size() == 0) {
        cout << "ERROR: XCACHE_AID entry missing in " << CONFFILE << endl;
        return -1;
    }
    /*if (test_cid.size() == 0) {
        cout << "ERROR: TEST_CID entry missing in " << CONFFILE << endl;
        return -1;
    }*/


    /*// This is how we tell the server that a CID is available
    // and it creates a route for it on the router
    GraphPtr dummy_cid_addr = server.serveCID(test_cid);
    */

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
		std::cout << "Now coming in quic server incomingPacket process!!..." << std::endl;
                server.incomingPacket();
            }
            if (fd == icid_handler.fd()) {
		std::cout<<"Now coming to iCID handler!!"<<std::endl;
                icid_handler.handleICIDRequest();
                continue;
            }
        }

    }

    // Server ended. Return success
    return 0;
}
