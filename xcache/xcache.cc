#include "localconfig.hpp"

//#include <string>
#include <memory>
#include <atomic>
#include <iostream>
#include <fstream>

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
#define ROUTER_PORT "ROUTER_PORT"
#define WORKDIR "WORKDIR"

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

auto test_cid = conf.get(TEST_CID);
char* tmp_c = const_cast<char*>(test_cid.c_str());
std::string proc_type;
std::string homepath = getenv("HOME");
#ifdef WORKDIR
	homepath.assign(conf.get(WORKDIR));
#endif
//PUT contents on xcache
std::string xContent_f = homepath  + conf.get(CONTENT_STORE);

//Check if file available for PUT or GET
ifstream f_content;
f_content.open(xContent_f.c_str());
if(f_content) {
	vector <string> xid_lst;
	xid_lst = contentChunkIDs(xContent_f);

	if ( xid_lst.size() > 0 ) {
		proc_type="PUT";
 		print_chunklst(xid_lst);
        //1. add hashtable for later lookup
        	server.upthashtable(xid_lst);
        	//cout<<"xcache xidhash after inserting the xid to be put: "<<server.gethashtable()<<endl;

        //2. build chunking xid route entry to router forwarding table
        	for (int i=0; i<xid_lst.size(); i++) {
                	std::vector<uint8_t> rawf_chunk;
                	std::pair<string, uint8_t*> Tpair = get_chunkhash(xid_lst[i].c_str(), rawf_chunk);
                	cout << "PUT "<< xid_lst[i].c_str() << " on xCache: "<< Tpair.first.c_str()<<endl;
		//3. build route for chunking on router
                	if ( print_lookup(server.gethashtable(), const_cast<char*>(xid_lst[i].c_str())) ==0 ) {
                        	GraphPtr dummy_cid_addr = server.serveCID(xid_lst[i].c_str());
                	}
        	}
	} else {
		cout << "ERROR: failed to chunk on content file" << endl;
		return -1;
	}

} else { //capture XID to GET from config file
	proc_type="GET";
	if ( test_cid.size() == 0) {
        	cout << "ERROR: missing contentID entry to GET in " << CONFFILE << endl;
        	return -1;
	}
	if ( print_lookup(server.gethashtable(), tmp_c) == 0 ){
		 // This is how we tell the server that a CID is available
    		// and it creates a route for it on the router
		 GraphPtr dummy_cid_addr = server.serveCID(test_cid);
	}
     	// check if content data accessible on xcache
      	std::vector<uint8_t> testdata;

      	std::pair<string, uint8_t*> tmppair = get_chunkhash(test_cid.c_str(), testdata);
      	if(!(tmppair.first).empty()){
          cout<< "Found matched CID "<<test_cid.c_str()<<endl;
          std::tuple<string, std::vector<uint8_t>, size_t> result =load_chunk(test_cid.c_str(), testdata);

          std::cout <<"Chunk path: " <<get<0>(result)<<" Chunk size: "<<get<2>(result)<<std::endl;
         // std::cout<< (get<1>(result)).data() <<std::endl;

      } else {
	      cout<< "No match CID in the route "<<test_cid.c_str()<<endl;
	      cout<<"Now we need issue GET request to endSErver from Xcache!!"<<endl;
      	}
} 

    if (xcache_aid.size() == 0) {
        cout << "ERROR: XCACHE_AID entry missing in " << CONFFILE << endl;
        return -1;
    }

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
		cout << "checking socket available fd: "<<fd <<" to call XCACHE_QUIC_SERVER::incomingPacket"<<endl;
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
