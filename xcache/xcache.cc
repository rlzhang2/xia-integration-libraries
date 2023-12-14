#include "localconfig.hpp"

//#include <string>
#include <memory>
#include <atomic>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
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
#define CONTENT_STORE "CONTENT_STORE"
#define WORKDIR "WORKDIR"

using namespace std;

// Cleanup on interrupt
atomic<bool> stop(false);

// subfunction to load content if need
int load_content(XcacheQUICServer& server, string cf){
	int retVal;
	bool bExists = false;
	
	//first check if recv storage for put
	struct stat st;
	if(stat("./tmpChunks_recv",&st) == 0)
    		if(st.st_mode & S_IFDIR != 0){
        //		printf(" directory is present\n");
			bExists = true;
		}
	// check test for putting one content file
	ifstream f_content;
        f_content.open(cf.c_str());
        if(f_content && !bExists) {
                vector <string> xid_lst;
                xid_lst = contentChunkIDs(cf);

		//check router addr:
                if ( xid_lst.size() > 0 ) {
                        //print_chunklst(xid_lst);
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
		printf("Error: content chunks failed to load\n");
                retVal = -1;
                }
        }
	return retVal;
}

//

int main()
{
auto conf = LocalConfig(CONFFILE);
auto xcache_aid = conf.get(XCACHE_AID);

 XcacheQUICServer server(xcache_aid);
 XcacheICIDHandler icid_handler(server);

std::string proc_type;
std::string homepath = getenv("HOME");
#ifdef WORKDIR
	homepath.assign(conf.get(WORKDIR));
#endif

std::string xContent_f = homepath  + conf.get(CONTENT_STORE);

    //int r = load_content(server, xContent_f);
    
    //check CID to get
    //getString =server.getCID();

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

        for (auto fd : ready_fds) {
            if (fd == server.fd()) {
		cout << "incoming packet on socket "<<fd<<endl;
                server.incomingPacket();
            }
            if (fd == icid_handler.fd()) {
		std::cout<<"coming to iCID handler!!"<<std::endl;
                icid_handler.handleICIDRequest();
                continue;
            }
        }

	if (ret == 0) {     // timed out
            continue;
        }


    }

    // Server ended. Return success
    return 0;
}
