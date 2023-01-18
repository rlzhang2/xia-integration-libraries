 #include "localconfig.hpp"
// XIA support
#include <openssl/pem.h>
#include "../xia-api-lib/xiaapi.hpp"
#include "dagaddr.hpp"
#include "headers/ncid_header.h"
#include "../contentchunk-lib/chunkapi.h"               //chunk content
#include "../contentchunk-lib/chunkhash.h"
#include "../contentchunk-lib/get_putChunkapi.h"

// C++ includes
#include <iostream>
#include <fstream>

// C includes
#include <string.h> // memset
#include <stdio.h>
#include <pthread.h>

extern "C" {
#include "picoquic.h" // picoquic_create, states, err, pkt types, contexts
//#include "picoquic_internal.h"
#include "picosocks.h" // picoquic_select and server socks functions
#include "util.h"
};

#define CONFFILE "./conf/local.conf"
#define THEIR_ADDR "THEIR_ADDR" // The THEIR_ADDR entry in config file
#define CLIENT_AID "CLIENT_AID" // The CLIENT_AID entry in config file
#define CONTENT_STORE "CONTENT_STORE"
//#define WORKDIR "WORKDIR"
#define IFNAME "IFNAME"
#define CONTROL_PORT "8295"
#define CONTROL_IP "172.64.0.31"

int cnx_handler (struct addr_info_t &test_from_addr, 
		 struct addr_info_t &test_to_addr, LocalConfig &conf) {

        int retval = -1;
	int state = 0;

	uint64_t current_time;
	struct callback_context_t callback_context;
	std::string proc_type ="PUT";
	FILE* logfile = NULL;
	
	//get chunking xids
	auto confile = LocalConfig(CONFFILE);
	std::string homepath = getenv("HOME");
	#ifdef WORKDIR
                        homepath.assign(WORKDIR);
                #endif
        std::string tmpContent_f = homepath  + confile.get(CONTENT_STORE);
	vector <string> xid_lst;
        xid_lst = contentChunkIDs(tmpContent_f);

	picoquic_quic_t *quic_client;

        memset(&callback_context, 0, sizeof(struct callback_context_t));

        state = 1; // socket created
	printf("Client socket fd: %d\n", test_from_addr.sockfd);
        //step1. Create QUIC context for client
        current_time = picoquic_current_time();
        callback_context.last_interaction_time = current_time;

        quic_client = picoquic_create(
                        2,             // number of connections
                        NULL,          // cert_file_name
                        NULL,          // key_file_name
                        NULL,          // cert_root_file_name
                        "hq-17",       // Appl. Layer Protocol Nogotiation
                        NULL,          // Stream data callback
                        NULL,          // Stream data context
                        NULL,          // connection ID callback
                        NULL,          // connection ID callback context
                        NULL,          // reset_seed
                        current_time,  // current time
                        NULL,          // p_simulated_time
                        NULL,          // ticket_file_name
                        NULL,          // ticket_encryption_key
                        0              // ticket encryption key length
                        );
         if(quic_client == NULL) {
                printf("ERROR: creating client\n");
                goto client_done;
        }
        printf("Created QUIC context\n");
        state = 2; // picoquic context created for client

	//step2. create a log file for writing
        logfile = fopen("client.log", "w");
        if(logfile == NULL) {
                printf("ERROR opening log file\n");
                goto client_done;
        }
        PICOQUIC_SET_LOG(quic_client, logfile);
        state = 3; // logfile needs to be closed

	get_chunk_data (test_from_addr, test_to_addr, xid_lst, quic_client, callback_context,
                                       state, current_time, proc_type, conf);

        client_done:
                 switch(state) {
                    case 3:
                        fclose(logfile);
                    case 2:
                        picoquic_free(quic_client);
                    case 1:
                        close(test_from_addr.sockfd);
         };


        retval=0;
        return retval;
}

int main()
{
	 int retval = -1;	
	// read local config
	LocalConfig conf;
        conf.control_addr = CONTROL_IP;
        conf.control_port = CONTROL_PORT;

        addr_info_t myaddr;
        addr_info_t serveraddr;

	if(conf.configure(CONTROL_PORT, CONTROL_IP, myaddr, serveraddr) < 0)
        {
		std::cout<<"Error configuration" <<endl;
                return retval;
        } else {
		std::cout<<"Server Addr: "<< serveraddr.dag->dag_string().c_str()<<std::endl;
	} 

	cnx_handler(myaddr, serveraddr, conf);

	// Everything went well, so return success
	retval = 0;

	return retval;
	
}
