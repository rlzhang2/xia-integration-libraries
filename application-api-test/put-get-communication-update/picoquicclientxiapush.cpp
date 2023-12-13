 #include "localconfig.hpp"
// XIA support
#include <openssl/pem.h>
#include "../xia-api-lib/xiaapi.hpp"
#include "dagaddr.hpp"
#include "headers/ncid_header.h"
#include "../contentchunk-lib/chunkapi.h"               //chunk content
#include "../contentchunk-lib/chunkhash.h"
#include "../contentchunk-lib/get_putChunkapi.h"
#include "./picoquicclientxiapush.h"

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
#define CHUNK_STORE "CHUNK_STORE"
#define IFNAME "IFNAME"
#define CONTROL_PORT "8295"
#define CONTROL_IP "172.64.0.31"
#define WORKDIR "WORKDIR"
#define TEST_CID "TEST_CID"
#define PUT_TYPE "PUT_TYPE"

/*The function takes the application parameters, creates chunks of the requested content file
 * and iterates the chunks xid and execute PUT operation over the picoquic connection to send 
 * chunks to server destination
 * @param: filename - content file requesting to PUT onto server destination
 * @chun_size: size of the chunk
 * @cidtype: CID or namedbased CID
 * @chunk_loc: location of the chunks created
 * @myaddr: struct addr_info_to of the source address of the PUT request
 * @serveraddr: struct addr_info_to of the destination address of PUT request
 * return 0 if successful, otherwise -1
 */
int putfile(string filename, uint32_t chunk_size, string cidtype, 
		string chunk_loc, addr_info_t &myaddr,addr_info_t &serveraddr, LocalConfig &conf) {
	//chunk the file
	vector <string> xid_lst;
	xid_lst=chunk_file_hash(filename, chunk_size, cidtype, chunk_loc);
	if (xid_lst.size()==0) {
		printf("Error: failed to create chunk from content");
		return -1;
	}	
	std::string proc_type ="PUT";
        if (cnx_handler (myaddr, serveraddr, xid_lst, chunk_loc, proc_type, conf) <0) {
		return -1;
	}
       return 0;
	//put the list to send onto quic
}


int putchunk(std::string xid_str, std::string chunk_loc, addr_info_t &myaddr,addr_info_t &serveraddr,LocalConfig &conf) {
        //put the chunkxid in the xidlst, and retrieve the chunk from chunk_loc
        vector <string> xid_lst;
	xid_lst.emplace_back(xid_str);
	for (int i=0; i<xid_lst.size(); i++) {
		 std::cout<<xid_lst[i];
	 }
	std::string proc_type ="PUT";
        if (cnx_handler (myaddr, serveraddr, xid_lst, chunk_loc, proc_type, conf) <0) {
		return -1;
	}
	return 0;

        //put the list to send onto quic
}

/* The function is to get chunk based on xid from a destination server and store the chunk into the desired location
@param: chunk xid: chunk identifier
@param: serverdag: server that client request to retrieve chunk
@param: receiving_loc: the location stores receiving chunks from provider
@Return 0 if succesful, otherwise -1
*/
int getchunk(std::string xid_str, std::string recv_loc, addr_info_t &myaddr,addr_info_t &serveraddr,LocalConfig &conf) {
        //retrieve the chunk for chunk_loc
        //put the chunkxid in the xidlst so 
        vector <string> xid_lst;
        xid_lst.emplace_back(xid_str);
        for (int i=0; i<xid_lst.size(); i++) {
                 std::cout<<xid_lst[i];
         }
        std::string proc_type ="GET";
        if (cnx_handler (myaddr, serveraddr, xid_lst, recv_loc, proc_type, conf) <0) {
                return -1;
        }
        return 0;

        //put the list to send onto quic
}

int cnx_handler (struct addr_info_t &test_from_addr, 
		 struct addr_info_t &test_to_addr, vector<string> xidlst, string chunk_loc, string proc_type, LocalConfig &conf) {
	int retval=-1;
	int state = 0;

	uint64_t current_time;
	struct callback_context_t callback_context;
	FILE* logfile = NULL;
	
	//get chunking xids

	picoquic_quic_t *quic_client;

        memset(&callback_context, 0, sizeof(struct callback_context_t));

        state = 1; // socket created
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

	get_chunk_data (test_from_addr, test_to_addr, xidlst, quic_client, callback_context,
                                       state, current_time, chunk_loc, proc_type, conf);
	retval=0;	
        client_done:
                 switch(state) {
                    case 3:
                        fclose(logfile);
                    case 2:
                        picoquic_free(quic_client);
                    case 1:
                        close(test_from_addr.sockfd);
         };
   	return retval;
}

 //initial the clientapplication
 //take the confile file and return from and serveraddr including clientsocket
int init_client(LocalConfig &conf, addr_info_t &myaddr, addr_info_t &serveraddr){
	int retval =0;
        //auto chunksize = conf.get(CHUNK_SIZE);
	conf.control_addr = CONTROL_IP;
        conf.control_port = CONTROL_PORT;
        //std::cout<<"chunk size: " <<chunksize<<std::endl;
         if(conf.configure(conf.control_port, conf.control_addr, myaddr, serveraddr) < 0)
        {
                std::cout<<"Error configuration" <<endl;
                retval=-1;
        } 
