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
#define CONTENT_STORE "CONTENT_STORE"
#define IFNAME "IFNAME"
#define CONTROL_PORT "8295"
#define CONTROL_IP "172.64.0.31"
#define WORKDIR "WORKDIR"
#define TEST_CID "TEST_CID"
#define PUT_TYPE "PUT_TYPE"


//application parameter
#define APPCONF "./conf/clientapp.conf"
#define CHUNK_SIZE 250
#define FILE_NAME "/home/ruilingz/picoquic/tmpContents/testsample"
#define CHUNK_LOC "/home/ruilingz/picoquic/tmpChunks/"
#define CHUNK_RECV "/home/ruilingz/picoquic/tmpChunks_recv/"
#define SERVER_AID "SERVER_AID" // The CLIENT_AID entry in config file
#define CIDTYPE "CID"

//this is application call test
int main()
{
	 int retval = -1;	
	//1. read local config, init client  -PASS
	LocalConfig conf;
	addr_info_t myaddr;
        addr_info_t serveraddr;

	vector <string> xid_lst;
	//application parameters
        std::string f_name= FILE_NAME;
        std::string cidtype=CIDTYPE;
        std::string chunk_loc=CHUNK_LOC;
	std::string recv_loc=CHUNK_RECV;

	std::string test_xid;
        test_xid.assign("CID:056beed41ac937a205617f3a0ba708feb19d319e");

	if ((init_client(conf, myaddr, serveraddr))<0) {
		printf ("Error: Client init failure");
		return retval;
	} 
	printf("Completed client initialization \n");
	std::cout<<"Server Addr: "<< serveraddr.dag->dag_string().c_str()<<std::endl;
        std::cout<<"My Addr dag: "<< myaddr.dag->dag_string().c_str() <<" Myaddr socket: "<< myaddr.sockfd<<std::endl;

	//1. testcase:client pass the server alias, and get the serverdag update to this
	//serverAlias -> ServerAID (client.conf) -> based on AID update the DAG
	auto clientconf = LocalConfig(APPCONF);
        auto serveraid = clientconf.get(SERVER_AID);
	std::string curr_serverdag_str =conf.get_serverdag_str();
        //conf.update_serveraddr(conf, conf.get_our_addr() + " " + xcache_aid + " " + test_cid);
	std::cout<<"SERVER AID: " <<serveraid.c_str()<<std::endl;
        std::cout<<"Current SERVER ADDR : " <<curr_serverdag_str.c_str()<<std::endl;
	

	/*//2.  chunkfile     --PASS
	xid_lst=chunk_file_hash(f_name, CHUNK_SIZE, cidtype, chunk_loc);
	if (xid_lst.size() ==0){
		return retval;
	}
	printf("Completed creating chunks \n");
	for (int i=0; i<xid_lst.size(); i++){
               std::cout<<"XID: "<< xid_lst[i].c_str()<<endl;
		}
	*/
	//3. putfile dag conversion test  --convert to graph DAG, then fill in sockaddr to use as destination serveraddress?
	//param src text representation of the DAG to convert (eg.DAG, RE,) 
	//int xia_pton( const char *src, sockaddr_x *dst)
	std::string test_srvdag;
	test_srvdag.assign("RE AD:236e92d9c30e3566921564e9ab362db3b1f417e0 HID:0acc12daed1d6145a8e67afcba885b3379021eed AID:69a4e068880cd40549405dfda6e794b0c7fdf195");
	
	try {
		Graph g(test_srvdag);
		addr_info_t testsrvaddr;
		g.fill_sockaddr(&testsrvaddr.addr);
        	std::cout << "TEST Server addr: " << g.dag_string() << std::endl;

        } catch (std::exception e) {
		printf("Error: convert from text to xia addr");
                return retval;
        }
	
	/*//4.putfile    --PASS
	//putfile will call chunk_file_hash to received chunklist and PUT list of chunks onto server
	if( putfile(f_name,CHUNK_SIZE, cidtype, chunk_loc, myaddr,serveraddr, conf) <0) {
		return retval;
	}
	*/
	
	//5. putchunk --PASS
	//test to put a single chunk using xid
	chunk_loc.assign("/home/ruilingz/picoquic/testpath/");  // pass to test use client's customized path
	if( putchunk(test_xid, chunk_loc, myaddr,serveraddr,conf) <0) {
		printf("Error: failed to put testchunk");
		return retval;
	}
	
	//4. getchunk  --PASS
	//client will pass chunkxid, serverdag, location to store the receiving chunk
	//using a new session quic
/*	recv_loc.assign("/home/ruilingz/picoquic/testpath_recv/");
	if( getchunk(test_xid, recv_loc, myaddr, serveraddr,conf) <0) {
			printf ("Error: failed to get testchunk");
			return retval;
			}	
			*/
		// Everything went well, so return success
		
		retval = 0;
	

	return retval;
	
}
