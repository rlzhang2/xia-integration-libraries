#ifndef _picoquicclientxiapush_h
#define _picoquicclientxiapush_h

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
#define CHUNK_STORE "CHUNK_STORE"
#define IFNAME "IFNAME"
#define WORKDIR "WORKDIR"
#define TEST_CID "TEST_CID"
#define PUT_TYPE "PUT_TYPE"

using namespace std;

int cnx_handler (struct addr_info_t &test_from_addr, 
		 struct addr_info_t &test_to_addr, vector<string> xidlst, std::string chunk_loc, std::string proc_type,LocalConfig &conf) ;
int init_client(LocalConfig &conf, addr_info_t &myaddr, addr_info_t &serveraddr);
int putfile(std::string filename,uint32_t chunk_size, std::string cidtype, std::string chunk_loc, 
		addr_info_t &myaddr, addr_info_t &serveraddr, LocalConfig &conf);
int putchunk(std::string xid_str, std::string chunk_loc, addr_info_t &myaddr,addr_info_t &serveraddr,LocalConfig &conf);
int getchunk(std::string xid_str, std::string recv_loc, addr_info_t &myaddr,addr_info_t &serveraddr,LocalConfig &conf);

#endif // _picoquicclientxiapush_h
