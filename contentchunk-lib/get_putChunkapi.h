#ifndef _get_putChunkapi_h
#define _get_putChunkapi_h

// XIA Helper definitions
#include "localconfig.hpp" // Read config file local.conf

// C++ includes
#include <iostream>
#include <fstream>

// C includes
#include <string.h> // memset
#include <stdio.h>
#include <vector>

extern "C" {
#include "picoquic.h" // picoquic_create, states, err, pkt types, contexts
//#include "picoquic_internal.h"
#include "picosocks.h" // picoquic_select and server socks functions
#include "util.h"
};

#define TEST_CHUNK_SIZE 300

//get_chunk_data: transfer data from source to destination on quic connection
//put_chunk: add the requested xids and data to stream tied to the  quic connection
//store_chunk: load chunk content on local storage
//ack_response:  sending ACK after completed streaming data

// If there were multiple streams, we would track progress for them here
struct callback_context_t {
        int connected;
        int stream_open;
        int received_so_far;
        uint64_t last_interaction_time;
	std::vector<uint8_t> data;
   	size_t datalen;
    	size_t sent_offset;
	vector<string> xid;
};

void get_chunk_data (struct addr_info_t &test_from_addr, struct addr_info_t &test_to_addr, vector <string> xid_lst,
                        picoquic_quic_t *quic_client, struct callback_context_t callback_context, int state, 
			uint64_t current_time,std::string process_type, LocalConfig &conf);
void put_chunk(picoquic_cnx_t* connection,
                struct callback_context_t* context, int numOfxids, std::string process_type, vector <string> xid_lst);
int store_chunk(picoquic_cnx_t* cnx, struct callback_context_t* context,
        uint8_t* bytes, size_t length, std::string xid_requested, std::string process_type);
void ack_response(picoquic_cnx_t* connection, uint64_t stream_id, int resp_code, struct callback_context_t* context);

#endif // _get_putChunkapi_h
