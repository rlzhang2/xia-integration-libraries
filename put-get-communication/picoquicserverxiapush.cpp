#include "localconfig.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
extern "C" {
#include "picoquic.h"
#include "picosocks.h"
#include "util.h"
};
#include "../contentchunk-lib/chunkapi.h"
#include "../xia-api-lib/xiaapi.hpp"
#include "dagaddr.hpp"
#include "../contentchunk-lib/get_putChunkapi.h"

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"

#define CONFFILE "./conf/local.conf"
#define SERVER_AID "SERVER_AID"
#define IFNAME "IFNAME"
#define CONTROL_PORT "8295"
#define CONTROL_IP "172.64.0.21"
#define WORKDIR "WORKDIR"

void print_address(struct sockaddr* address, char* label)
{
	char hostname[256];
	if(address->sa_family == AF_XIA) {
		sockaddr_x* addr = (sockaddr_x*) address;
		Graph dag(addr);
		std::cout << std::string(label) << " "
			<< dag.dag_string() << std::endl;
	} else {
		std::cout << "Invalid address - expected XIA" << std::endl;
	}
	return;
}

//Check to assign requested xid from PUSH to context for validation
int setContextXID(picoquic_cnx_t* connection, callback_context_t* context, uint8_t* bytes, size_t length, string proc_type)
{
	int ret = -1;

	//check streaming putdata from Client
	char temp_data[length];
        memcpy(temp_data, bytes, length);
	//printf("ServerCallback: Client sent putData: \n %s %zu\n", temp_data, length);

        //separate prefix XID type from content chunkdata; context->xid capture all xids
        string sXidData(temp_data);

        string sXid= (sXidData.find("NCID:") != string::npos) ? sXidData.substr(0,44+1) : sXidData.substr(0,44);
        context->xid.push_back(sXid);
	std::cout<<"Context xid size: "<< context->xid.size() <<" tmpData size: "<<sizeof(temp_data) <<" length: "<<length<<endl;

	//release mem
	memset(temp_data, 0, sizeof(temp_data));

        if (store_chunk(connection, context,bytes, length, sXid, proc_type) ==0){
                 printf("PUT data stored!!!\n");
		 ret =0;
        }
	return ret;
}

static int server_callback(picoquic_cnx_t* connection,
		uint64_t stream_id, uint8_t* bytes, size_t length,
		picoquic_call_back_event_t event, void* ctx)
{
	printf("ServerCallback: stream: %lu, len: %zu, event: %d\n",
			stream_id, length, event);
	callback_context_t* context = (callback_context_t*)ctx;
	std::string proc_type ="PUT";

	switch(event) {
		case picoquic_callback_ready:
			printf("ServerCallback: Ready\n");
			break;
		case picoquic_callback_almost_ready:
			printf("ServerCallback: AlmostReady\n");
			break;
		// Handle the connection related events
		case picoquic_callback_close:
			printf("ServerCallback: Close\n");
		case picoquic_callback_application_close:
			printf("ServerCallback: ApplicationClose\n");
		case picoquic_callback_stateless_reset:
			printf("ServerCallback: StatelessReset\n");
			if(context != NULL) {
				// Free the context memory and set it NULL for callback
				free(context);
				picoquic_set_callback(connection, server_callback, NULL);
				printf("ServerCallback: need to free context\n");
			}
			return 0;

		// Handle the stream related events
		case picoquic_callback_prepare_to_send:
			// Unexpected call
			printf("ServerCallback: PrepareToSend\n");
			return -1;
		case picoquic_callback_stop_sending:
			printf("ServerCallback: StopSending: resetting stream\n");
			picoquic_reset_stream(connection, stream_id, 0);
			return 0;
		case picoquic_callback_stream_reset:
			printf("ServerCallback: StreamReset: resetting stream\n");
			picoquic_reset_stream(connection, stream_id, 0);
			return 0;
		case picoquic_callback_stream_gap:
			printf("ServerCallback: StreamGap\n");
			// This is not supported by picoquic yet
			picoquic_reset_stream(connection, stream_id,
					PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
			return 0;
		case picoquic_callback_stream_data:
			printf("ServerCallback: StreamData\n");
			 if(context && (length > 0)) {
				context->received_so_far += length;
				setContextXID(connection,context, bytes, length, proc_type);
			 }
		case picoquic_callback_stream_fin:
			printf("ServerCallback: StreamFin\n");
			if(event == picoquic_callback_stream_fin && length == 0) {
				printf("ServerCallback: StreamFin - resetting!\n");
				picoquic_reset_stream(connection, stream_id,
						PICOQUIC_TRANSPORT_STREAM_STATE_ERROR);
				return 0;
			}
			// If there's no context, create one
			if(!context) {
				printf("ServerCallback: creating a new context for stream\n");
				callback_context_t *new_context = (callback_context_t*)malloc(
						sizeof(callback_context_t));
				if(new_context) {
					memset(new_context, 0, sizeof(callback_context_t));
				} else {
					printf("ERROR creating context in callback\n");
					picoquic_close(connection, PICOQUIC_ERROR_MEMORY);
					return 0;
				}
				// Assign the context to this callback for future triggers
				picoquic_set_callback(connection, server_callback,
						new_context);
				context = new_context;
				if(length > 0) {
					context->received_so_far += length;
                                	setContextXID(connection,context, bytes, length, proc_type);
				}
			}
			if(event != picoquic_callback_stream_data) {
				
				if (context) {	
			       //pull Client ack response after processing stream data from Client
				char rdata[length+1];
                        	memcpy(rdata, bytes, length);
                        	rdata[length] = 0;
                        	std::string ClientAck(rdata);
                        	cout<<"ServerCallback: Client ACK after completed stream: "<< ClientAck.c_str()<<endl;
				}
				printf("ServerCallback: Client sent %d bytes before ending\n",
						context->received_so_far);
			}
			break;
	};
	return 0;
}

int main()
{
	int retval = -1;
	int state = 0;
	FILE* logfile = NULL;
	uint64_t current_time;
	picoquic_quic_t* server = NULL;
	int64_t delay_max = 10000000;      // max wait 10 sec.
	sockaddr_x addr_from;
	sockaddr_x addr_local;
	unsigned long to_interface = 0;    // our interface
	uint8_t buffer[1536];              // buffer to receive packets
	int bytes_recv;                    // size of packet received
	picoquic_cnx_t* connections = NULL;
	picoquic_cnx_t* next_connection = NULL;
	uint8_t send_buffer[2000];
	size_t send_length = 0;
	unsigned char received_ecn;

	addr_info_t myaddr;
	LocalConfig conf;
	conf.control_addr = CONTROL_IP;
	conf.control_port = CONTROL_PORT;
	addr_info_t peer_addr;
	if(conf.configure(CONTROL_PORT, CONTROL_IP, myaddr, peer_addr) < 0)
	{
		goto server_done;
	}	
	state = 1; // server socket now exists
	printf("Check server socket fd: %d\n", myaddr.sockfd);

	// Get the server certificate
	char server_cert_file[512];
	if(picoquic_get_input_path(server_cert_file, sizeof(server_cert_file),
				NULL, SERVER_CERT_FILE)) {
		printf("ERROR finding server certificate\n");
		goto server_done;
	}

	// Get the server crypto key
	char server_key_file[512];
	if(picoquic_get_input_path(server_key_file, sizeof(server_key_file),
				NULL, SERVER_KEY_FILE)) {
		printf("ERROR finding server key file\n");
		goto server_done;
	}

	// Create QUIC instance
	current_time = picoquic_current_time();
	server = picoquic_create(8, // number of connections
			server_cert_file,
			server_key_file,
			NULL,                // cert_root_file_name
			NULL,                // Appl. Layer Protocol Negotiation (ALPN)
			server_callback,     // Stream data callback
			NULL,                // Stream data context - assigned in callback
			NULL, // Connection ID callback
			NULL,                // Connection ID callback context
			NULL,                // reset seed
			current_time,
			NULL,                // p_simulated_time
			NULL,                // ticket_file_name
			NULL,                // ticket_encryption_key
			0                    // ticket encryption key length
			);
	if(server == NULL) {
		printf("ERROR creating QUIC instance for server\n");
		goto server_done;
	}
	state = 2;

	// Open a log file
	logfile = fopen("server.log", "w");
	if(logfile == NULL) {
		printf("ERROR creating log file\n");
		goto server_done;
	}
	state = 3;
	PICOQUIC_SET_LOG(server, logfile);

	// Wait for packets
	while(1) {
		int64_t delta_t = picoquic_get_next_wake_delay(server, current_time,
				delay_max);

		printf("Going into select\n");
		bytes_recv = picoquic_xia_select(myaddr.sockfd, &addr_from,
				&addr_local, buffer, sizeof(buffer),
				delta_t,
				&current_time);
		if(bytes_recv < 0) {
			printf("Server: ERROR selecting on client requests\n");
			goto server_done;
		}

		uint64_t loop_time;
		if(bytes_recv > 0) {
			// Process the incoming packet via QUIC server
			printf("Server: got %d bytes from client\n", bytes_recv);
			(void)picoquic_incoming_packet(server, buffer,
					(size_t)bytes_recv, (struct sockaddr*)&addr_from,
					(struct sockaddr*)&addr_local, to_interface,
					received_ecn,
					current_time);
			
			printf("Server: processed incoming packet through QUIC\n");
			char label[] = "Server: client addr:";
			print_address((struct sockaddr*)&addr_from, label);
			char label2[] = "Server: server addr:";
			print_address((struct sockaddr*)&addr_local, label2);

			// If we don't have a list of server connections, get it
			if(connections==NULL
					|| connections!=picoquic_get_first_cnx(server)) {
				printf("Server: New connection\n");
				connections = picoquic_get_first_cnx(server);
				if(connections == NULL) {
					printf("ERROR: No connection found!\n");
					goto server_done;
				}
				printf("Server: Connection established. Connection state = %d\n",
						picoquic_get_cnx_state(connections));
                printf("\n%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_initial_cnxid(connections)));

			}
		}
		loop_time = current_time;

		// Send stateless packets
		picoquic_stateless_packet_t* sp;
		while((sp = picoquic_dequeue_stateless_packet(server)) != NULL) {
			printf("Server: found a stateless packet to send\n");
			if(sp->addr_to.sx_family != AF_XIA) {
				std::cout << "ERROR: Non XIA stateless packet" << std::endl;
				break;
			}
			// send out any outstanding stateless packets
			printf("Server: sending stateless packet out on network\n");
			picoquic_xia_sendmsg(myaddr.sockfd, sp->bytes, sp->length,
					&sp->addr_to, &sp->addr_local, conf);
			picoquic_delete_stateless_packet(sp);
		}

		// ms outgoing packets for all connections
		while((next_connection = picoquic_get_earliest_cnx_to_wake(server,
					loop_time)) != NULL) {
			sockaddr_x peer_addr;
			sockaddr_x local_addr;
			int peer_addr_len = sizeof(sockaddr_x);
			int local_addr_len = sizeof(sockaddr_x);

			// Ask QUIC to prepare a packet to send out on this connection
			//
			// TODO: HACK!!! peer and local addr pointers sent as
			// sockaddr_storage so underlying code won't complain.
			// Fix would require changes to picoquic which we want to avoid

			int rc = picoquic_prepare_packet(next_connection, current_time,
					send_buffer, sizeof(send_buffer), &send_length,
					(struct sockaddr_storage*) &peer_addr, &peer_addr_len,
					(struct sockaddr_storage*) &local_addr, &local_addr_len);
			if(rc == PICOQUIC_ERROR_DISCONNECTED) {
				// Connections list is empty, if this was the last connection
				if(next_connection == connections) {
					connections = NULL;
				}
				printf("Server: Disconnected!\n");
				picoquic_delete_cnx(next_connection);
				// All connections ended, break out of outgoing packets loop
				break;
			}
			if(rc == 0) {
				if(send_length > 0) {
					printf("Server: sending %ld byte packet\n", send_length);
					(void)picoquic_xia_sendmsg(myaddr.sockfd,
							send_buffer, send_length,
							&peer_addr, &local_addr, conf);
				}
			} else {
				printf("Server: Exiting outgoing pkts loop. rc=%d\n", rc);
				break;
			}
		}
	}
	// Server ended cleanly, change return code to success
	retval = 0;

server_done:
	switch(state) {
		case 3: // close the log file
			fclose(logfile);
		case 2: // cleanup QUIC instance
			picoquic_free(server);
		case 1: // cleanup server sockets
			if(myaddr.sockfd != -1) {
				close(myaddr.sockfd);
			}
	};
	return retval;
}
