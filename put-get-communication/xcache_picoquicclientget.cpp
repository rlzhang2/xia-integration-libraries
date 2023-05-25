 #include "localconfig.hpp"
// XIA support
#include "../xia-api-lib/xiaapi.hpp"
#include "dagaddr.hpp"
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
#define TICKET_STORE "TICKET_STORE"
#define IFNAME "IFNAME"
#define CONTROL_PORT "8295"
#define CONTROL_IP "172.64.0.31"
#define TEST_CID "TEST_CID"
#define XCACHE_AID "XCACHE_AID"


// If there were multiple streams, we would track progress for them here
/*struct callback_context_t {
	int connected;
	int stream_open;
	int received_so_far;
	uint64_t last_interaction_time;
}; */

//picoquic_stream_data_cb_fn
int client_callback(picoquic_cnx_t* cnx,
		uint64_t stream_id, uint8_t*bytes, size_t length,
		picoquic_call_back_event_t event, void *callback_context)
{
	printf("Client callback\n");

	std::cout<<" Stream ID: " <<stream_id <<" Length: "<<length <<std::endl;

	struct callback_context_t *context =
		(struct callback_context_t*)callback_context;

	context->last_interaction_time = picoquic_current_time();

	switch(event) {
		case picoquic_callback_ready:
			printf("Callback: ready\n");
			break;
		case picoquic_callback_almost_ready:
			printf("Callback: almost_ready\n");
			break;
		case picoquic_callback_close:
			printf("Callback: close\n");
		case picoquic_callback_application_close:
			printf("Callback: application close\n");
		case picoquic_callback_stateless_reset:
			printf("Callback: stateless reset\n");
			context->stream_open = 0;
			return 0;
		case picoquic_callback_stream_reset:
			printf("Callback: stream reset\n");
		case picoquic_callback_stop_sending:
			printf("Callback: stop_sending\n");
			picoquic_reset_stream(cnx, stream_id, 0);
			context->stream_open = 0;
			return 0;
		case picoquic_callback_stream_gap:
			printf("Callback: stream gap\n");
			picoquic_reset_stream(cnx, stream_id,
					PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
			context->stream_open = 0;
			return 0;
		case picoquic_callback_stream_data:
			printf("Callback: no event\n");
			if(length > 0) {
				char data[2048];
				memcpy(data, (char*)bytes, length);
				data[length] = 0;
				printf("Server sent: %s\n", data);
				context->received_so_far += length;
			}
			break;
		case picoquic_callback_stream_fin:
			printf("Callback: stream finished\n");
			if(length > 0) {
				char data[2048];
				memcpy(data, (char*)bytes, length);
				data[length] = 0;
				printf("Server sent: %s\n", data);
				context->received_so_far += length;
			}
			//context->stream_open = 0;
			printf("Reception completed after %d bytes.\n",
					context->received_so_far);
			printf("Resetting the stream after it finished.\n");
			//picoquic_reset_stream(cnx, stream_id, 0);
			/*
			// Closing connection immediately
			printf("Closing connection after stream ended\n");
			picoquic_close(cnx, 0);
			*/
			break;
		default:
			printf("ERROR: unknown callback event %d\n", event);
	};
	return 0;
}

void start_stream(picoquic_cnx_t* connection,
		struct callback_context_t* context)
{
	printf("Starting a stream\n");

	auto conf = LocalConfig(CONFFILE);
  	auto test_cid = conf.get(TEST_CID);

	uint64_t stream_id = 0;
        context->stream_open = 1;
        context->connected = 1;

    	char data[strlen(test_cid.c_str())];
	strcpy(data, test_cid.c_str());
	printf("Sending %ld CID string  on stream\n", sizeof(data));
        if(picoquic_add_to_stream(connection,
                                stream_id, // Any arbitrary stream ID client picks
                                (uint8_t*)data, sizeof(data), // data to be sent
                                1)) { // finished; would be 0 if interacting more with server
                printf("ERROR: sending CID to stream\n");
        }
}

int main()
{
	// cleanup state
	int state = 0;
	int retval = -1;
	FILE* logfile = NULL;

	// Event loop parameters
	int64_t delay_max = 10000000;
	sockaddr_x packet_from;
	sockaddr_x packet_to;
	unsigned long if_index_to = 0;
	uint8_t buffer[2048];
	int bytes_recv;
	int64_t delta_t = 0;
	//int notified_ready = 0;
	int established = 0;
	unsigned char received_ecn;
	uint64_t current_time;
	int zero_rtt_available = 0; // Flag set to 1 if 0RTT is available
	std::string procType("GET");

	// Outgoing packet buffer
	uint8_t send_buffer[2048];
	size_t send_length = 0;
	
	auto conf = LocalConfig(CONFFILE);
        conf.control_addr = CONTROL_IP;
        conf.control_port = CONTROL_PORT;
        auto test_cid = conf.get(TEST_CID);
	auto xcache_aid = conf.get(XCACHE_AID);

	addr_info_t myaddr;
	addr_info_t serveraddr;
	std::string ticket_store_filename;
	struct callback_context_t callback_context;
	if(conf.configure(CONTROL_PORT, CONTROL_IP, myaddr, serveraddr) < 0)
	{
		goto client_done;
	}

	std::cout << "CLIENTADDR: " << myaddr.dag->dag_string().c_str() << std::endl;
	std::cout << "SERVERADDR: " << serveraddr.dag->dag_string().c_str() << std::endl;

	//updated serverdag with testCID
	conf.update_serveraddr(conf, conf.get_our_addr() + " " + xcache_aid + " " + test_cid);
        std::cout<<"SERVER ADDR after updated: " <<serveraddr.dag->dag_string().c_str()<<std::endl;

	ticket_store_filename = TICKET_STORE; //conf.get_ticket_store();

	// // QUIC client
	picoquic_quic_t *client;

	// Callback context
	memset(&callback_context, 0, sizeof(struct callback_context_t));

	state = 1; // socket created

	// Create QUIC context for client
	current_time = picoquic_current_time();
	callback_context.last_interaction_time = current_time;
	client = picoquic_create(
			8,             // number of connections
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
			ticket_store_filename.c_str(),          // ticket_file_name
			NULL,          // ticket_encryption_key
			0              // ticket encryption key length
			);

	if(client == NULL) {
		printf("ERROR: creating client\n");
		goto client_done;
	}
	printf("Created QUIC context\n");
	state = 2; // picoquic context created for client

	// Open a log file for writing
	logfile = fopen("client.log", "w");
	if(logfile == NULL) {
		printf("ERROR opening log file\n");
		goto client_done;
	}
	PICOQUIC_SET_LOG(client, logfile);
	state = 3; // logfile needs to be closed

	// We didn't provide a root cert, so set verifier to null
	picoquic_set_null_verifier(client);

	// Create a connection in QUIC
	picoquic_cnx_t *connection;
	connection = picoquic_create_cnx(
			client, // QUIC context
			picoquic_null_connection_id,        // initial connection ID
			picoquic_null_connection_id,        // remote_connection ID
			(struct sockaddr*) &serveraddr.addr, // Address to (struct sockaddr*) &serveraddr.addr,
			current_time,   // start time
			0,              // preferred version
			"localhost",    // Server name identifier
			"hq-17",        // ALPN
			1           	// client mode, set to 1, if on client side
			);
	if(connection == NULL) {
		printf("ERROR: creating client connection in QUIC\n");
		goto client_done;
	}
	printf("Created QUIC connection instance\n");
	state = 4;

	// Set a callback for the client connection
	// TODO: Can we just set the callback in picoquic_create?
	picoquic_set_callback(connection, client_callback, &callback_context);

	// Now connect to the server
	if(picoquic_start_client_cnx(connection)) {
		printf("ERROR: connecting to server\n");
		goto client_done;
	}
	printf("Started connection to server\n");

	// If 0RTT is available, start a stream
	if(picoquic_is_0rtt_available(connection)) {
		start_stream(connection, &callback_context);
		zero_rtt_available = 1;
	}
	printf("Zero RTT available: %d\n", zero_rtt_available);

	pthread_mutex_lock(&conf.lock);
	// Send a packet to get the connection establishment started
	if(picoquic_prepare_packet(connection, current_time,
				send_buffer, sizeof(send_buffer), &send_length,
				(struct sockaddr_storage*)&serveraddr.addr, &serveraddr.addrlen,
				(struct sockaddr_storage*)&myaddr.addr, &myaddr.addrlen)) {
		printf("ERROR: preparing a QUIC packet to send\n");
		pthread_mutex_unlock(&conf.lock);
		goto client_done;
	}
	printf("Prepared packet of size %zu\n", send_length);
	myaddr.dag->fill_sockaddr(&myaddr.addr);
	int bytes_sent;
	if(send_length > 0) {
		bytes_sent = picoquic_xia_sendmsg(myaddr.sockfd, send_buffer,
				(int) send_length, &serveraddr.addr, &myaddr.addr, conf);
		if(bytes_sent < 0) {
			printf("ERROR: sending packet to server\n");
			goto client_done;
		}
		printf("Sent %d byte packet to server: %s\n  from me: %s\n", bytes_sent,
		 serveraddr.dag->dag_string().c_str(), myaddr.dag->dag_string().c_str());
	}
	pthread_mutex_unlock(&conf.lock);

	// Wait for incoming packets
	while(picoquic_get_cnx_state(connection) != picoquic_state_disconnected) {

		delay_max = 10000000;

		// Wait until data or timeout
		bytes_recv = picoquic_xia_select(myaddr.sockfd, &packet_from,
				&packet_to, buffer, sizeof(buffer),
				delta_t,
				&current_time);

		// Exit on error
		if(bytes_recv < 0) {
			printf("ERROR: receiving packet after select\n");
			goto client_done;
		}

		// Get the connection state
		picoquic_state_enum cnx_state = picoquic_get_cnx_state(connection);
		printf("Connection state: %d\n", cnx_state);

		// We have a packet to process
		if(bytes_recv > 0) {
			//Check the packet Addresses receiving
			// TODO: it seems this function always returns 0
			if(picoquic_incoming_packet(client, buffer,
						(size_t)bytes_recv, (struct sockaddr*)&packet_from,
						(struct sockaddr*)&packet_to, if_index_to,
						received_ecn,
						current_time)) {
				printf("ERROR: processing incoming packet\n");
				delta_t = 0;
			} else { //store received content data locally
				Graph p_from(&packet_from);
                        	Graph p_to(&packet_to);
                        	std::cout<<"Packet fromAddr: "<<p_from.dag_string()<<std::endl;
                        	std::cout<<"Packet toAddr: "<<p_to.dag_string()<<std::endl;
                        	
				//std::string str = reinterpret_cast<char *>(buffer);
				//std::cout<<"Data length" <<bytes_recv<<" str len: "<<str.size()<<endl;
				store_chunk(connection, &callback_context, buffer, bytes_recv, test_cid.c_str(), procType);
			}
			delta_t = 0;
		}

		// Timed out. Check if connection established or stream ended
		if(bytes_recv == 0) {
			if(cnx_state == picoquic_state_ready
					|| cnx_state == picoquic_state_client_ready_start) {

				// The connection is ready. Start a stream.
				if(!established) {
					printf("Connected! ver: %x, I-CID: %llx\n",
							picoquic_supported_versions[
							connection->version_index].version,
							(unsigned long long)picoquic_val64_connection_id(
								picoquic_get_logging_cnxid(connection)));
					if(!zero_rtt_available) {
						printf("zero rtt was not available, starting stream\n");
						start_stream(connection, &callback_context);
					}
					established = 1;
				}
			}

		// If the stream has been closed, we close the connection
			if(callback_context.connected && !callback_context.stream_open) {
				printf("The stream was not open, close connection\n");
				picoquic_close(connection, 0);
				connection = NULL;
				break;
			}

			// Waited too long. Close connection
			if(current_time > callback_context.last_interaction_time
					&& current_time - callback_context.last_interaction_time
					    > 60000000ull) {
				printf("No progress for 60 seconds. Closing\n");
				picoquic_close(connection, 0);
				connection = NULL;
				break;
				//goto client_done;
			}
		}

		// We get here whether there was a packet or a timeout
		send_length = PICOQUIC_MAX_PACKET_SIZE;
		while(send_length > 0) {
			//sleep(5); // add a delay make sure the configuration updates
			// Send out all packets waiting to go
			pthread_mutex_lock(&conf.lock);
			if(picoquic_prepare_packet(connection, current_time,
						send_buffer, sizeof(send_buffer), &send_length,
						NULL, NULL, NULL, NULL)) {
				printf("ERROR sending QUIC packet\n");
				pthread_mutex_unlock(&conf.lock);
				goto client_done;
			}
			if(send_length > 0) {
				printf("Sending packet of size %ld\n", send_length);
				bytes_sent = picoquic_xia_sendmsg(myaddr.sockfd, send_buffer,
						(int) send_length, &serveraddr.addr, &myaddr.addr, conf);
				//printf("Sending a packet of size %d\n", (int)send_length);
				if(bytes_sent <= 0) {
					printf("ERROR sending packet to server\n");
				}
				printf("Sent %d byte packet to server: %s) from me: %s\n", bytes_sent, 
					serveraddr.dag->dag_string().c_str(), myaddr.dag->dag_string().c_str());
			}
			pthread_mutex_unlock(&conf.lock);
		}

		// How long before we timeout waiting for more packets
		delta_t = picoquic_get_next_wake_delay(client, current_time,
				delay_max);

	}
	// Save tickets from server, so we can join quickly next time
	if(picoquic_save_tickets(client->p_first_ticket, current_time,
				ticket_store_filename.c_str()) != 0) {
		printf("ERROR saving session tickets\n");
	}
	// Everything went well, so return success
	retval = 0;

client_done:
	switch(state) {
		case 4:
			if(connection) {
				picoquic_close(connection, 0); // 0 = reason code
			}
		case 3:
			fclose(logfile);
			// fallthrough
		case 2:
			picoquic_free(client);
			// fallthrough
		case 1:
			// TODO: Need to unregister this socket and AID at router
			close(myaddr.sockfd);
	};

	return retval;
}
