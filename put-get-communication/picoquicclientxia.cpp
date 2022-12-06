 #include "localconfig.hpp"
// XIA support
#include "../xia-api-lib/xiaapi.hpp"
#include "dagaddr.hpp"

// C++ includes
#include <iostream>

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

// If there were multiple streams, we would track progress for them here
struct callback_context_t {
	int connected;
	int stream_open;
	int received_so_far;
	uint64_t last_interaction_time;
};

//picoquic_stream_data_cb_fn
int client_callback(picoquic_cnx_t* cnx,
		uint64_t stream_id, uint8_t*bytes, size_t length,
		picoquic_call_back_event_t event, void *callback_context)
{
	printf("Client callback\n");

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
				char data[256];
				memcpy(data, (char*)bytes, length);
				data[length] = 0;
				printf("Server sent: %s\n", data);
				context->received_so_far += length;
			}
			break;
		case picoquic_callback_stream_fin:
			printf("Callback: stream finished\n");
			if(length > 0) {
				char data[256];
				memcpy(data, (char*)bytes, length);
				data[length] = 0;
				printf("Server sent: %s\n", data);
				context->received_so_far += length;
			}
			context->stream_open = 0;
			printf("Reception completed after %d bytes.\n",
					context->received_so_far);
			printf("Resetting the stream after it finished.\n");
			picoquic_reset_stream(cnx, stream_id, 0);
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

	uint64_t stream_id = 0;
	char data[] = "Hello world!";
	context->stream_open = 1;
	context->connected = 1;

	// Queue up a "Hello world!" to be sent to the server
	printf("Sending %ld bytes of data on stream\n", sizeof(data));
	if(picoquic_add_to_stream(connection,
				stream_id, // Any arbitrary stream ID client picks
				(uint8_t*)data, sizeof(data), // data to be sent
				1)) { // finished; would be 0 if interacting more with server
		printf("ERROR: sending hello on stream\n");
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
	uint8_t buffer[1536];
	int bytes_recv;
	int64_t delta_t = 0;
	//int notified_ready = 0;
	int established = 0;
	unsigned char received_ecn;
	uint64_t current_time;
	int zero_rtt_available = 0; // Flag set to 1 if 0RTT is available

	// Outgoing packet buffer
	uint8_t send_buffer[1536];
	size_t send_length = 0;

	// read local config
	
	//server
	// sockaddr_x server_address;
	// std::string serverdagstr = SERVER_ADDR + " " + SERVER_AID;
	// Graph serverdag(serverdagstr);
	// serverdag.fill_sockaddr(&server_address);
	// int server_addrlen = sizeof(sockaddr_x);

	// 
	LocalConfig conf;
	conf.control_addr = CONTROL_IP;
	conf.control_port = CONTROL_PORT;
	addr_info_t myaddr;
	addr_info_t serveraddr;
	std::string ticket_store_filename;
	if(conf.configure(CONTROL_PORT, CONTROL_IP, myaddr, serveraddr) < 0)
	{
		goto client_done;
	}

	// Server address  - keeping that fixed
	// auto server_addr = conf.get_their_addr();
	// auto server_aid = conf.get_server_aid();
	// int server_addrlen;

	// auto conf = LocalConfig::get_instance(CONFFILE);
	// auto server_addr = conf.get(THEIR_ADDR);
	// auto server_aid = conf.get(SERVER_AID);
	// auto client_aid = conf.get(CLIENT_AID);
	// std::string client_ifname = conf.get(IFNAME);
	ticket_store_filename = TICKET_STORE; //conf.get_ticket_store();

	// // QUIC client
	picoquic_quic_t *client;

	// Callback context
	struct callback_context_t callback_context;
	memset(&callback_context, 0, sizeof(struct callback_context_t));

	// // A socket to talk to server on
	// //sockfd = socket(server_address.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	// // bind to socket and fill my addr
	// sockfd = picoquic_xia_open_server_socket(client_aid.c_str(), mydag, client_ifname);
	// if(sockfd == INVALID_SOCKET) {
	// 	goto client_done;
	// }
	// std::cout << "CLIENTADDR: " << mydag->dag_string().c_str() << std::endl;
	// mydag->fill_sockaddr(&my_address);
	// my_addrlen = sizeof(sockaddr_x);
	// printf("Created socket to talk to server\n");
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
			(struct sockaddr*) &serveraddr.addr, // Address to
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
		printf("Sent %d byte packet to server: %s) from me: %s\n", bytes_sent,
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
			printf("Got %d byte packet\n", bytes_recv);
			// TODO: it seems this function always returns 0
			if(picoquic_incoming_packet(client, buffer,
						(size_t)bytes_recv, (struct sockaddr*)&packet_from,
						(struct sockaddr*)&packet_to, if_index_to,
						received_ecn,
						current_time)) {
				printf("ERROR: processing incoming packet\n");
				delta_t = 0;
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
