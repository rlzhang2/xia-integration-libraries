#include <string.h> // memset
#include <stdio.h>

#include "picoquic.h" // picoquic_create, states, err, pkt types, contexts
//#include "picoquic_internal.h"
#include "picosocks.h" // picoquic_select and server socks functions
#include "util.h"

#define SERVER_PORT 4443
static const char *ticket_store_filename = "demo_ticket_store.bin";

// If there were multiple streams, we would track progress for them here
struct callback_context_t {
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

	struct callback_context_t *context = callback_context;
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

	// QUIC client
	picoquic_quic_t *client;

	// Callback context
	struct callback_context_t callback_context;
	memset(&callback_context, 0, sizeof(struct callback_context_t));

	// Server address
	struct sockaddr_storage server_address;
	int server_addrlen;
	int is_name;

	// Get the server's address
	if(picoquic_get_server_address("127.0.0.1", SERVER_PORT,
				&server_address, &server_addrlen, &is_name)) {
		printf("ERROR: getting server address\n");
		goto client_done;
	}
	printf("Got server address of size %d\n", server_addrlen);
	printf("Server addr type: %s\n",
			(server_address.ss_family == AF_INET) ? "AF_INET" : "AF_INET6");

	// A socket to talk to server on
	int sockfd = socket(server_address.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if(sockfd == INVALID_SOCKET) {
		goto client_done;
	}
	printf("Created socket to talk to server\n");
	state = 1; // socket created

	// Tell Linux to return PKTINFO - address information
	if(server_address.ss_family == AF_INET6) {
		int val = 1;
		if(setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val))){
			printf("ERROR: setting IPV6_ONLY option\n");
			goto client_done;
		}
		val = 1;
		if(setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO,(char*)&val,
					sizeof(int))) {
			printf("ERROR: setting IPV6_RECVPKTINFO option\n");
			goto client_done;
		}
	} else { // IPv4
		int val = 1;
#ifdef IP_PKTINFO
		if(setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO,
					(char*)&val, sizeof(int))) {
			printf("ERROR: setting IP_PKTINFO option\n");
			goto client_done;
		}
#else
		// IP_PKTINFO is not defined on BSD
		if(setsockopt(sockfd, IPPROTO_IP, IP_RECVDSTADDR,
					(char*)&val, sizeof(int))) {
			printf("ERROR: setting IP_RECVDSTADDR option\n");
			goto client_done;
		}
#endif
	}

	// Create QUIC context for client
	uint64_t current_time = picoquic_current_time();
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
			ticket_store_filename,          // ticket_file_name
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
			(struct sockaddr*) &server_address, // Address to
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
	int zero_rtt_available = 0; // Flag set to 1 if 0RTT available
	if(picoquic_is_0rtt_available(connection)) {
		start_stream(connection, &callback_context);
		zero_rtt_available = 1;
	}
	printf("Zero RTT available: %d\n", zero_rtt_available);

	// Send a packet to get the connection establishment started
	uint8_t send_buffer[1536];
	size_t send_length = 0;
	if(picoquic_prepare_packet(connection, current_time,
				send_buffer, sizeof(send_buffer), &send_length,
				NULL, NULL,    // Address to
				NULL, NULL)) { // Address from
		printf("ERROR: preparing a QUIC packet to send\n");
		goto client_done;
	}
	printf("Prepared packet of size %zu\n", send_length);
	int bytes_sent;
	if(send_length > 0) {
		bytes_sent = sendto(sockfd, send_buffer, (int)send_length, 0,
				(struct sockaddr*)&server_address, server_addrlen);
		if(bytes_sent < 0) {
			printf("ERROR: sending packet to server\n");
			goto client_done;
		}
		printf("Sent %d byte packet to server\n", bytes_sent);
	}

	// Wait for incoming packets
	int64_t delay_max = 10000000;
	struct sockaddr_storage packet_from;
	struct sockaddr_storage packet_to;
	socklen_t from_length;
	socklen_t to_length;
	unsigned long if_index_to;
	uint8_t buffer[1536];
	int bytes_recv;
	int64_t delta_t = 0;
	//int notified_ready = 0;
	int established = 0;
	unsigned char received_ecn;
	while(picoquic_get_cnx_state(connection) != picoquic_state_disconnected) {

		delay_max = 10000000;

		// Wait until data or timeout
		from_length = sizeof(struct sockaddr_storage);
		to_length = sizeof(struct sockaddr_storage);
		bytes_recv = picoquic_select(&sockfd, // list of sockets
				1, // number of sockets
				&packet_from, &from_length,
				&packet_to, &to_length,
				&if_index_to,           // to interface
				&received_ecn,
				buffer, sizeof(buffer), // packet contents, if received
				delta_t,                // timeout, initially 0: block
				&current_time);         // updated current time

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
			if(!callback_context.stream_open) {
				printf("The stream was not open, close connection\n");
				picoquic_close(connection, 0);
				connection = NULL;
				break;
			}

			// Waited too long. Close connection
			if(current_time > callback_context.last_interaction_time
					&& current_time - callback_context.last_interaction_time
					    > 10000000ull) {
				printf("No progress for 10 seconds. Closing\n");
				picoquic_close(connection, 0);
				connection = NULL;
				break;
				//goto client_done;
			}
		}

		// We get here whether there was a packet or a timeout
		send_length = PICOQUIC_MAX_PACKET_SIZE;
		while(send_length > 0) {
			// Send out all packets waiting to go
		if(picoquic_prepare_packet(connection, current_time,
					send_buffer, sizeof(send_buffer), &send_length,
					NULL, NULL, NULL, NULL)) {
			printf("ERROR sending QUIC packet\n");
			goto client_done;
		}
		if(send_length > 0) {
			printf("Sending packet of size %ld\n", send_length);
			//printf("Sending a packet of size %d\n", (int)send_length);
			bytes_sent = sendto(sockfd, send_buffer, (int)send_length, 0,
					(struct sockaddr*)&server_address, server_addrlen);
			if(bytes_sent <= 0) {
				printf("ERROR sending packet to server\n");
			}
		}
		}

		// How long before we timeout waiting for more packets
		delta_t = picoquic_get_next_wake_delay(client, current_time,
				delay_max);

	}
	// Save tickets from server, so we can join quickly next time
	if(picoquic_save_tickets(client->p_first_ticket, current_time,
				ticket_store_filename) != 0) {
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
			close(sockfd);
	};

	return retval;
}
