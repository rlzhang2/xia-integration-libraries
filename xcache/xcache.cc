#include "localconfig.hpp"

#include <string>
#include <memory>
#include <atomic>
#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

extern "C" {
#include "picoquic.h"
#include "picosocks.h"
#include "util.h"
};
#include "quicxiasock.hpp"
#include "xiaapi.hpp"
#include "dagaddr.hpp"
#include "cid_header.h"
#include "xcache_quic.h"

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"

#define CONFFILE "xcache.local.conf"
#define XCACHE_AID "XCACHE_AID"
#define TEST_CID "TEST_CID"

#define TEST_CHUNK_SIZE 8192

using namespace std;

// Cleanup on interrupt
atomic<bool> stop(false);

void sigint_handler(int) {
	stop.store(true);
}


static int server_callback(picoquic_cnx_t* connection,
		uint64_t stream_id, uint8_t* bytes, size_t length,
		picoquic_call_back_event_t event, void* ctx);

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

typedef struct {
	int stream_open;     // Assuming just one stream for now
	int received_so_far; // Number of bytes received in that one stream
	vector<uint8_t> data;
	size_t datalen;
	size_t sent_offset;
	NodePtr xid;
} callback_context_t;

int buildDataToSend(callback_context_t* ctx, size_t datalen)
{
	ctx->data.reserve(datalen);
	for(int i=0; i<datalen; i++) {
		ctx->data.push_back(i % 256);
	}
	return 0;
}

static int sendData(picoquic_cnx_t* connection,
		uint64_t stream_id, callback_context_t* ctx)
{
	int rc;
	if (!ctx) {
		return -1;
	}
	if (ctx->data.size() == 0) {
		if (buildDataToSend(ctx, TEST_CHUNK_SIZE) ) {
			cout << "ERROR creating data buffer to send" << endl;
			return -1;
		}
		ctx->datalen = TEST_CHUNK_SIZE;
		ctx->sent_offset = 0;
	}

	if(ctx->sent_offset != 0) {
		return 0;
	}

	char* datacharstr = reinterpret_cast<char*> (ctx->data.data());
	string datastr(datacharstr, ctx->data.size());

	// Make a Content Header for given data
	auto chdr = make_unique<CIDHeader>(datastr, 0);
	cout << __FUNCTION__ << " Content size: " << chdr->content_len() << endl;
	string serialized_header = chdr->serialize();

	// Send the header size
	uint32_t header_len_nbo = htonl(serialized_header.size());
	if (picoquic_add_to_stream(connection, stream_id,
			(const uint8_t*) &header_len_nbo, sizeof(header_len_nbo), 0)) {
		cout << __FUNCTION__ << " ERROR sending hdr size" << endl;
		return -1;
	}
	cout << "Sent hdr size: " << serialized_header.size() << endl;
	cout << "in NBO: " << header_len_nbo << endl;

	// Send the header
	if (picoquic_add_to_stream(connection, stream_id,
			(const uint8_t*) serialized_header.c_str(),
			serialized_header.size(), 0)) {
		cout << __FUNCTION__ << " ERROR: sending header" << endl;
		return -1;
	}
	cout << "Sent header of size: " << serialized_header.size() << endl;

	// Send the data
	if (picoquic_add_to_stream(connection, stream_id,
			ctx->data.data(), ctx->datalen, 1)) {
		cout << "ERROR: queuing data to send. Returned " <<  rc << endl;
		return -1;
	}
	cout << "Sent data of size: " << ctx->datalen << endl;
	ctx->sent_offset = ctx->datalen;
}

int remove_context(picoquic_cnx_t* connection,
		callback_context_t* context) {
	if(context != NULL) {
		delete context;
		picoquic_set_callback(connection, server_callback, NULL);
		std::cout << "ServerCallback: freed context" << std::endl;
	}
	return 0;
}

int process_data(callback_context_t* context, uint8_t* bytes, size_t length)
{
	// Missing context
	if(!context) {
		cout << __FUNCTION__ << " ERROR missing context" << endl;
		return -1;
	}

	// No data to process
	if(length <= 0) {
		return 0;
	}
	string data((const char*)bytes, length);
	cout << __FUNCTION__ << " Client sent " << data.c_str() << endl;
	context->received_so_far += length;
}

static int server_callback(picoquic_cnx_t* connection,
		uint64_t stream_id, uint8_t* bytes, size_t length,
		picoquic_call_back_event_t event, void* ctx)
{
	cout << "ServerCallback: stream " << stream_id
		 << " len: " << length
		 << " event: " << event << endl;
	callback_context_t* context = (callback_context_t*)ctx;
	if(!context) {
		cout << __FUNCTION__ << " called without context." << endl;
		return -1;
	}

	switch(event) {
		case picoquic_callback_ready:
			cout << "ServerCallback: Ready" << endl;
			break;
		case picoquic_callback_almost_ready:
			cout << "ServerCallback: AlmostReady" << endl;
			break;
		// Handle the connection related events
		case picoquic_callback_close:
			cout << "ServerCallback: Close" << endl;
			return (remove_context(connection, context));
		case picoquic_callback_application_close:
			cout << "ServerCallback: ApplicationClose" << endl;
			return (remove_context(connection, context));
		case picoquic_callback_stateless_reset:
			cout << "ServerCallback: StatelessReset" << endl;
			return (remove_context(connection, context));
		// Handle the stream related events
		case picoquic_callback_prepare_to_send:
			// Unexpected call
			cout << "ServerCallback: PrepareToSend" << endl;
			return -1;
		case picoquic_callback_stop_sending:
			cout << "ServerCallback: StopSending: resetting stream" << endl;
			picoquic_reset_stream(connection, stream_id, 0);
			return 0;
		case picoquic_callback_stream_reset:
			cout << "ServerCallback: StreamReset: resetting stream" << endl;
			picoquic_reset_stream(connection, stream_id, 0);
			return 0;
		case picoquic_callback_stream_gap:
			cout << "ServerCallback: StreamGap" << endl;
			// This is not supported by picoquic yet
			picoquic_reset_stream(connection, stream_id,
					PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
			return 0;
		case picoquic_callback_stream_data:
			cout << "ServerCallback: StreamData" << endl;
			sendData(connection, stream_id, context);
			return(process_data(context, bytes, length));
		case picoquic_callback_stream_fin:
			cout << "ServerCallback: StreamFin" << endl;
			if(length == 0) {
				cout << "ServerCallback: StreamFin - resetting!" << endl;
				picoquic_reset_stream(connection, stream_id,
						PICOQUIC_TRANSPORT_STREAM_STATE_ERROR);
				return 0;
			}
			process_data(context, bytes, length);
			sendData(connection, stream_id, context);
			cout << "ServerCallback: StreamFin" << endl;
			cout << "ServerCallback: got " << context->received_so_far
				<< " bytes from client before ending" << endl;
			return 0;
	};
	return 0;
}

void installSIGINTHandler() {
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_handler = sigint_handler;
	sigfillset(&action.sa_mask);
	sigaction(SIGINT, &action, NULL);
}

int main()
{
	int retval = -1;

	installSIGINTHandler();

	// Get XIDs from local config file
	auto conf = LocalConfig::get_instance(CONFFILE);
	auto xcache_aid = conf.get(XCACHE_AID);
	auto test_cid = conf.get(TEST_CID);
	if (xcache_aid.size() == 0) {
		printf("ERROR: XCACHE_AID entry missing in %s\n", CONFFILE);
		return -1;
	}
	if (test_cid.size() == 0) {
		printf("ERROR: TEST_CID entry missing in %s\n", CONFFILE);
		return -1;
	}
	
	// We give a fictitious AID for now, and get a dag in my_addr
	auto server_socket = make_unique<QUICXIASocket>(xcache_aid);
	GraphPtr dummy_cid_addr = server_socket->serveCID(test_cid);
	int sockfd = server_socket->fd();

	XcacheQUIC server(server_callback);

	// Wait for packets
	int bytes_recv;                    // size of packet received
	size_t send_length = 0;
	unsigned char received_ecn;
	picoquic_cnx_t* newest_cnx = NULL;
	picoquic_cnx_t* next_connection = NULL;
	uint8_t buffer[1536];              // buffer to receive packets
	uint8_t send_buffer[1536];
	uint64_t current_time;
	int64_t delay_max = 10000000;      // max wait 10 sec.
	unsigned long to_interface = 0;    // our interface
	sockaddr_x addr_from;
	sockaddr_x addr_local;
	int64_t delta_t;

	while (true) {
		delta_t = server.nextWakeDelay(current_time, delay_max);

		bytes_recv = picoquic_xia_select(sockfd, &addr_from,
				&addr_local, buffer, sizeof(buffer),
				delta_t,
				&current_time);
		if(bytes_recv < 0) {
			printf("Server: ERROR selecting on client requests\n");
			goto server_done;
		}
		if(stop.load()) {
			cout << "Interrupted. Cleaning up" << endl;
			break;
		}

		uint64_t loop_time;
		if(bytes_recv > 0) {
			// Process the incoming packet via QUIC server
			printf("Server: got %d bytes from client\n", bytes_recv);
			Graph sender_addr(&addr_from);
			Graph our_addr(&addr_local);
			printf("Server: sender: %s\n", sender_addr.dag_string().c_str());
			printf("Server: us: %s\n", our_addr.dag_string().c_str());
			(void)server.incomingPacket(buffer,
					(size_t)bytes_recv, (struct sockaddr*)&addr_from,
					(struct sockaddr*)&addr_local, to_interface,
					received_ecn,
					current_time);
			// If we don't have a list of server connections, get it
			if(newest_cnx == NULL
					|| newest_cnx != server.firstConnection()) {
				printf("Server: New connection\n");
				newest_cnx = server.firstConnection();
				if(newest_cnx == NULL) {
					printf("ERROR: No connection found!\n");
					goto server_done;
				}
				// Let's create a context with intent XID
				auto ctx = new callback_context_t();
				ctx->xid.reset(new Node(our_addr.intent_CID_str()));
				picoquic_set_callback(newest_cnx, server_callback, ctx);
				printf("Server: Connection state = %d\n",
						picoquic_get_cnx_state(newest_cnx));

			}
		}
		loop_time = current_time;

		// Send stateless packets
		picoquic_stateless_packet_t* sp;
		while((sp = server.dequeueStatelessPacket()) !=NULL) {
			printf("Server: found a stateless packet to send\n");
			if(sp->addr_to.sx_family != AF_XIA) {
				std::cout << "ERROR: Non XIA stateless packet" << std::endl;
				break;
			}
			// send out any outstanding stateless packets
			printf("Server: sending stateless packet out on network\n");
			picoquic_xia_sendmsg(sockfd, sp->bytes, sp->length,
					&sp->addr_to, &sp->addr_local);
			picoquic_delete_stateless_packet(sp);
		}

		// Send outgoing packets for all connections
		while((next_connection = server.earliestConnection(loop_time))
				!= NULL) {
			int peer_addr_len = sizeof(sockaddr_x);
			int local_addr_len = sizeof(sockaddr_x);
			// Ask QUIC to prepare a packet to send out on this connection
			//
			// TODO: HACK!!! peer and local addr pointers sent as
			// sockaddr_storage so underlying code won't complain.
			// Fix would require changes to picoquic which we want to avoid
			int rc = picoquic_prepare_packet(next_connection, current_time,
					send_buffer, sizeof(send_buffer), &send_length,
					(struct sockaddr_storage*) &addr_from, &peer_addr_len,
					(struct sockaddr_storage*) &addr_local, &local_addr_len);
			if(rc == PICOQUIC_ERROR_DISCONNECTED) {
				// Connections list is empty, if this was the last connection
				if(next_connection == newest_cnx) {
					newest_cnx = NULL;
				}
				printf("Server: Disconnected!\n");
				picoquic_delete_cnx(next_connection);
				// All connections ended, break out of outgoing packets loop
				break;
			}
			if(rc == 0) {
				if(send_length > 0) {
					printf("Server: sending %ld byte packet\n", send_length);
					(void)picoquic_xia_sendmsg(sockfd,
							send_buffer, send_length,
							&addr_from, &addr_local);
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
	return retval;
}