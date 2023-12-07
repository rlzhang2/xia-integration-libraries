#include "localconfig.hpp"

// XIA support
#include "../xia-api-lib/xiaapi.hpp"
#include "dagaddr.hpp"
#include "cid_header.h"

// C++ includes
#include <iostream>
#include <memory>
#include <vector>
#include <queue>
#include <string>
#include <sys/stat.h>

// C includes
#include <string.h> // memset
#include <stdio.h>
#include <arpa/inet.h>

extern "C" {
#include "picoquic.h" // picoquic_create, states, err, pkt types, contexts
//#include "picoquic_internal.h"
#include "picosocks.h" // picoquic_select and server socks functions
#include "util.h"
};

#define CONFFILE "xcacheclient.local.conf"

#define ROUTER_ADDR "ROUTER_ADDR"
#define ROUTER_PORT "ROUTER_PORT"
#define OUR_ADDR "OUR_ADDR"
#define CLIENT_AID "CLIENT_AID"
#define THEIR_ADDR "THEIR_ADDR"
#define TICKET_STORE "TICKET_STORE"
#define TEST_CID "TEST_CID"
#define CHUNKS_RECV_DIR "CHUNKS_RECV_DIR"
#define WORKDIR "WORKDIR"

using namespace std;

enum class ChunkState {INITIAL, FETCHING_HEADER, FETCHING_DATA, READY};

struct chunk {
	ChunkState state = ChunkState::INITIAL;
	int hdr_len = -1;
	vector<uint8_t> buf;
	unique_ptr<ContentHeader> chdr;
	unique_ptr<uint8_t> data;
};

struct xcache_callback_context_t {
        int connected;
        int stream_open;
        int received_so_far;
        uint64_t last_interaction_time;
	unique_ptr<struct chunk> chunk;
	vector<string> xid; //add xid to set when requesting a xid fetch
};

int trim_buffer(vector<uint8_t>& buf, int len)
{
	if(len > buf.size()) {
		return -1;
	}
	buf.erase(buf.begin(), buf.begin() + len);
	return 0;
}

//ClientEnd store content after fetching back chunk data from Xcache QuicServer 
int store_xidchunk(struct xcache_callback_context_t* context, std::string fp, uint8_t* bytes, size_t length, bool isValid){
	int retVal =0;
        std::string path;
	FILE *f_store;
	if (isValid){
		char* contextstr = reinterpret_cast<char*> (context->chunk->data.get());
                string datacontextstr(contextstr, context->chunk->chdr->content_len());
                auto chdr_context = make_unique<CIDHeader>(datacontextstr, 0);

		//Store Content using ContentHeader which be same as CID requested
                string serialized_cheader = chdr_context->serialize();
                cout << "content Header  : " << chdr_context->id() << endl;

                //create path if not existing
		if (mkdir(fp.c_str(), 0777) < 0 && errno != EEXIST) {
			std::cout <<"ERROR: create the chunk received filepath "<< endl;
                        return -1;
               	}
        	path = fp + chdr_context->id();
	       	f_store = fopen(path.c_str(), "rb");
               	if (f_store == NULL) { //xid path not existing
			f_store = fopen(path.c_str(), "wb");
                        	if (f_store == NULL) {
                                        std::cout << "Can't open file to write chunk data "<< std::endl;
					return -1;
                                 }
				fwrite(bytes, 1, length, f_store);
				fclose(f_store);
				cout << "Content Chunk has been stored successfully under  "<< path.c_str() << endl;
		} else{
                	printf("content already in storage!!\n");
                	}
        return 0;
	} else {
		cout<<"ERROR: invalid Data received!!!"<<endl;
		retVal= -1;
	}	
	return retVal;
}

int process_data(struct xcache_callback_context_t* context, uint8_t* bytes, size_t length)
{
	//Client use the content cid to fetch to validate chunk received, and path to store chunks
	auto conf = LocalConfig(CONFFILE);
        auto test_cid = conf.get(TEST_CID);

	std::string tmp_fs;
        std::string homepath = getenv("HOME");
        #ifdef WORKDIR
        	homepath.assign(conf.get(WORKDIR));
        #endif
        tmp_fs = homepath + conf.get(CHUNKS_RECV_DIR);

	auto buf = &(context->chunk->buf);
	int hdr_len = -1;
	size_t data_len = -1;
	uint32_t* dataptr;
	char* datastrptr;
	unique_ptr<string> d;
	bool isValid(true);
	std::string s_tmpHeader;
	cout << __FUNCTION__ << " Processing data of size: "
		<< context->chunk->buf.size() << endl;

	while(buf->size() != 0) {
		switch(context->chunk->state) {
			case ChunkState::INITIAL:
				cout << __FUNCTION__ << " state INITIAL" << endl;
				if(buf->size() < 4) {
					return 0;
				}
				// Get header length and switch to FETCHING_HEADER state
				dataptr = reinterpret_cast<uint32_t*>(buf->data());
				context->chunk->hdr_len = ntohl(*dataptr);
				//cout << "Got header len: " << context->chunk->hdr_len << endl;
				buf->erase(buf->begin(), buf->begin() + sizeof(uint32_t));
				context->chunk->state = ChunkState::FETCHING_HEADER;
				break;
			case ChunkState::FETCHING_HEADER:
				cout << __FUNCTION__ << " state FETCHING_HEADER" << endl;
				hdr_len = context->chunk->hdr_len;
				if(buf->size() < hdr_len) {
					return 0;
				}
				// The entire header has been received
				cout << "Got header" << endl;
				datastrptr = reinterpret_cast<char*>(buf->data());
				d.reset(new string(datastrptr, hdr_len));
				context->chunk->chdr.reset(new CIDHeader(*d));
				s_tmpHeader = context->chunk->chdr->id();
				//cout << "Check CIDHeader calcualted from received data: " << s_tmpHeader.c_str() << endl;

				//compare CIDHeader calcuated with the CID requested
				if(strcmp(test_cid.c_str(),s_tmpHeader.c_str()) != 0){
					isValid=false;
				}
				buf->erase(buf->begin(), buf->begin() + hdr_len);
				context->chunk->state = ChunkState::FETCHING_DATA;
				break;
			case ChunkState::FETCHING_DATA:
				cout << __FUNCTION__ << " state FETCHING_DATA" << endl;
				data_len = context->chunk->chdr->content_len();
				if(buf->size() < data_len) {
					return 0;
				}
				// Entire data is now in the buffer
				cout << "Got data" << endl;
				context->chunk->data.reset(new uint8_t[data_len]);
				memcpy(context->chunk->data.get(), buf->data(), data_len);
                                //printf("Received chunkdata from xCacheServer: %lu  %s\n",data_len,  context->chunk->data.get());

				//Store chunks
				store_xidchunk(context,tmp_fs, bytes, length,  isValid); 
				buf->erase(buf->begin(), buf->begin() + data_len);
				context->chunk->state = ChunkState::READY;
				break;
			case ChunkState::READY:
				cout << __FUNCTION__ << " state READY" << endl;
				cout << "We have the entire chunk now!" << endl;
				break;
		};
	}
}


int receive_data(struct xcache_callback_context_t* context,
		uint8_t* bytes, size_t length) {

	cout << __FUNCTION__ << " Got " << length << " bytes" << endl;
	if (!context) {
		return -1;
	}
	if (context->chunk == nullptr) {
		context->chunk.reset(new struct chunk);
	}

	auto buf = &(context->chunk->buf);
	buf->insert(buf->begin(), bytes, bytes + length);
	context->received_so_far += length;
}

// End a stream on the given connection
int end_stream(picoquic_cnx_t* cnx, uint64_t stream_id,
		struct xcache_callback_context_t* context)
{
	picoquic_reset_stream(cnx, stream_id, 0);
	context->stream_open = 0;
	return 0;
}
//picoquic_stream_data_cb_fn
int client_callback(picoquic_cnx_t* cnx,
		uint64_t stream_id, uint8_t*bytes, size_t length,
		picoquic_call_back_event_t event, void *callback_context)
{
//	cout << __FUNCTION__ << " stream: " << stream_id << " datalen: " << length << endl;

	struct xcache_callback_context_t *context =
		(struct xcache_callback_context_t*)callback_context;

	context->last_interaction_time = picoquic_current_time();

	switch(event) {
		case picoquic_callback_ready:
			cout << "Callback: ready" << endl;
			break;
		case picoquic_callback_almost_ready:
			cout << "Callback: almost ready" << endl;
			break;
		case picoquic_callback_close:
			cout << "Callback: close" << endl;
			return end_stream(cnx, stream_id, context);
		case picoquic_callback_application_close:
			cout << "Callback: application close" << endl;
			return end_stream(cnx, stream_id, context);
		case picoquic_callback_stateless_reset:
			cout << "Callback: stateless reset" << endl;
			return end_stream(cnx, stream_id, context);
		case picoquic_callback_stream_reset:
			cout << "Callback: stream reset" << endl;
			return end_stream(cnx, stream_id, context);
		case picoquic_callback_stop_sending:
			cout << "Callback: stop sending" << endl;
			return end_stream(cnx, stream_id, context);
		case picoquic_callback_stream_gap:
			cout << "Callback: stream gap" << endl;
			picoquic_reset_stream(cnx, stream_id,
					PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
			context->stream_open = 0;
			return 0;
		case picoquic_callback_stream_data:
			cout << "Xcache Client Callback: stream data" << endl;
			if(length > 0) {
				receive_data(context, bytes, length);
				process_data(context, bytes, length);
			}
			break;
		case picoquic_callback_stream_fin:
			cout << "Xcache Client Callback: stream finished" << endl;
			if(length > 0) {
				receive_data(context, bytes, length);
				process_data(context, bytes, length);
			}
			context->stream_open = 0;
			cout << "Reception done after " << context->received_so_far
				<< " bytes" << endl;
			cout << "Resetting the stream after it finished." << endl;
			picoquic_reset_stream(cnx, stream_id, 0);
			break;
		default:
			cout << "ERROR: unknown callback event " << event << endl;
	};
	if(context && context->chunk) {
		if(context->chunk->state == ChunkState::READY) {
			cout << __FUNCTION__ <<
				" Got entire chunk. Resetting stream" << endl;
			return end_stream(cnx, stream_id, context);
		}
	}
	return 0;
}

void start_stream(picoquic_cnx_t* connection,
		struct xcache_callback_context_t* context, string xid)
{
	cout << "Starting a stream" << endl;

	uint64_t stream_id = 0;
	context->stream_open = 1;
	context->connected = 1;

	//char data[] = "TEST from start_stream Hello world!";
	//sent a GET CID request
	char data[xid.length()];
        strcpy(data, xid.c_str());
	context->xid.push_back(xid.c_str()); //add requested cid to context	
	// Queue up a "Hello world!" to be sent to the server
	//printf("Sending %ld bytes  CID string %s on stream \n",  sizeof(data), data);
	if(picoquic_add_to_stream(connection,
				stream_id, // Any arbitrary stream ID client picks
				(uint8_t*)data, sizeof(data), // data to be sent
				1)) { // finished; would be 0 if interacting more with server
		cout << "ERROR: sending hello on stream" << endl;
	}
}

int main()
{
	// cleanup state
	int state = 0;
	int retval = -1;
	FILE* logfile = NULL;
	int sockfd;

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

	auto conf = LocalConfig(CONFFILE);
	auto ticket_filename = conf.get(TICKET_STORE);
	auto client_aid = conf.get(CLIENT_AID);
	auto server_addr = conf.get(THEIR_ADDR);
	auto test_cid = conf.get(TEST_CID);
	GraphPtr mydag;
	sockaddr_x my_address;
	int my_addrlen;

	// QUIC client
	picoquic_quic_t *client;

	 std::cout << "Check Start callback context"<<server_addr.c_str()<<endl;
	// Callback context
	struct xcache_callback_context_t callback_context;
	memset(&callback_context, 0, sizeof(struct xcache_callback_context_t));

	// Server address
	sockaddr_x server_address;
	int server_addrlen;
	auto ad_offset = server_addr.find("AD");
	server_addr.insert(ad_offset, "( ");
	server_addr.push_back(' ');
	server_addr.push_back(')');
	std::cout << "Server addr as fallback" << server_addr << std::endl;
	std::string serverdagstr = server_addr + " " + test_cid;
	Graph serverdag(serverdagstr);
	std::cout << "Fetching: " << serverdag.dag_string() << std::endl;
	serverdag.fill_sockaddr(&server_address);
	server_addrlen = sizeof(sockaddr_x);

	// A socket to talk to server on
	//sockfd = socket(server_address.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	sockfd = picoquic_xia_open_server_socket(client_aid.c_str(), mydag);
	if(sockfd == INVALID_SOCKET) {
		goto client_done;
	}
	std::cout << "CLIENTADDR: " << mydag->dag_string() << std::endl;
	mydag->fill_sockaddr(&my_address);
	my_addrlen = sizeof(sockaddr_x);
	cout << "Created socket to talk to server" << endl;
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
			ticket_filename.c_str(),          // ticket_file_name
			NULL,          // ticket_encryption_key
			0              // ticket encryption key length
			);

	if(client == NULL) {
		cout << "ERROR: creating client" << endl;
		goto client_done;
	}
	cout << "Created QUIC context" << endl;
	state = 2; // picoquic context created for client

	// Open a log file for writing
	logfile = fopen("client.log", "w");
	if(logfile == NULL) {
		cout << "ERROR opening log file" << endl;
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
		cout << "ERROR: creating client connection in QUIC" << endl;
		goto client_done;
	}
	cout << "Created QUIC connection instance" << endl;
	state = 4;

	// Set a callback for the client connection
	// TODO: Can we just set the callback in picoquic_create?
	picoquic_set_callback(connection, client_callback, &callback_context);

	// Now connect to the server
	if(picoquic_start_client_cnx(connection)) {
		cout << "ERROR: connecting to server" << endl;
		goto client_done;
	}
	cout << "Started connection to server" << endl;

	// If 0RTT is available, start a stream
	if(picoquic_is_0rtt_available(connection)) {
		start_stream(connection, &callback_context, test_cid);
		zero_rtt_available = 1;
	}
	cout << "Zero RTT available: " << zero_rtt_available << endl;

	// Send a packet to get the connection establishment started
	if(picoquic_prepare_packet(connection, current_time,
				send_buffer, sizeof(send_buffer), &send_length,
				(struct sockaddr_storage*)&server_address, &server_addrlen,
				(struct sockaddr_storage*)&my_address, &my_addrlen)) {
		cout << "ERROR: preparing a QUIC packet to send" << endl;
		goto client_done;
	}
	cout << "Prepared packet of size " <<  send_length << endl;
	mydag->fill_sockaddr(&my_address);
	int bytes_sent;
	if(send_length > 0) {
		bytes_sent = picoquic_xia_sendmsg(sockfd, send_buffer,
				(int) send_length, &server_address, &my_address);
		if(bytes_sent < 0) {
			cout << "ERROR: sending packet to server";
			goto client_done;
		}
		cout << "Sent " << bytes_sent << " byte packet to server" << endl;
	}

	// Wait for incoming packets
	while(picoquic_get_cnx_state(connection) != picoquic_state_disconnected) {

		delay_max = 10000000;

		// Wait until data or timeout
		bytes_recv = picoquic_xia_select(sockfd, &packet_from,
				&packet_to, buffer, sizeof(buffer),
				delta_t,
				&current_time);

		// Exit on error
		if(bytes_recv < 0) {
			cout << "ERROR: receiving packet after select" << endl;
			goto client_done;
		}

		// Get the connection state
		picoquic_state_enum cnx_state = picoquic_get_cnx_state(connection);
		cout << "Connection state: " << cnx_state << endl;

		// We have a packet to process
		if(bytes_recv > 0) {
			cout << "Got " << bytes_recv << " byte packet" << endl;
			// TODO: it seems this function always returns 0
			if(picoquic_incoming_packet(client, buffer,
						(size_t)bytes_recv, (struct sockaddr*)&packet_from,
						(struct sockaddr*)&packet_to, if_index_to,
						received_ecn,
						current_time)) {
				cout << "ERROR: processing incoming packet" << endl;
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
					cout << "Connected! ver: " <<
							picoquic_supported_versions[
							connection->version_index].version
							<< " I-CID: " << 
							(unsigned long long)picoquic_val64_connection_id(
								picoquic_get_logging_cnxid(connection))
							<< endl;
					if(!zero_rtt_available) {
						cout << "0rtt unavailable, starting stream" << endl;
						start_stream(connection, &callback_context,test_cid);
					}
					established = 1;
				}
			}

			// If the stream has been closed, we close the connection
			if(callback_context.connected && !callback_context.stream_open) {
				cout << "The stream was not open, close connection" << endl;
				picoquic_close(connection, 0);
				connection = NULL;
				break;
			}

			// Waited too long. Close connection
			if(current_time > callback_context.last_interaction_time
					&& current_time - callback_context.last_interaction_time
					    > 10000000ull) {
				cout << "No progress for 10 seconds. Closing" << endl;
				picoquic_close(connection, 0);
				connection = NULL;
				break;
				//goto client_done;
			}
		}

		// We get here whether there was a packet or a timeout
		do {
			// Send out all packets waiting to go
			if(picoquic_prepare_packet(connection, current_time,
						send_buffer, sizeof(send_buffer), &send_length,
						NULL, NULL, NULL, NULL)) {
				cout << "ERROR sending QUIC packet" << endl;
				goto client_done;
			}
			if(send_length > 0) {
				cout << "Sending packet of size " << send_length << endl;
				bytes_sent = picoquic_xia_sendmsg(sockfd, send_buffer,
						(int) send_length, &server_address, &my_address);
				//printf("Sending a packet of size %d\n", (int)send_length);
				if(bytes_sent <= 0) {
					cout << "ERROR sending packet to server" << endl;
				}
			}
		} while(send_length > 0);

		// How long before we timeout waiting for more packets
		delta_t = picoquic_get_next_wake_delay(client, current_time,
				delay_max);

	}
	// Save tickets from server, so we can join quickly next time
	if(picoquic_save_tickets(client->p_first_ticket, current_time,
				ticket_filename.c_str()) != 0) {
		cout << "ERROR saving session tickets" << endl;
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
			close(sockfd);
	};

	return retval;
}
