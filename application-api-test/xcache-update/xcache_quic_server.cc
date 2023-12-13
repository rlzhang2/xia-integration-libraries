
#include "xcache_quic_server.h"

#include "cid_header.h"
#include <functional> // std::bind
#include <iostream>
#include <fstream>
#include <tuple>
using namespace std;

XcacheQUICServer::XcacheQUICServer(const string& xcache_aid)
    : quic(&XcacheQUICServer::server_callback) {
    xcache_socket = make_unique<QUICXIASocket>(xcache_aid);
    xcache_cidHash=create_table(TABLE_SIZE);
}

void XcacheQUICServer::updateTime() {
    quic.updateTime();
}

int XcacheQUICServer::fd() {
    return xcache_socket->fd();
}

string  XcacheQUICServer::getCID() {

	int ret;
	string sCID_to_request;
    	ret = picoquic_xia_recvfrom(xcache_socket->fd(), &addr_from, &addr_local,
            buffer, sizeof(buffer));
        Graph our_addr(&addr_local);
	sCID_to_request = our_addr.intent_CID_str();

    return sCID_to_request;
}

GraphPtr XcacheQUICServer::serveCID(const string& cid) {

    return xcache_socket->serveCID(cid);
}

int64_t XcacheQUICServer::nextWakeDelay(int64_t delay_max) {
    return quic.nextWakeDelay(delay_max);
}

int XcacheQUICServer::sendInterest(sockaddr_x& icid_dag) {
    sockaddr_x our_addr;
    xcache_socket->fillAddress(our_addr);
    return picoquic_xia_icid_request(fd(), &icid_dag, &our_addr);
}

void XcacheQUICServer::upthashtable(vector <string> xidLst){
        initHashtable(gethashtable(), xidLst);
}

chunkhash_table*  XcacheQUICServer::gethashtable(){
        if (xcache_cidHash->count > 0) {
                //printTable(xcache_cidHash);
                cout<<"check xcache hashtable size: "<<xcache_cidHash->count <<endl;
        }
        return xcache_cidHash;
}

// There's a packet on our socket for us to process, after select()
int XcacheQUICServer::incomingPacket() {
    bytes_recv = picoquic_xia_recvfrom(fd(), &addr_from, &addr_local,
            buffer, sizeof(buffer));
    if(bytes_recv <= 0) {
        cout << "ERROR recv on xiaquic sock " << fd() << endl;
    }
    quic.updateTime();

    if(bytes_recv > 0) {
        cout << "step1. Server got " << bytes_recv << " bytes from client" << endl;
        Graph sender_addr(&addr_from);
        Graph our_addr(&addr_local);
        cout << "Sender: " << sender_addr.dag_string() << endl;
        cout << "Us: " << our_addr.dag_string() << endl;
        quic.incomingPacket(buffer,
                (size_t) bytes_recv, (struct sockaddr*) &addr_from,
                (struct sockaddr*) &addr_local, to_interface,
                received_ecn);
        if(newest_cnx == NULL
            || newest_cnx != quic.firstConnection()) {
            cout << "Server: New connection" << endl;
            newest_cnx = quic.firstConnection();
            if(newest_cnx == NULL) {
                cout << "ERROR: No connection found!" << endl;
                return -1;
            }
            auto ctx = new callback_context_t();
            ctx->xid.reset(new Node(our_addr.intent_CID_str()));
	    //Check the requested XID is set with new quic context
	    Node cidNode_tmp = our_addr.intent_CID_str();
	    cout<<"step2. Server captures CID requested from Get "<< cidNode_tmp.to_string().c_str()<<endl;
	    
            picoquic_set_callback(newest_cnx, server_callback, ctx);
            cout << "Server: Connection state = "
                << picoquic_get_cnx_state(newest_cnx) << endl;
        }
    }

    // Send stateless packets
    picoquic_stateless_packet_t* sp;
    while((sp = quic.dequeueStatelessPacket()) !=NULL) {
        cout << "Server: found a stateless packet to send" << endl;
        if(sp->addr_to.sx_family != AF_XIA) {
            cout << "ERROR: Non XIA stateless packet" << endl;
            break;
        }
        // send out any outstanding stateless packets
        cout << "Server: sending stateless packet out on network" << endl;
        picoquic_xia_sendmsg(fd(), sp->bytes, sp->length,
                &sp->addr_to, &sp->addr_local);
        picoquic_delete_stateless_packet(sp);
    }

    // Send outgoing packets for all connections
    while((next_connection = quic.earliestConnection()) != NULL) {
        int peer_addr_len = sizeof(sockaddr_x);
        int local_addr_len = sizeof(sockaddr_x);
        // Ask QUIC to prepare a packet to send out on this connection
        //
        // TODO: HACK!!! peer and local addr pointers sent as
        // sockaddr_storage so underlying code won't complain.
        // Fix would require changes to picoquic which we want to avoid
	std::cout<<"Check QuicServer Preparing Packet to send out"<<std::endl;
        int rc = picoquic_prepare_packet(next_connection,
                quic.currentTime(),
                send_buffer, sizeof(send_buffer), &send_length,
                (struct sockaddr_storage*) &addr_from, &peer_addr_len,
                (struct sockaddr_storage*) &addr_local, &local_addr_len);
	cout<<"RZ Check send_length: "<<sizeof(send_buffer)<<endl;
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
		//send content data if available locally
		std::vector<uint8_t> contentData;
		std::string chunkloc =CHUNK_LOC;
        	contentData=get_chunkdata(getCID().c_str(), chunkloc, "GET", send_length);

    		 (void)picoquic_xia_sendmsg(fd(),
                        reinterpret_cast<uint8_t *>(contentData.data()), contentData.size(),
                        &addr_from, &addr_local);
		 printf("Server: sending %ld byte packet\n", contentData.size());
            }
        } else {
            printf("Server: Exiting outgoing pkts loop. rc=%d\n", rc);
            break;
        }
    }
    return 0;
}

void XcacheQUICServer::print_address(struct sockaddr* address, char* label)
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

int XcacheQUICServer::buildDataToSend(callback_context_t* ctx, size_t datalen)
{
    //First we retrieve the CID from getRequest
    Node cidNode_req = * ctx->xid;
    cout<<"Check CID string requested from Get "<< cidNode_req.to_string().c_str()<<endl;
    //ctx->data.reserve(datalen);
    //TODO: If the datalen is greater than TEST_CHUNK_SIZE, handle errormsg
    std::vector<uint8_t> tmpChunkData;
     std::string procType("GET");
     std::string chunkloc =CHUNK_LOC;
    tmpChunkData = get_chunkdata(cidNode_req.to_string().c_str(),chunkloc, procType, datalen);

    copy(tmpChunkData.begin(), tmpChunkData.end(), back_inserter(ctx->data));
    printf("Sending %ld bytes of data on stream\n", ctx->data.size() );

    return 0;
}

// Send a chunk
int XcacheQUICServer::sendData(picoquic_cnx_t* connection,
                uint64_t stream_id, callback_context_t* ctx)
{
    cout <<"step5. "<< __FUNCTION__ << ": Create Data to send to Client "  << endl;
    if (!ctx) {
        return -1;
    }

    // Fill in random data as chunk contents
    if (ctx->data.size() == 0) {
        if (buildDataToSend(ctx, TEST_CHUNK_SIZE)) {
            cout << "ERROR: failed to retrieve data to send" << endl;
            return -1;
        }
        ctx->datalen = ctx->data.size();
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
        cout << "ERROR: queuing data to send" << endl;
        return -1;
    } 
    cout << "Send Data Size: " << ctx->datalen <<endl;
    ctx->sent_offset = ctx->datalen;
    return ctx->datalen;
}

int XcacheQUICServer::remove_context(picoquic_cnx_t* connection,
            callback_context_t* context) {
    if(context != NULL) {
        delete context;
        picoquic_set_callback(connection, server_callback, NULL);
        std::cout << "ServerCallback: freed context" << std::endl;
    }
    return 0;
}

// Handle data from client
int XcacheQUICServer::process_data(callback_context_t* context,
        uint8_t* bytes, size_t length)
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

    // Client simply sends a hello message as a placeholder
    string data((const char*)bytes, length);
    cout <<"step4. "<< __FUNCTION__ << ": Client sent " << data.c_str() << endl;
    context->received_so_far += length;
    return length;
}


int XcacheQUICServer::server_callback(picoquic_cnx_t* connection,
        uint64_t stream_id, uint8_t* bytes, size_t length,
        picoquic_call_back_event_t event, void* ctx)
{
   
    cout <<"step3. " << __FUNCTION__ <<": stream: " << stream_id
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

     	   // getCIDcontent("test",connection);
            cout << "ServerCallback: StreamFin" << endl;
            cout << "ServerCallback: got " << context->received_so_far
                << " bytes from client before ending" << endl;
            return 0;
    };
    return 0;
}

