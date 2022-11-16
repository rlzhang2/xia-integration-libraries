#ifndef _XCACHE_QUIC_SERVER_H
#define _XCACHE_QUIC_SERVER_H

extern "C" {
#include "picoquic.h"
#include "picosocks.h"
#include "util.h"
};

#include <vector>
#include <memory>
#include <string>

#include "xcache_quic.h"
#include "quicxiasock.hpp"

#include "xiaapi.hpp"

#define TEST_CHUNK_SIZE 8192

using XcacheQUICPtr = std::unique_ptr<XcacheQUIC>;
using QUICXIASocketPtr = std::unique_ptr<QUICXIASocket>;

typedef struct {
    int stream_open;
    int received_so_far;
    std::vector<uint8_t> data;
    size_t datalen;
    size_t sent_offset;
    NodePtr xid;
} callback_context_t;

class XcacheQUICServer {
    public:
        XcacheQUICServer(const std::string& aid);
        int64_t nextWakeDelay(int64_t delay_max);
        void updateTime();
        int incomingPacket();
        int sendInterest(sockaddr_x& icid_dag);
        int fd();
        GraphPtr serveCID(const std::string& cid);
    private:
        static int server_callback(picoquic_cnx_t* connection,
                uint64_t stream_id, uint8_t* bytes, size_t length,
                picoquic_call_back_event_t event, void* ctx);
        void print_address(struct sockaddr* address, char* label);
        static int buildDataToSend(callback_context_t* ctx, size_t datalen);
        static int sendData(picoquic_cnx_t* connection,
                uint64_t stream_id, callback_context_t* ctx);
        static int remove_context(picoquic_cnx_t* connection,
                callback_context_t* context);
        static int process_data(callback_context_t* context,
                uint8_t* bytes, size_t length);

        XcacheQUIC quic;
        int bytes_recv;                    // size of packet received
        size_t send_length = 0;
        unsigned char received_ecn;
        picoquic_cnx_t* newest_cnx = NULL;
        picoquic_cnx_t* next_connection = NULL;
        uint8_t buffer[1536];              // buffer to receive packets
        uint8_t send_buffer[1536];
        int64_t delay_max = 10000000;      // max wait 10 sec.
        unsigned long to_interface = 0;    // our interface
        sockaddr_x addr_from;
        sockaddr_x addr_local;
        int64_t delta_t;

        int sockfd;     // QUIC socket, this server is listening to
        QUICXIASocketPtr xcache_socket;

};
#endif //_XCACHE_QUIC_SERVER_H
