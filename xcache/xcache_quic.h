#ifndef _XCACHE_QUIC_H_
#define _XCACHE_QUIC_H_

// QUIC includes
extern "C" {
#include "picoquic.h"
#include "picosocks.h"
#include "util.h"
#include <sys/types.h>
#include <ifaddrs.h>
#include <stdio.h>
};

// C++ standard includes
#include <string>
#include <memory>

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"
#define LOGFILENAME "xcache.log"

using PicoquicPtr = std::unique_ptr<picoquic_quic_t,
	  decltype(&picoquic_free)>;

using FilePtr = std::unique_ptr<FILE, decltype(&fclose)>;

class XcacheQUIC {
	public:
		XcacheQUIC(picoquic_stream_data_cb_fn callback);
		void updateTime();
		int64_t nextWakeDelay(int64_t delay_max);
		int incomingPacket(uint8_t* bytes, uint32_t packet_length,
				struct sockaddr* addr_from, struct sockaddr* addr_to,
				int if_index_to, unsigned char received_ecn);
		uint64_t currentTime();
		picoquic_cnx_t* firstConnection();
		picoquic_stateless_packet_t* dequeueStatelessPacket();
		picoquic_cnx_t* earliestConnection();

	private:
		void init();
		std::string serverCertFile();
		std::string serverKeyFile();
		std::string inputPath(std::string filename);

		std::string server_key_file;
		std::string server_cert_file;
		PicoquicPtr server = PicoquicPtr(nullptr, &picoquic_free);
		FilePtr logfile = FilePtr(nullptr, &fclose);
		uint64_t current_time;
};
#endif //_XCACHE_QUIC_H_
