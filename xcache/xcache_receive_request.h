#ifndef XCACHE_RECEIVE_REQUEST_H
#define XCACHE_RECEIVE_REQUEST_H

// Fetch Service includes
#include "xcache_work_request.h"
#include "xcache_thread_pool.h"
#include "xcache_irq_table.h"
#include "irq.pb.h"

// XIA includes
#include "xcache.h"

// System includes
#include <chrono>
#include <thread>
#include <iostream>	// TODO remove debug prints and this include

#define XCACHE_RECEIVE_TIMEOUT 5
#define XCACHE_RECEIVE_MAXBUF 2048

class XcacheReceiveRequest : public XcacheWorkRequest {
	public:
		XcacheReceiveRequest(int sock);
		static XcacheReceiveRequest *from_client(std::string &buf);
		virtual ~XcacheReceiveRequest();
		virtual void process();
	private:
		void pushChunkTo(std::string cid, std::string requestor);

		XcacheThreadPool *_pool; // Thread pool to serve
		XcacheIRQTable *_irqtable; // Table of interest requests

		int sock; // Accepted socket to receive chunk on
};
#endif //XCACHE_RECEIVE_REQUEST_H
