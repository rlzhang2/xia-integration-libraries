#ifndef XCACHE_PUSH_REQUEST_H
#define XCACHE_PUSH_REQUEST_H

// Push Service includes
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

#define XCACHE_PUSH_TIMEOUT 5
#define XCACHE_PUSH_MAXBUF 2048

class XcachePushRequest : public XcacheWorkRequest {
	public:
		XcachePushRequest(std::string cid, std::string requestor);
		virtual ~XcachePushRequest();
		virtual void process();
	private:
		std::string _cid;
		std::string _requestor;
		XcacheThreadPool *_pool;
		XcacheIRQTable *_irqtable;
		XcacheHandle _xcache;
};
#endif //XCACHE_PUSH_REQUEST_H
