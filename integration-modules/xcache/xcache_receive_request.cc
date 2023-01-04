// Project includes
#include "xcache_receive_request.h"
#include "xcache_push_request.h"
#include "xcache_irq_table.h"
//#include "controller.h"

// XIA includes
#include "publisher/publisher.h"
#include "headers/content_header.h"
#include "Xsocket.h"
#include "dagaddr.hpp"

// System includes
#include <assert.h>

XcacheReceiveRequest::XcacheReceiveRequest(int accepted_sock)
{
	sock = accepted_sock; // Socket on which we'll receive chunk
	_pool = XcacheThreadPool::get_pool();
	_irqtable = XcacheIRQTable::get_table();
}

XcacheReceiveRequest::~XcacheReceiveRequest()
{
	if(sock != -1) {
		Xclose(sock);
		sock = -1;
	}
}

// Queue up a task to push this chunk to the requestor address
void XcacheReceiveRequest::pushChunkTo(std::string cid, std::string requestor)
{
	XcacheWorkRequestPtr work(
			std::make_unique<XcachePushRequest>(cid, requestor));
	_pool->queue_work(std::move(work));
}

// ASSUME: An accepted socket to which a chunk is being pushed
// Receive chunk header and data over the accepted socket
void XcacheReceiveRequest::process()
{
	std::cout << "Fetching a chunk" << std::endl;
	std::string buf;
	std::unique_ptr<ContentHeader> chdr;
	std::atomic<bool> stop(false);
	if (xcache_get_content(sock, buf, chdr, stop)) {
		std::cout << "Error receiving a chunk" << std::endl;
		return;
	}
	assert(buf.size() == chdr->content_len());
	// Now we have the chunk header in chdr, and contents in buf
	// store the chunk into local cache
	// TODO: We may want to send chunk directly, instead of storing to cache
	/*
	xcache_controller *ctrl = xcache_controller::get_instance();
	std::string chunk_id;
	ctrl->store(chunk_id, buf, chdr->ttl());
	assert(chunk_id == chdr->store_id());
	*/
	// send them to all requestors listed in irq_table

	// Get the list of requestors for this chunk and remove them from table
	auto cid = chdr->id();
	auto requestors = _irqtable->requestors(cid);
	for(auto requestor : requestors) {
		pushChunkTo(cid, requestor);
	}

	return;
}
