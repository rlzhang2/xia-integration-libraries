#include "xcache_icid_handler.h"
#include "xcache_irq_table.h"

#include <sys/types.h>      // bind
#include <sys/socket.h>     // bind

#include <iostream>
#include <memory>

using namespace std;

XcacheICIDHandler::XcacheICIDHandler(XcacheQUICServer& server)
    : _server(server) {

    // Create a socket that we'll accept incoming ICID requests on
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        throw "ERROR: Unable to create socket for ICID Handler";
    }

    // Bind to ICID Handler Port
    //struct sockaddr_in addr;
    auto addr = std::make_unique<struct sockaddr_in>();
    addr->sin_family = AF_INET;
    addr->sin_port = htons(ICID_HANDLER_PORT);
    addr->sin_addr.s_addr = htons(INADDR_ANY);
    if (bind(sockfd, (struct sockaddr*)addr.get(), sizeof(sockaddr_in))) {
        throw "ERROR: binding to ICID Handler port";
    }

    _sockfd = sockfd;
}

XcacheICIDHandler::~XcacheICIDHandler() {
    if (_sockfd != -1) {
        close(_sockfd);
    }
}

int XcacheICIDHandler::fd() {
    return _sockfd;
}

int XcacheICIDHandler::handleICIDRequest()
{
    char buffer[ICID_MAXBUF];
    int ret;
    bool fetch_needed = false;
    auto irqtable = XcacheIRQTable::get_table();

    cout << "XcacheICIDHandler: waiting for incoming ICID packet" << endl;
    ret = recvfrom(_sockfd, buffer, ICID_MAXBUF, 0, NULL, NULL);
    if(ret <= 0) {
        cout << "Error reading interest:"
            << strerror(errno) << endl;
        return -1;
    }

    // Read in the XIA Header here
    // TODO: Add additional checks to ensure buffer contains XIA pkt
    cout << "XcacheICIDHandler: reading XIA header" << endl;
    struct click_xia *xiah = (struct click_xia *)buffer;
    Graph dst_dag;
    dst_dag.from_wire_format(xiah->dnode, &xiah->node[0]);

    Graph src_dag;
    src_dag.from_wire_format(xiah->snode, &xiah->node[xiah->dnode]);

    // Now find the ICID intent
    // TODO: Handle exception thrown if intent is not an ICID
    cout << "XcacheICIDHandler: looking for ICID intent" << endl;
    Node icid = dst_dag.intent_ICID();

    // Convert into CID to check for
    Node cid(XID_TYPE_CID, icid.id_string());
    std::string cid_str = cid.to_string();

    // Check if the CID is local. If yes, queue job to push it to caller
    // TODO: Create new QUIC conenciton to src_dag and send chunk
    /*
    printf("ICIDMonitor: checking to see if CID is local\n");
    if(ctrl->is_CID_local(cid_str) == true) {
        // Schedule a job to have the chunk pushed to caller
        printf("ICIDMonitor: queuing a push of found CID\n");
        ICIDWorkRequestPtr work(
                std::make_unique<ICIDPushRequest>(cid.to_string(),
                    src_dag.dag_string()));
        pool->queue_work(std::move(work));
        return;
    }
    */
    cout << "XcacheICIDHandler: CID was not local" << endl;
    // If not,
    // We need to fetch only if the chunk is not already in IRQ table
    if(irqtable->has_entry(cid_str) == false) {
        cout << "XcacheICIDHandler: CID not requested before" << endl;
        fetch_needed = true;
    }

    // add CID and requestor address to irq_table
    cout << "XcacheICIDHandler: updating interest request table" << endl;
    if(irqtable->add_fetch_request(cid_str, src_dag.dag_string()) == false) {
        cout << "Error adding fetch request to table" << endl;
        return -1;
    }

    // If we already sent an interest for this chunk, just wait for
    // it to be satisfied.
    // TODO: This prevents repeated requests from client. Is that OK?
    if(!fetch_needed) {
        cout << "XcacheICIDHandler: skipping duplicate ICID" << endl;
        return 0;
    }

    cout << "XcacheICIDHandler: sending new ICID request" << endl;

    // Send a new ICID request with our socket's address
    sockaddr_x icid_addr;
    dst_dag.fill_sockaddr(&icid_addr);
    _server.sendInterest(icid_addr);

    cout << "XcacheICIDHandler: done handling ICID request" << endl;
    return 0;
}
