// XIA Headers
#include "xiaapi.hpp"

// XIA Helper definitions
#include "localconfig.hpp" // Read config file local.conf

// QUIC Headers
extern "C" {
#include "util.h"    // DBG_PRINTF
};

// C++ Headers
#include <iostream>
#include <string>
#include <sstream>   // ostringstream
#include <memory>    // unique_ptr

// C Headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <errno.h>

// The protobuf defs to configure forwarding table on router
#include "configrequest.pb.h"

#define CONFFILE "local.conf"

// Let's hard code the router's address for now
#define OUR_ADDR "OUR_ADDR"
#define ROUTER_ADDR "ROUTER_ADDR"
#define ROUTER_PORT "ROUTER_PORT"
#define ROUTER_CONTROL_PORT "ROUTER_CONTROL_PORT"
#define ROUTER_IFACE "ROUTER_IFACE"

int picoquic_xia_socket(std::string ifname)
{
    // Get the interface addresses for this system
    struct ifaddrs* ifap;
    if(getifaddrs(&ifap)) {
        std::cout << "ERROR getting local interface addresses" << std::endl;
        return -1;
    }

    // Convert 'ifap' into a smart pointer 'addrs'
    // freeifaddrs() called automatically when 'addrs' goes out of scope
    std::unique_ptr<struct ifaddrs, decltype(&freeifaddrs)> addrs(
            ifap, &freeifaddrs);

    struct ifaddrs* ifa;
    struct sockaddr_in* sa;
    for(ifa = addrs.get(); ifa; ifa = ifa->ifa_next) {
        if(ifa->ifa_addr->sa_family == AF_INET) {
            sa = (struct sockaddr_in*) ifa->ifa_addr;
            if(strncmp(ifa->ifa_name, ifname.c_str(), ifname.length()) == 0) {
                printf("Iface: %s Address: %s\n", ifa->ifa_name,
                    inet_ntoa(sa->sin_addr));
                break;
            }
           
        }
    }
    if(ifa == NULL) {
        std::cout << "ERROR couldn't find the interface address" << std::endl;
        return -1;
    }
    // 'sa' now points to a valid local address
    // Bind to a random port
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockfd == -1) {
        return -1;
    }
    if(bind(sockfd, (struct sockaddr*) sa, sizeof(sockaddr_in))) {
        std::cout << "ERROR binding to a port" << std::endl;
        return -1;
    }
    std::cout<<"Hmm";
    return sockfd;
}

int picoquic_xia_socket()
{
    // Get the interface addresses for this system
    struct ifaddrs* ifap;
    if(getifaddrs(&ifap)) {
        std::cout << "ERROR getting local interface addresses" << std::endl;
        return -1;
    }

    // Convert 'ifap' into a smart pointer 'addrs'
    // freeifaddrs() called automatically when 'addrs' goes out of scope
    std::unique_ptr<struct ifaddrs, decltype(&freeifaddrs)> addrs(
            ifap, &freeifaddrs);

    struct ifaddrs* ifa;
    struct sockaddr_in* sa;
    for(ifa = addrs.get(); ifa; ifa = ifa->ifa_next) {
        if(ifa->ifa_addr->sa_family == AF_INET) {
            sa = (struct sockaddr_in*) ifa->ifa_addr;
            if(strncmp(ifa->ifa_name, "lo", 2) == 0) {
                sa = NULL;
                continue;
            }
            printf("Iface: %s Address: %s\n", ifa->ifa_name,
                    inet_ntoa(sa->sin_addr));
            break;
        }
    }
    if(ifa == NULL) {
        std::cout << "ERROR couldn't find a local address" << std::endl;
        return -1;
    }
    // 'sa' now points to a valid local address
    // Bind to a random port
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockfd == -1) {
        return -1;
    }
    if(bind(sockfd, (struct sockaddr*) sa, sizeof(sockaddr_in))) {
        std::cout << "ERROR binding to a port" << std::endl;
        return -1;
    }
    return sockfd;
}

static int _send_server_cmd(std::string cmd)
{
    // Get router control IP address (XIAConfigHelper address)
    struct sockaddr_in router_addr;
    if(picoquic_xia_router_control_addr(&router_addr)) {
        std::cout << "Error getting router address" << std::endl;
        return -1;
    }

    // Add the command to a protobuf request to XIAConfigHelper on router
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    configrequest::Request request;
    request.set_type(configrequest::Request::IP_ROUTES);
    auto routes = request.mutable_routes();
    routes->add_route_cmds(cmd);

    // Serialize the protobuf to go on wire
    std::string req;
    request.SerializeToString(&req);
    std::cout << "Sending buf of size " << req.size() << std::endl;
    uint32_t req_len_nbo = htonl(req.size());

    // A buffer to hold the Int32 size and the protobuf contents
    uint8_t buffer[1024];
    size_t buffer_offset = 0;
    memcpy(&buffer[buffer_offset], &req_len_nbo, sizeof(req_len_nbo));
    buffer_offset += sizeof(req_len_nbo);
    memcpy(&buffer[buffer_offset], req.c_str(), req.size());
    buffer_offset += req.size();

    // Create socket and connect to XIAConfigHelper
    int rsockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (rsockfd == -1) {
        std::cout << "ERROR: creating socket for router config" << std::endl;
        return -1;
    }
    if(connect(rsockfd, (struct sockaddr*)&router_addr,sizeof(router_addr))) {
        std::cout << "ERROR: talking to router for route setup" << std::endl;
        return -1;
    }
    std::cout << "Connected to router" << std::endl;

    // Receive the helper greeting
    char dummy[32];
    memset(dummy, 0, sizeof(dummy));
    int retval = recv(rsockfd, dummy, sizeof(dummy), 0);
    if (retval < 0) {
        std::cout << "ERROR: receiving helper greeting" << std::endl;
        return -1;
    }
    // The first 4 bytes contain string size
    int strsize;
    memcpy(&strsize, dummy, sizeof(int));
    strsize = ntohl(strsize);
    std::cout << "Router returned string of size: " << strsize << std::endl;
    printf("Router said: %s size: %d\n", &dummy[4], retval);

    std::cout << "Sending route cmd of size: " << buffer_offset << std::endl;
    retval = send(rsockfd, buffer, buffer_offset, 0);
    if (retval != buffer_offset) {
        std::cout << "ERROR: sending routing info to router" << std::endl;
    }
    close(rsockfd);
    return 0;
}

static int _send_server_cmd(std::string cmd, LocalConfig &conf)
{
    // Get router control IP address (XIAConfigHelper address)
    struct sockaddr_in router_addr;
    if(picoquic_xia_router_control_addr(&router_addr, conf)) {
        std::cout << "Error getting router address" << std::endl;
        return -1;
    }

    // Add the command to a protobuf request to XIAConfigHelper on router
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    configrequest::Request request;
    request.set_type(configrequest::Request::IP_ROUTES);
    auto routes = request.mutable_routes();
    routes->add_route_cmds(cmd);

    // Serialize the protobuf to go on wire
    std::string req;
    request.SerializeToString(&req);
    std::cout << "Sending buf of size " << req.size() << std::endl;
    uint32_t req_len_nbo = htonl(req.size());

    // A buffer to hold the Int32 size and the protobuf contents
    uint8_t buffer[1024];
    size_t buffer_offset = 0;
    memcpy(&buffer[buffer_offset], &req_len_nbo, sizeof(req_len_nbo));
    buffer_offset += sizeof(req_len_nbo);
    memcpy(&buffer[buffer_offset], req.c_str(), req.size());
    buffer_offset += req.size();

    // Create socket and connect to XIAConfigHelper
    int rsockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (rsockfd == -1) {
        std::cout << "ERROR: creating socket for router config" << std::endl;
        return -1;
    }

    struct sockaddr_in addr;
    bzero((char *)&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(conf.get_router_iface().c_str());
    std::cout<<"Set sin addr to"<<conf.get_router_iface()<<std::endl;
    
    if (bind(rsockfd, (struct sockaddr *)&addr,
           sizeof(addr)) < 0) {
        perror("\n");
        return -1;
    }
    char str[64];
    inet_ntop(AF_INET, &(router_addr.sin_addr), str, INET_ADDRSTRLEN);
    std::cout<<"Want to connect to "<<str<<std::endl;
    if(connect(rsockfd, (struct sockaddr*)&router_addr,sizeof(router_addr))) {
        std::cout << "ERROR: talking to router for route setup" << std::endl;
        perror("\n");
        return -1;
    }
    std::cout << "Connected to router" << std::endl;

    // Receive the helper greeting
    char dummy[32];
    memset(dummy, 0, sizeof(dummy));
    int retval = recv(rsockfd, dummy, sizeof(dummy), 0);
    if (retval < 0) {
        std::cout << "ERROR: receiving helper greeting" << std::endl;
        return -1;
    }
    // The first 4 bytes contain string size
    int strsize;
    memcpy(&strsize, dummy, sizeof(int));
    strsize = ntohl(strsize);
    std::cout << "Router returned string of size: " << strsize << std::endl;
    printf("Router said: %s size: %d\n", &dummy[4], retval);

    std::cout << "Sending route cmd of size: " << buffer_offset << std::endl;
    retval = send(rsockfd, buffer, buffer_offset, 0);
    if (retval != buffer_offset) {
        std::cout << "ERROR: sending routing info to router" << std::endl;
    }
    close(rsockfd);
    return 0;
}

auto getIPAddressFromSocket(int sockfd) -> std::unique_ptr<struct sockaddr_in>
{
    auto addr = std::make_unique<struct sockaddr_in>();
    socklen_t addrlen = sizeof(struct sockaddr_in);
    if (getsockname(sockfd, (struct sockaddr*) addr.get(), &addrlen)) {
        std::cout << "ERROR: getting address we bound to" << std::endl;
        return nullptr;
    }
    std::cout << "Bound to " << inet_ntoa(addr->sin_addr) << ":"
        << ntohs(addr->sin_port) << std::endl;
    return addr;
}

void xidToLocalDAG (const char* xid, GraphPtr& addr)
{
    // Our XIA address, to be used for sending packets out
    auto conf = LocalConfig(CONFFILE);
    auto our_addr = conf.get(OUR_ADDR);
    std::string xidstr(xid);
    std::string xiaaddrstr = our_addr +  " " + xidstr;
    std::cout << "Our address: " << xiaaddrstr << std::endl;
    addr.reset(new Graph(xiaaddrstr));
}

void xidToLocalDAG (const char* xid, GraphPtr& addr, LocalConfig &conf)
{
    // Our XIA address, to be used for sending packets out
    // auto conf = LocalConfig::get_instance(CONFFILE);
    // auto our_addr = conf.get(OUR_ADDR);
    // 
    auto our_addr = conf.get_our_addr();
    std::string xidstr(xid);
    std::string xiaaddrstr = our_addr +  " " + xidstr;
    //    std::cout<<"xid "<<xid<<" our_addr "<<our_addr<<" "<<"xidstr "<<xidstr<<std::endl;
    std::cout << "Our address: " << xiaaddrstr <<" len : "<<xiaaddrstr.length()<<std::endl;
    addr.reset(new Graph(xiaaddrstr));
}

void aidToLocalDAG(const char* aid, GraphPtr& addr)
{
    xidToLocalDAG(aid, addr);
}

void aidToLocalDAG(const char* aid, GraphPtr& addr, LocalConfig &conf)
{
    xidToLocalDAG(aid, addr, conf);
}

void cidToLocalDAG(const char* cid, GraphPtr& addr, LocalConfig &conf)
{
    xidToLocalDAG(cid, addr, conf);
}

void cidToLocalDAG(const char* cid, GraphPtr& addr)
{
    xidToLocalDAG(cid, addr);
}

auto buildRouteRemoveCommandForXID(std::string& xidtype,
        const char* xid, LocalConfig &conf) -> std::string
{
    // auto conf = LocalConfig::get_instance(CONFFILE);
    // auto router_iface = conf.get(ROUTER_IFACE);
    std::ostringstream cmd;
    std::string xidstr(xid);
    cmd << "./bin/xroute -r " << xidtype << "," << xidstr;
    std::cout << "Route remove cmd to router: " << cmd.str() << std::endl;
    return cmd.str();
}

auto buildRouteRemoveCommandForXID(std::string& xidtype,
        const char* xid) -> std::string
{
    auto conf = LocalConfig(CONFFILE);
    auto router_iface = conf.get(ROUTER_IFACE);
    std::ostringstream cmd;
    std::string xidstr(xid);
    cmd << "./bin/xroute -r " << xidtype << "," << xidstr;
    std::cout << "Route remove cmd to router: " << cmd.str() << std::endl;
    return cmd.str();
}


auto buildRouteCommandForXID(std::string& xidtype,
        const char* xid,
        const struct sockaddr_in& bound_addr, LocalConfig &conf) -> std::string
{
    // auto conf = LocalConfig::get_instance(CONFFILE);

    // // Get the router's interface that we are connected to
    // auto router_iface = conf.get(ROUTER_IFACE);

    // Set route for AID to be sent to our bound address
    auto router_iface = 0;//conf.get_router_iface();
    std::ostringstream cmd;
    std::string xidstr(xid);
    cmd << "./bin/xroute -a " << xidtype << "," << xidstr << ","
        << router_iface << ","
        << inet_ntoa(bound_addr.sin_addr) << ":"
        << ntohs(bound_addr.sin_port);
    std::cout << "Route cmd to router: " << cmd.str() << std::endl;
    return cmd.str();
}

auto buildRouteCommandForXID(std::string& xidtype,
        const char* xid,
        const struct sockaddr_in& bound_addr) -> std::string
{
    auto conf = LocalConfig(CONFFILE);

    // Get the router's interface that we are connected to
    auto router_iface = conf.get(ROUTER_IFACE);

    // Set route for AID to be sent to our bound address
    std::ostringstream cmd;
    std::string xidstr(xid);
    cmd << "./bin/xroute -a " << xidtype << "," << xidstr << ","
        << router_iface << ","
        << inet_ntoa(bound_addr.sin_addr) << ":"
        << ntohs(bound_addr.sin_port);
    std::cout << "Route cmd to router: " << cmd.str() << std::endl;
    return cmd.str();
}

auto buildRouteCommandForCID(const char* cid,
        const struct sockaddr_in& bound_addr,
        LocalConfig &conf) -> std::string
{
    std::string xidtype("CID");
    return buildRouteCommandForXID(xidtype, cid, bound_addr, conf);
}

auto buildRouteCommandForCID(const char* cid,
        const struct sockaddr_in& bound_addr) -> std::string
{
    std::string xidtype("CID");
    return buildRouteCommandForXID(xidtype, cid, bound_addr);
}

auto buildRouteRemoveCommandForCID(const char* cid,
    LocalConfig &conf) -> std::string
{
    std::string xidtype("CID");
    return buildRouteRemoveCommandForXID(xidtype, cid, conf);
}

auto buildRouteRemoveCommandForCID(const char* cid) -> std::string
{
    std::string xidtype("CID");
    return buildRouteRemoveCommandForXID(xidtype, cid);
}

auto buildRouteCommandForAID(const char* aid,
        const struct sockaddr_in& bound_addr) -> std::string
{
    std::string xidtype("AID");
    return buildRouteCommandForXID(xidtype, aid, bound_addr);
}

auto buildRouteCommandForAID(const char* aid,
        const struct sockaddr_in& bound_addr,
        LocalConfig &conf) -> std::string
{
    std::string xidtype("AID");
    return buildRouteCommandForXID(xidtype, aid, bound_addr, conf);
}

auto buildRouteRemoveCommandForAID(const char* aid,
    LocalConfig &conf) -> std::string
{
    std::string xidtype("AID");
    return buildRouteRemoveCommandForXID(xidtype, aid, conf);
}

auto buildRouteRemoveCommandForAID(const char* aid) -> std::string
{
    std::string xidtype("AID");
    return buildRouteRemoveCommandForXID(xidtype, aid);
}

int picoquic_xia_serve_cid(int xcachesockfd, const char* cid,
        GraphPtr& cid_addr, LocalConfig &conf)
{
    // Find out Xcache IP address and port
    auto xcache_ip_addr = getIPAddressFromSocket(xcachesockfd);
    if (xcache_ip_addr == nullptr) {
        return -1;
    }

    // Fill cid_addr with our local DAG for given CID
    cidToLocalDAG(cid, cid_addr, conf);

    // Build a bin/xroute command to be sent to router
    std::string cmd = buildRouteCommandForCID(cid, *xcache_ip_addr, conf);

    if(_send_server_cmd(cmd, conf)) {
        std::cout << "ERROR configuring route to " << cid << std::endl;
        return -1;
    }
    return 0;
}

int picoquic_xia_serve_cid(int xcachesockfd, const char* cid,
        GraphPtr& cid_addr)
{
    // Find out Xcache IP address and port
    auto xcache_ip_addr = getIPAddressFromSocket(xcachesockfd);
    if (xcache_ip_addr == nullptr) {
        return -1;
    }

    // Fill cid_addr with our local DAG for given CID
    cidToLocalDAG(cid, cid_addr);

    // Build a bin/xroute command to be sent to router
    std::string cmd = buildRouteCommandForCID(cid, *xcache_ip_addr);

    if(_send_server_cmd(cmd)) {
        std::cout << "ERROR configuring route to " << cid << std::endl;
        return -1;
    }
    return 0;
}

int picoquic_xia_unserve_cid(const char* cid)
{
    std::string cmd = buildRouteRemoveCommandForCID(cid);
    if(_send_server_cmd(cmd)) {
        std::cout << "ERROR removing route for " << cid << std::endl;
        return -1;
    }
    return 0;
}

int picoquic_xia_unserve_cid(const char* cid, LocalConfig &conf)
{
    std::string cmd = buildRouteRemoveCommandForCID(cid, conf);
    if(_send_server_cmd(cmd, conf)) {
        std::cout << "ERROR removing route for " << cid << std::endl;
        return -1;
    }
    return 0;
}

int picoquic_xia_unserve_aid(const char* aid, LocalConfig &conf)
{
    std::string cmd = buildRouteRemoveCommandForAID(aid, conf);
    if(_send_server_cmd(cmd, conf)) {
        std::cout << "ERROR removing route for " << aid << std::endl;
        return -1;
    }
    return 0;
}

int picoquic_xia_unserve_aid(const char* aid)
{
    std::string cmd = buildRouteRemoveCommandForAID(aid);
    if(_send_server_cmd(cmd)) {
        std::cout << "ERROR removing route for " << aid << std::endl;
        return -1;
    }
    return 0;
}

// Open a server socket
// Associate it to given AID
//
// Returns socket descriptor and our local address, on Success
// Returns -1, on Failure
int picoquic_xia_open_server_socket(const char* aid, GraphPtr& my_addr)
{
    // Open a socket and bind to a random local port
    int sockfd = picoquic_xia_socket();
    if(sockfd == -1) {
        std::cout << "ERROR creating bound socket" << std::endl;
        return -1;
    }

    // Find out the address:port that we bound to
    auto bound_ip_addr = getIPAddressFromSocket(sockfd);
    if (bound_ip_addr == nullptr) {
        return -1;
    }

    // Fill my_addr with our local DAG corresponding to given aid
    aidToLocalDAG(aid, my_addr);

    // Build a bin/xroute command to be sent to router
    std::string cmd = buildRouteCommandForAID(aid, *bound_ip_addr);

    // Send command to configure route from router to this socket for aid
    if(_send_server_cmd(cmd)) {
        std::cout << "ERROR configuring route to " << aid << std::endl;
        return -1;
    }
    return sockfd;
}

// Open a server socket
// Associate it to given AID
//
// Returns socket descriptor and our local address, on Success
// Returns -1, on Failure
int picoquic_xia_open_server_socket(const char* aid, GraphPtr& my_addr, 
    std::string ifname, LocalConfig &conf)
{
    // Open a socket and bind to a random local port
    int sockfd = picoquic_xia_socket(ifname);
    if(sockfd == -1) {
        std::cout << "ERROR creating bound socket" << std::endl;
        return -1;
    }

    // Find out the address:port that we bound to
    auto bound_ip_addr = getIPAddressFromSocket(sockfd);
    if (bound_ip_addr == nullptr) {
        return -1;
    }

    // Fill my_addr with our local DAG corresponding to given aid
    aidToLocalDAG(aid, my_addr, conf);

    // Build a bin/xroute command to be sent to router
    std::string cmd = buildRouteCommandForAID(aid, *bound_ip_addr, conf);

    // Send command to configure route from router to this socket for aid
    if(_send_server_cmd(cmd, conf)) {
        std::cout << "ERROR configuring route to " << aid << std::endl;
        return -1;
    }
    return sockfd;
}

int picoquic_xia_open_server_socket(const char* aid, GraphPtr& my_addr,
    LocalConfig &conf)
{
    // Open a socket and bind to a random local port
    int sockfd = picoquic_xia_socket();
    if(sockfd == -1) {
        std::cout << "ERROR creating bound socket" << std::endl;
        return -1;
    }

    // Find out the address:port that we bound to
    auto bound_ip_addr = getIPAddressFromSocket(sockfd);
    if (bound_ip_addr == nullptr) {
        return -1;
    }

    // Fill my_addr with our local DAG corresponding to given aid
    aidToLocalDAG(aid, my_addr, conf);

    // Build a bin/xroute command to be sent to router
    std::string cmd = buildRouteCommandForAID(aid, *bound_ip_addr, conf);

    // Send command to configure route from router to this socket for aid
    if(_send_server_cmd(cmd, conf)) {
        std::cout << "ERROR configuring route to " << aid << std::endl;
        return -1;
    }
    return sockfd;
}

int picoquic_xia_sendmsg(int sockfd, uint8_t* bytes, int length,
        sockaddr_x* peer_addr, sockaddr_x* local_addr)
{
    Graph addr_to(peer_addr);
    Graph addr_from(local_addr);
    // Convert addr to wire format
    // Create XIA Header
    struct click_xia xiah;
    size_t xiah_len = sizeof(xiah) - sizeof(xiah.node);
    memset(&xiah, 0, xiah_len);
    xiah.ver = 1;
    xiah.nxt = CLICK_XIA_NXT_DATA;
    xiah.plen = htons(length);
    xiah.hlim = HLIM_DEFAULT;
    xiah.dnode = addr_to.num_nodes();
    xiah.snode = addr_from.num_nodes();

    //xiah.snode = myaddr.num_nodes();
    xiah.last = LAST_NODE_DEFAULT;
    int num_nodes = xiah.dnode + xiah.snode;

    // The addresses (dest, src) reside in a separate buffer
    std::vector<click_xia_xid_node> addr_nodes(num_nodes);
    auto dst_nodes = addr_nodes.data();
    auto src_nodes = dst_nodes + xiah.dnode;
    addr_to.fill_wire_buffer(dst_nodes);
    addr_from.fill_wire_buffer(src_nodes);

    // Get the (nearest) XIA router's address
    struct sockaddr_in router_addr;
    if(picoquic_xia_router_addr(&router_addr)) {
        std::cout << "Error getting router address" << std::endl;
        return -1;
    }

    // Combine header, addresses and user provided bytes
    struct iovec parts[3];
    parts[0].iov_base = &xiah;
    parts[0].iov_len = xiah_len;
    parts[1].iov_base = addr_nodes.data();
    parts[1].iov_len = sizeof(click_xia_xid_node) * num_nodes;
    parts[2].iov_base = bytes;
    parts[2].iov_len = length;

    // Now send the packet out to the router
    struct msghdr msg;
    msg.msg_name = &router_addr;
    msg.msg_namelen = sizeof(router_addr);
    msg.msg_iov = parts;
    msg.msg_iovlen = 3;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    int retval = sendmsg(sockfd, &msg, 0);

    return retval;
}

int picoquic_xia_sendmsg(int sockfd, uint8_t* bytes, int length,
        sockaddr_x* peer_addr, sockaddr_x* local_addr, LocalConfig &conf)
{
    Graph addr_to(peer_addr);
    Graph addr_from(local_addr);
    // std::cout<<"addr_to "<<addr_to.dag_string()<<std::endl;
    // std::cout<<"addr_from "<<addr_from.dag_string()<<std::endl;
    // Convert addr to wire format
    // Create XIA Header
    struct click_xia xiah;
    size_t xiah_len = sizeof(xiah) - sizeof(xiah.node);
    memset(&xiah, 0, xiah_len);
    xiah.ver = 1;
    xiah.nxt = CLICK_XIA_NXT_DATA;
    xiah.plen = htons(length);
    xiah.hlim = HLIM_DEFAULT;
    xiah.dnode = addr_to.num_nodes();
    xiah.snode = addr_from.num_nodes();

    //xiah.snode = myaddr.num_nodes();
    xiah.last = LAST_NODE_DEFAULT;
    int num_nodes = xiah.dnode + xiah.snode;

    // The addresses (dest, src) reside in a separate buffer
    std::vector<click_xia_xid_node> addr_nodes(num_nodes);
    auto dst_nodes = addr_nodes.data();
    auto src_nodes = dst_nodes + xiah.dnode;
    addr_to.fill_wire_buffer(dst_nodes);
    addr_from.fill_wire_buffer(src_nodes);

    // Get the (nearest) XIA router's address
    struct sockaddr_in router_addr;
    if(picoquic_xia_router_addr(&router_addr, conf)) {
        std::cout << "Error getting router address" << std::endl;
        return -1;
    }

    // Combine header, addresses and user provided bytes
    struct iovec parts[3];
    parts[0].iov_base = &xiah;
    parts[0].iov_len = xiah_len;
    parts[1].iov_base = addr_nodes.data();
    parts[1].iov_len = sizeof(click_xia_xid_node) * num_nodes;
    parts[2].iov_base = bytes;
    parts[2].iov_len = length;

    // Now send the packet out to the router
    struct msghdr msg;
    msg.msg_name = &router_addr;
    msg.msg_namelen = sizeof(router_addr);
    msg.msg_iov = parts;
    msg.msg_iovlen = 3;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    int retval = sendmsg(sockfd, &msg, 0);

    return retval;
}

int picoquic_xia_router_addr(struct sockaddr_in* router_addr)
{
    auto conf = LocalConfig(CONFFILE);
    auto raddr = conf.get(ROUTER_ADDR);
    auto rport = std::stoi(conf.get(ROUTER_PORT));
    // TODO: fill in the router address from a config file
    // TODO: future calls should just return address without reading.
    memset(router_addr, 0, sizeof(struct sockaddr_in));
    router_addr->sin_port = htons(rport);
    router_addr->sin_family = AF_INET;
    if(inet_aton(raddr.c_str(), &(router_addr->sin_addr)) == 0) {
        std::cout << "Error converting router addr" << std::endl;
        return -1;
    }
    //printf("Router addr: %s:%d\n", inet_ntoa(router_addr->sin_addr),
            //ntohs(router_addr->sin_port));
    return 0;
}

int picoquic_xia_router_addr(struct sockaddr_in* router_addr, LocalConfig &conf)
{
    // auto conf = LocalConfig::get_instance(CONFFILE);
    // auto raddr = conf.get(ROUTER_ADDR);
    // auto rport = std::stoi(conf.get(ROUTER_PORT));
    // TODO: fill in the router address from a config file
    // TODO: future calls should just return address without reading.
    // 
    auto raddr = conf.get_raddr();
    auto rport = conf.get_rport();
    memset(router_addr, 0, sizeof(struct sockaddr_in));
    router_addr->sin_port = htons(std::stoi(rport));
    router_addr->sin_family = AF_INET;
    if(inet_aton(raddr.c_str(), &(router_addr->sin_addr)) == 0) {
        std::cout << "Error converting router addr" << std::endl;
        return -1;
    }
    //printf("Router addr: %s:%d\n", inet_ntoa(router_addr->sin_addr),
            //ntohs(router_addr->sin_port));
    return 0;
}

int picoquic_xia_router_control_addr(struct sockaddr_in* router_addr)
{
    // TODO: fill in the router address from a config file
    auto conf = LocalConfig(CONFFILE);
    auto raddr = conf.get(ROUTER_ADDR);
    auto rcport = std::stoi(conf.get(ROUTER_CONTROL_PORT));
    // TODO: future calls should just return address without reading.
    memset(router_addr, 0, sizeof(struct sockaddr_in));
    router_addr->sin_port = htons(rcport);
    router_addr->sin_family = AF_INET;
    if(inet_aton(raddr.c_str(), &(router_addr->sin_addr)) == 0) {
        std::cout << "Error converting router addr" << std::endl;
        return -1;
    }
    //printf("Router addr: %s:%d\n", inet_ntoa(router_addr->sin_addr),
            //ntohs(router_addr->sin_port));
    return 0;
}

int picoquic_xia_router_control_addr(struct sockaddr_in* router_addr,
    LocalConfig &conf)
{
    auto raddr = conf.get_raddr();
    auto rcport = "9854";//conf.get_rport();
    std::cout<<"Connecting to "<<raddr<<":"<<rcport<<std::endl;
    // TODO: future calls should just return address without reading.
    memset(router_addr, 0, sizeof(struct sockaddr_in));
    router_addr->sin_port = htons(std::stoi(rcport));
    router_addr->sin_family = AF_INET;
    if(inet_aton(raddr.c_str(), &(router_addr->sin_addr)) == 0) {
        std::cout << "Error converting router addr" << std::endl;
        return -1;
    }
    //printf("Router addr: %s:%d\n", inet_ntoa(router_addr->sin_addr),
            //ntohs(router_addr->sin_port));
    return 0;
}

int picoquic_xia_recvfrom(int sockfd, sockaddr_x* addr_from,
        sockaddr_x* addr_local, uint8_t* buffer, int buflen)
{
    // Receive the packet
    struct sockaddr_in router_addr;
    struct msghdr msg;

    // We receive the XIA Header minus DAGs
    struct click_xia xiah;
    size_t xiah_len = sizeof(xiah) - sizeof(xiah.node);
    // and the DAGs along with payload
    uint8_t addrspluspayload[1532];

    struct iovec parts[2];
    parts[0].iov_base = &xiah;
    parts[0].iov_len = xiah_len;
    parts[1].iov_base = addrspluspayload;
    parts[1].iov_len = sizeof(addrspluspayload);

    msg.msg_name = &router_addr;
    msg.msg_namelen = sizeof(router_addr);
    msg.msg_iov = parts;
    msg.msg_iovlen = 2;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    ssize_t retval = recvmsg(sockfd, &msg, 0);
    if(retval == -1) {
        std::cout << "Error receiving a packet" << std::endl;
        return -1;
    }

    // Extract XIA header from it
    if(xiah.ver != 1 || xiah.nxt != CLICK_XIA_NXT_DATA) {
        std::cout << "Error: invalid packet. Not XIA" << std::endl;
        return -1;
    }

    // Copy over the DAGs to user provided buffers
    int payload_length = ntohs(xiah.plen);
    const node_t* dst_wire_addr = (const node_t*)addrspluspayload;
    const node_t* src_wire_addr = dst_wire_addr + xiah.dnode;
    Graph our_addr;
    Graph their_addr;
    our_addr.from_wire_format(xiah.dnode, dst_wire_addr);
    their_addr.from_wire_format(xiah.snode, src_wire_addr);
    our_addr.fill_sockaddr(addr_local);
    their_addr.fill_sockaddr(addr_from);

    // Copy out the payload to user buffer
    int payload_offset = sizeof(node_t) * (xiah.dnode + xiah.snode);
    memcpy(buffer, &(addrspluspayload[payload_offset]), payload_length);
    return payload_length;
}

int picoquic_xia_select(int sockfd, sockaddr_x* addr_from,
        sockaddr_x* addr_local, uint8_t* buffer, int buflen,
        int64_t delta_t, uint64_t* current_time)
{
    fd_set readfds;
    struct timeval tv;
    int bytes_recv = 0;
    int ret_select;

    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    if(delta_t <= 0) {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
    } else {
        if(delta_t > 10000000) {
            tv.tv_sec = (long)10;
            tv.tv_usec = 0;
        } else {
            tv.tv_sec = (long)(delta_t / 1000000);
            tv.tv_usec = (long)(delta_t % 1000000);
        }
    }
    ret_select = select(sockfd+1, &readfds, NULL, NULL, &tv);
    if(ret_select < 0) {
        bytes_recv = -1;
        DBG_PRINTF("Error: select on xiaquic sock returns %d\n", ret_select);
    } else if(ret_select > 0) {
        if(FD_ISSET(sockfd, &readfds)) {
            bytes_recv = picoquic_xia_recvfrom(sockfd, addr_from,
                    addr_local, buffer, buflen);
            if(bytes_recv <= 0) {
                DBG_PRINTF("Unable to recv on xiaquic sock %d\n", sockfd);
            }
        }
    }
    *current_time = picoquic_current_time();

    return bytes_recv;
}

int picoquic_xia_icid_request(int xcachesockfd,
        sockaddr_x* cid_addr, sockaddr_x* our_addr) {
    uint8_t bytes[0];
    picoquic_xia_sendmsg(xcachesockfd, bytes, 0, cid_addr, our_addr);
}

int picoquic_xia_icid_request(int xcachesockfd,
        sockaddr_x* cid_addr, sockaddr_x* our_addr,
        LocalConfig conf) {
    uint8_t bytes[0];
    picoquic_xia_sendmsg(xcachesockfd, bytes, 0, cid_addr, our_addr, conf);
}
