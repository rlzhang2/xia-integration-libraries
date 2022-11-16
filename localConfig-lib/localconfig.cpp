#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

// C Headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>

#include "localconfig.hpp"

// XIA support
#include "xiaapi.hpp"


#define BUFSIZE 512

static std::string& ltrim(std::string& str, const std::string& chars= " \t\r")
{
    str.erase(0, str.find_first_not_of(chars));
    return str;
}
 
static std::string& rtrim(std::string& str, const std::string& chars= " \t\r")
{
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
}
 
static std::string& trim(std::string& str, const std::string& chars= " \t\r")
{
    return ltrim(rtrim(str, chars), chars);
}

LocalConfig& LocalConfig::get_instance(const std::string& confFile)
{
	static LocalConfig config(confFile);
	return config;
}

LocalConfig::LocalConfig(const std::string& confFile)
{
	std::ifstream configuration(confFile);
	if(!configuration.is_open()) {
		throw "ERROR reading local config";
	}
	std::string line;
	while(std::getline(configuration, line)) {
		ltrim(line);
		if (line[0] == '#') {
			continue;
		}
		std::stringstream ss(line);
		std::string item;
		std::vector<std::string> entries;
		while(std::getline(ss, item, '=')) {
			entries.push_back(item);
		}
		if(entries.size() != 2) {
			throw "ERROR in config file";
		}
		_conf[trim(entries[0])] = trim(entries[1]);
	}
	configuration.close();
}

LocalConfig::LocalConfig(){
	this->control_socket = -1;
    this->aid = "";
    this->_name = "";
    this->_iface = "";
    this->_r_addr = "";
	this->_r_port = "";
	this->_r_ad = "";
	this->_r_hid = "";
	this->serverdag_str = "";
}

std::string LocalConfig::get(const std::string& param)
{
	auto it = _conf.find(param);
	if (it == _conf.end()) {
		return "";
	}
	return _conf[param];
}

void LocalConfig::stripInputLine(std::string& line)
{
	auto rm_whitespace = [](char ch) {
		return std::isspace<char>(ch, std::locale::classic());
	};

	line.erase(std::remove_if(line.begin(), line.end(), rm_whitespace),
			line.end());
}

int LocalConfig::configure(std::string control_port, std::string control_addr, 
            addr_info_t &raddr, addr_info_t &saddr)
{
 struct addrinfo hints, *res, *rp;
 int sock_fd;
 struct sockaddr_in addr;

 if(pthread_mutex_init(&this->lock, NULL) != 0)
 {
 	printf("Failed to initialize mutex\n");
 	return -1;
 }

  /* Start listening on the contro addr:port */
  if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	printf("Failed to open listen socket\n");
	return -1;
  }
  int opt_value = 1;

  /* Eliminates "Address already in use" error from bind. */
  if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
				 (const void *)&opt_value , sizeof(int)) < 0) {
	printf("open_listen_socket: Failed to set \
    SO_REUSEADDR socket option\n");
	return -1;
  }

  bzero((char *)&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(control_addr.c_str());
  addr.sin_port = htons(std::stoi(control_port.c_str()));

  if (bind(sock_fd, (struct sockaddr *)&addr,
		   sizeof(addr)) < 0) {
  	perror("\n");
	return -1;
  }

 if(listen(sock_fd, 1) < 0)
 {
 	printf("Failed while listening");
 	return -1;
 }

 // started listening on control socket
 this->control_socket = sock_fd;
 this->router_addr = &raddr;
 this->server_addr = &saddr;
 this->router_addr->addrlen = sizeof(sockaddr_x);
 this->loop = 0;

// Get the first configuration filled in conf
 void *ret = LocalConfig::config_controller((void *)this);
 if(ret)
   return -1;

 this->loop = 1; // keep the config_controller running forever
 pthread_create(&this->control_thread, NULL, config_controller,
 		(void *)this);

 return 0;
}


void *LocalConfig::config_controller(void *arg)
{	
	struct sockaddr_storage their_addr;
	LocalConfig *conf = (LocalConfig *)arg;
	socklen_t addr_size = sizeof(struct sockaddr);
	int new_fd;
	char buf[BUFSIZE];
	bzero(buf, BUFSIZE);
	
	do {
		
		// accept incoming configuration update requests
		new_fd = accept(conf->get_control_socket(), (struct sockaddr *)&their_addr, 
		&addr_size);
		if(new_fd < 0)
		{
			perror("\n");
			return (void *)-1;
		}
		int bytes_recvd = recv(new_fd, buf, BUFSIZE, 0);
		if(bytes_recvd < 0)
	 	{
	 		perror("\n");
	 		return (void *)-1;
	 	}
	 	// change this
	 	std::string s;
		int i=4;
	 	while(i<bytes_recvd)
	 		s.push_back(buf[i++]);

	 	configmessage::Config myconfig;
	 	myconfig.ParseFromString(s);

	 	printf("Received new config from the configurator\n");

	 	pthread_mutex_lock(&conf->lock);
	 	LocalConfig::update_serveraddr(*conf, myconfig.serverdag());
		LocalConfig::update_routeraddr(*conf, myconfig);
		pthread_mutex_unlock(&conf->lock);
		close(new_fd);
	 	
	} while(conf->loop);
	return NULL;
}

bool LocalConfig::set_serverdag_str(std::string serverdag_str)
{
	if(this->serverdag_str.compare(serverdag_str) != 0)
	{
		this->serverdag_str = serverdag_str;
		return true;
	}
	printf("serverdag did not change \n");
	return false;
}

void LocalConfig::update_serveraddr(LocalConfig &conf, std::string serverdag)
{
	if(conf.set_serverdag_str(serverdag)) {
		conf.server_addr->dag.reset(new Graph(serverdag));
		conf.server_addr->dag->fill_sockaddr(&conf.server_addr->addr);
		printf("updated server dag to %s ", serverdag.c_str());
	}
}

void LocalConfig::update_routeraddr(LocalConfig &conf, configmessage::Config myconfig)
{
 	std::string router_addr = "RE " + myconfig.ad() + " " + myconfig.hid();
 	std::cout<<"Received router_addr : "<<router_addr<<std::endl;
 	std::cout<<"Our addr : "<<conf.get_our_addr()<<std::endl;
 	if(conf.get_our_addr().compare(router_addr) != 0 || conf.get_raddr().compare(myconfig.ipaddr()) != 0
 		|| conf.get_rport().compare(myconfig.port()) != 0)
 	{
		LocalConfig::set_config(conf, myconfig);

		int sockfd = picoquic_xia_open_server_socket(conf.get_aid().c_str(), conf.router_addr->dag,
		myconfig.iface(), conf);
	 	if(sockfd < 0)
	 	{
	 		printf("Could not update to the new config");
	 		exit(1);
	 	}
	 	conf.router_addr->sockfd = sockfd;
	 	conf.router_addr->dag->fill_sockaddr(&conf.router_addr->addr);
	 	printf("Router addr updated to %s: %s \n", conf._r_addr.c_str(), conf._r_port.c_str());
 	}
 	else
 	{
 		printf("Router addr did not change\n");
 	}
}


void LocalConfig::set_config(LocalConfig &conf, configmessage::Config myconfig)
{
	conf._name = myconfig.name();
	conf.aid = myconfig.aid();
	conf._r_addr = myconfig.ipaddr();
	conf._iface = myconfig.iface();
	conf._r_port = myconfig.port();
	conf._r_ad = myconfig.ad();
	conf._r_hid = myconfig.hid();
}

std::string LocalConfig::get_raddr()
{
	return this->_r_addr;
}

std::string LocalConfig::get_rport()
{
	return this->_r_port;
}

std::string LocalConfig::get_our_addr()
{
	return "RE " + this->_r_ad + " " + this->_r_hid;
}

std::string LocalConfig::get_router_iface()
{
	return this->_iface;
}

std::string LocalConfig::get_serverdag_str()

{
	return this->serverdag_str;
}

int LocalConfig::get_control_socket()
{
	return this->control_socket;
}

std::string LocalConfig::get_aid()
{
	return this->aid;
}
