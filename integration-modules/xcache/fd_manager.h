#ifndef _FD_MANAGER_H
#define _FD_MANAGER_H

#include <poll.h>

#include <mutex>
#include <vector>

// Manage file descriptors and poll on them when requested
//
class FdManager {
public:
	FdManager();
	int addDescriptor(int sockfd);
	int removeDescriptor(int sockfd);
	int waitForData(int64_t delta_t, std::vector<int>& ready_fds);
private:
	nfds_t nfds;
	struct timespec timeout;
	std::vector<struct pollfd> fds;
	std::mutex fds_lock;
};
#endif //_FD_MANAGER_H
