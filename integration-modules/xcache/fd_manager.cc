#include "fd_manager.h"

#include <iostream>
#include <algorithm>

#include <poll.h>

FdManager::FdManager() {
	std::cout << "File descriptor manager initiated" << std::endl;
}

int FdManager::addDescriptor(int sockfd) {
	struct pollfd fd;
	fd.fd = sockfd;
	fd.events = POLLIN;
	fd.revents = 0;
	{
		std::lock_guard<std::mutex> guard(fds_lock);
		fds.push_back(fd);
	}
	return 0;
}

int FdManager::removeDescriptor(int sockfd) {

	std::lock_guard<std::mutex> guard(fds_lock);
	fds.erase (std::remove_if (fds.begin(), fds.end(),
			[&sockfd] (struct pollfd fd) { return fd.fd == sockfd;}),
			fds.end());

	return 0;
}

int FdManager::waitForData(int64_t delta_t, std::vector<int>& ready_fds) {
	struct timespec timeout;
	timeout.tv_sec = 0;
	timeout.tv_nsec = 0;

	if(delta_t <= 0) {
		timeout.tv_sec = 0;
		timeout.tv_nsec = 0;
	} else {
		if(delta_t > 10000000) {
			timeout.tv_sec = (long)10;
			timeout.tv_nsec = 0;
		} else {
			timeout.tv_sec = (long)(delta_t / 1000000);
			timeout.tv_nsec = (long)(delta_t % 1000000)*1000;
		}
	}

	std::vector<struct pollfd> fds_copy;
	{
		std::lock_guard<std::mutex> guard(fds_lock);
		fds_copy = fds;
	}

	int ret = ppoll(fds_copy.data(), fds_copy.size(), &timeout, NULL);
	if (ret > 0) {
		for (auto fd : fds_copy) {
			if (fd.revents && POLLIN) {
				ready_fds.push_back(fd.fd);
			}
		}
	}
	return ret;
}
