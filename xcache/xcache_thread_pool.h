#ifndef _XCACHE_THREAD_POOL_H
#define _XCACHE_THREAD_POOL_H

#include <condition_variable>
#include <thread>
#include <mutex>
#include <queue>
#include <vector>
#include <atomic>

class XcacheWorker;
class XcacheWorkRequest;

using XcacheWorkRequestPtr = std::unique_ptr<XcacheWorkRequest>;

class XcacheThreadPool {

	public:
		static XcacheThreadPool *get_pool(); // A reference to this thread pool

		int queue_work(XcacheWorkRequestPtr work); // Add work to work queue

		XcacheWorkRequestPtr fetch_work(); // Fetch work off queue

		// TODO:
		// fetch_work() should be accessible only to workers

	protected:
		XcacheThreadPool();
		~XcacheThreadPool();

	private:
		// The worker
		void work();

		// There is only one thread pool instance
		static XcacheThreadPool *_instance;

		// Total number of threads in this pool - based on num of processors
		unsigned int _num_threads;

		// Worker objects and corresponding threads
		std::vector<std::thread> _worker_threads;

		// Work Queue, a mutex to protect it
		std::queue<XcacheWorkRequestPtr> _work_queue;
		std::mutex _work_queue_mutex;

		// Workers wait on condition that there is work in queue
		std::condition_variable _work_in_queue;

		// Ensure that the threads are created only once
		std::once_flag _initialized;

		// Stop the workers
		std::atomic_bool _stop;

};
#endif //_XCACHE_THREAD_POOL_H

