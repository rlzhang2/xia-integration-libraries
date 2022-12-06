#ifndef _XCACHE_WORK_REQUEST_H
#define _XCACHE_WORK_REQUEST_H

/*!
 * @brief Abstract class representing Forwarding Service work request
 *
 * All tasks in the Forwarding Service are queued up in a WorkQueue
 * and are then scheduled among Worker threads.
 */

class XcacheWorkRequest {
	public:
		virtual ~XcacheWorkRequest() {}
		virtual void process() = 0;
	protected:

};
#endif // _XCACHE_WORK_REQUEST_H
