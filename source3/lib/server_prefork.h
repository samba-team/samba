/*
   Unix SMB/CIFS implementation.
   Common server globals

   Copyright (C) Simo Sorce <idra@samba.org> 2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "system/network.h"
#include <tevent.h>
#include "lib/tsocket/tsocket.h"

struct prefork_pool;

enum pf_worker_status {
	PF_WORKER_NONE = 0,
	PF_WORKER_ALIVE,
	PF_WORKER_ACCEPTING,
	PF_WORKER_EXITING
};

enum pf_server_cmds {
	PF_SRV_MSG_NONE = 0,
	PF_SRV_MSG_EXIT
};

/**
* @brief This structure is shared between the controlling parent and the
*        the child. The parent can only write to the 'cmds' and
*        'allowed_clients' variables, while a child is running.
*        The child can change 'status', and 'num_clients'.
*        All other variables are initialized by the parent before forking the
*        child.
*/
struct pf_worker_data {
	pid_t pid;
	enum pf_worker_status status;
	time_t started;
	time_t last_used;
	int num_clients;

	enum pf_server_cmds cmds;
	int allowed_clients;
};

/**
* @brief This is the 'main' function called by a child right after the fork.
*        It is daemon specific and should initialize and perform whatever
*        operation the child is meant to do. Returning from this function will
*        cause the termination of the child.
*
* @param ev		The event context
* @param msg_ctx	The messaging context
* @param pf		The mmaped area used to communicate with parent
* @param listen_fd_size The number of file descriptors to monitor
* @param listen_fds	The array of file descriptors
* @param private_data	Private data that needs to be passed to the main
*			function from the calling parent.
*
* @return Returns the exit status to be reported to the parent via exit()
*/
typedef int (prefork_main_fn_t)(struct tevent_context *ev,
				struct messaging_context *msg_ctx,
				struct pf_worker_data *pf,
				int child_id,
				int listen_fd_size,
				int *listen_fds,
				void *private_data);

/**
* @brief Callback function for parents that also want to be called on sigchld
*
* @param ev_ctx		The event context
* @param pool		The pool handler
* @param private_data	Data private to the parent
*/
typedef void (prefork_sigchld_fn_t)(struct tevent_context *ev_ctx,
				    struct prefork_pool *pool,
				    void *private_data);

/* ==== Functions used by controlling process ==== */

/**
* @brief Creates the first pool of preforked processes
*
* @param mem_ctx	The memory context used to hold the pool structure
* @param ev_ctx		The event context
* @param msg_ctx	The messaging context
* @param listen_fd_size	The number of file descriptors to monitor
* @param listen_fds	The array of file descriptors to monitor
* @param min_children	Minimum number of children that must be available at
*			any given time
* @param max_children   Maximum number of children that can be started. Also
*			determines the initial size of the pool.
* @param main_fn	The children 'main' function to be called after fork
* @param private_data	The children private data.
* @param pf_pool	The allocated pool.
*
* @return True if it was successful, False otherwise.
*
* NOTE: each listen_fd is forced to non-blocking mode once handed over.
* You should not toush listen_fds once you hand the to the prefork library.
*/
bool prefork_create_pool(TALLOC_CTX *mem_ctx,
			 struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 int listen_fd_size, int *listen_fds,
			 int min_children, int max_children,
			 prefork_main_fn_t *main_fn, void *private_data,
			 struct prefork_pool **pf_pool);
/**
* @brief Function used to attempt to expand the size of children.
*
* @param pfp		The pool structure.
* @param new_max	The new max number of children.
*
* @return 0 if operation was successful
*	  ENOSPC if the mmap area could not be grown to the requested size
*	  EINVAL if the new max is invalid.
*
* NOTE: this function can easily fail if the mmap area cannot be enlarged.
*	A well behaving parent MUST NOT error out if this happen.
*/
int prefork_expand_pool(struct prefork_pool *pfp, int new_max);

/**
* @brief Used to prefork a number of new children
*
* @param ev_ctx		The event context
* @param msg_ctx	The messaging context
* @param pfp		The pool structure
* @param num_children	The number of children to be started
*
* @return The number of new children effectively forked.
*
* NOTE: This method does not expand the pool, if the max number of children
*	has already been forked it will do nothing.
*/
int prefork_add_children(struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 struct prefork_pool *pfp,
			 int num_children);
/**
* @brief Commands a number of children to stop and exit
*
* @param msg_ctx	The messaging context.
* @param pfp		The pool.
* @param num_children	The number of children we need to retire.
* @param age_limit	The minimum age a child has been active to be
*			considered for retirement. (Compared against the
*			'started' value in the pf_worker_data structure of the
*			children.
*
* @return Number of children that were signaled to stop
*
* NOTE: Only children that have no attached clients can be stopped.
*	If all the available children are too young or are busy then it
*	is possible that none will be asked to stop.
*/
int prefork_retire_children(struct messaging_context *msg_ctx,
			    struct prefork_pool *pfp,
			    int num_children, time_t age_limit);
/**
* @brief Count the number of children
*
* @param pfp	The pool.
* @param active	Number of children currently active if not NULL
*
* @return The total number of children.
*/
int prefork_count_children(struct prefork_pool *pfp, int *active);

/**
* @brief Count the number of actual connections currently allowed
*
* @param pfp		The pool.
*
* @return The number of connections that can still be opened by clients
*	  with the current pool of children.
*/
int prefork_count_allowed_connections(struct prefork_pool *pfp);

/**
* @brief Increase the amount of clients each child is allowed to handle
*	 simultaneaously. It will allow each child to handle more than
*	 one client at a time, up to 'max' (currently set to 100).
*
* @param pfp	The pool.
* @param max	Max number of allowed connections per child
*/
void prefork_increase_allowed_clients(struct prefork_pool *pfp, int max);

/**
* @brief Decrease the amount of clients each child is allowed to handle.
*	 Min is 1.
*
* @param pfp	The pool.
*/
void prefork_decrease_allowed_clients(struct prefork_pool *pfp);

/**
* @brief Reset the maximum allowd clients per child to 1.
*	 Does not reduce the number of clients actually beeing served by
*	 any given child, but prevents children from overcommitting from
*	 now on.
*
* @param pfp	The pool.
*/
void prefork_reset_allowed_clients(struct prefork_pool *pfp);

/**
* @brief Send a specific signal to all children.
*	 Used to send SIGHUP when a reload of the configuration is needed
*	 for example.
*
* @param pfp		The pool.
* @param signal_num	The signal number to be sent.
*/
void prefork_send_signal_to_all(struct prefork_pool *pfp, int signal_num);

/**
* @brief Send a message to all children that the server changed something
*	 in the pool and they may want to take action.
*
* @param msg_ctx	The messaging context.
* @param pfp		The pool.
*/
void prefork_warn_active_children(struct messaging_context *msg_ctx,
				  struct prefork_pool *pfp);

/**
* @brief Sets the SIGCHLD callback
*
* @param pfp		The pool handler.
* @param sigchld_fn	The callback function (pass NULL to unset).
* @param private_data	Private data for the callback function.
*/
void prefork_set_sigchld_callback(struct prefork_pool *pfp,
				  prefork_sigchld_fn_t *sigchld_fn,
				  void *private_data);

/* ==== Functions used by children ==== */

/**
* @brief Try to listen and accept on one of the listening sockets.
*	 Asynchronusly tries to grab the lock and perform an accept.
*	 Will automatically update the 'status' of the child and handle
*	 all the locking/unlocking/timingout as necessary.
*	 Changes behavior depending on whether the child already has other
*	 client connections. If not it blocks on the lock call for periods of
*	 time. Otherwise it loops on the lock using a timer in order to allow
*	 processing of the other clients requests.
*
* @param mem_ctx	The memory context on whic to allocate the request
* @param ev		The event context
* @param pf		The child/parent shared structure
* @param listen_fd_size	The number of listening file descriptors
* @param listen_fds	The array of listening file descriptors
*
* @return The tevent request pointer or NULL on allocation errors.
*/
struct tevent_req *prefork_listen_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct pf_worker_data *pf,
					int listen_fd_size,
					int *listen_fds);
/**
* @brief Returns the file descriptor after the new client connection has
*	 been accepted.
*
* @param req		The request
* @param mem_ctx	The memory context for cli_addr and srv_addr
* @param fd		The new file descriptor.
* @param srv_addr	The server address in tsocket_address format
* @param cli_addr	The client address in tsocket_address format
*
* @return	The error in case the operation failed.
*/
int prefork_listen_recv(struct tevent_req *req,
			TALLOC_CTX *mem_ctx, int *fd,
			struct tsocket_address **srv_addr,
			struct tsocket_address **cli_addr);

