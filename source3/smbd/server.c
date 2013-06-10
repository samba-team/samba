/*
   Unix SMB/CIFS implementation.
   Main SMB server routines
   Copyright (C) Andrew Tridgell		1992-1998
   Copyright (C) Martin Pool			2002
   Copyright (C) Jelmer Vernooij		2002-2003
   Copyright (C) Volker Lendecke		1993-2007
   Copyright (C) Jeremy Allison			1993-2007

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

#include "includes.h"
#include "system/filesys.h"
#include "popt_common.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "registry/reg_init_full.h"
#include "libcli/auth/schannel.h"
#include "secrets.h"
#include "memcache.h"
#include "ctdbd_conn.h"
#include "printing/queue_process.h"
#include "rpc_server/rpc_service_setup.h"
#include "rpc_server/rpc_config.h"
#include "serverid.h"
#include "passdb.h"
#include "auth.h"
#include "messages.h"
#include "smbprofile.h"
#include "lib/id_cache.h"
#include "lib/param/param.h"
#include "lib/background.h"
#include "lib/conn_tdb.h"
#include "../lib/util/pidfile.h"
#include "lib/smbd_shim.h"
#include "scavenger.h"

struct smbd_open_socket;
struct smbd_child_pid;

struct smbd_parent_context {
	bool interactive;

	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;

	/* the list of listening sockets */
	struct smbd_open_socket *sockets;

	/* the list of current child processes */
	struct smbd_child_pid *children;
	size_t num_children;

	struct timed_event *cleanup_te;
};

struct smbd_open_socket {
	struct smbd_open_socket *prev, *next;
	struct smbd_parent_context *parent;
	int fd;
	struct tevent_fd *fde;
};

struct smbd_child_pid {
	struct smbd_child_pid *prev, *next;
	pid_t pid;
};

extern void start_epmd(struct tevent_context *ev_ctx,
		       struct messaging_context *msg_ctx);

extern void start_lsasd(struct event_context *ev_ctx,
			struct messaging_context *msg_ctx);

#ifdef WITH_DFS
extern int dcelogin_atmost_once;
#endif /* WITH_DFS */

/*******************************************************************
 What to do when smb.conf is updated.
 ********************************************************************/

static void smbd_parent_conf_updated(struct messaging_context *msg,
				     void *private_data,
				     uint32_t msg_type,
				     struct server_id server_id,
				     DATA_BLOB *data)
{
	struct tevent_context *ev_ctx =
		talloc_get_type_abort(private_data, struct tevent_context);

	DEBUG(10,("smbd_parent_conf_updated: Got message saying smb.conf was "
		  "updated. Reloading.\n"));
	change_to_root_user();
	reload_services(NULL, NULL, false);
	printing_subsystem_update(ev_ctx, msg, false);
}

/*******************************************************************
 What to do when printcap is updated.
 ********************************************************************/

static void smb_pcap_updated(struct messaging_context *msg,
			     void *private_data,
			     uint32_t msg_type,
			     struct server_id server_id,
			     DATA_BLOB *data)
{
	struct tevent_context *ev_ctx =
		talloc_get_type_abort(private_data, struct tevent_context);

	DEBUG(10,("Got message saying pcap was updated. Reloading.\n"));
	change_to_root_user();
	delete_and_reload_printers(ev_ctx, msg);
}

/*******************************************************************
 Delete a statcache entry.
 ********************************************************************/

static void smb_stat_cache_delete(struct messaging_context *msg,
				  void *private_data,
				  uint32_t msg_tnype,
				  struct server_id server_id,
				  DATA_BLOB *data)
{
	const char *name = (const char *)data->data;
	DEBUG(10,("smb_stat_cache_delete: delete name %s\n", name));
	stat_cache_delete(name);
}

/****************************************************************************
  Send a SIGTERM to our process group.
*****************************************************************************/

static void  killkids(void)
{
	if(am_parent) kill(0,SIGTERM);
}

static void msg_exit_server(struct messaging_context *msg,
			    void *private_data,
			    uint32_t msg_type,
			    struct server_id server_id,
			    DATA_BLOB *data)
{
	DEBUG(3, ("got a SHUTDOWN message\n"));
	exit_server_cleanly(NULL);
}

#ifdef DEVELOPER
static void msg_inject_fault(struct messaging_context *msg,
			     void *private_data,
			     uint32_t msg_type,
			     struct server_id src,
			     DATA_BLOB *data)
{
	int sig;

	if (data->length != sizeof(sig)) {
		DEBUG(0, ("Process %s sent bogus signal injection request\n",
			  procid_str_static(&src)));
		return;
	}

	sig = *(int *)data->data;
	if (sig == -1) {
		exit_server("internal error injected");
		return;
	}

#if HAVE_STRSIGNAL
	DEBUG(0, ("Process %s requested injection of signal %d (%s)\n",
		  procid_str_static(&src), sig, strsignal(sig)));
#else
	DEBUG(0, ("Process %s requested injection of signal %d\n",
		  procid_str_static(&src), sig));
#endif

	kill(getpid(), sig);
}
#endif /* DEVELOPER */

NTSTATUS messaging_send_to_children(struct messaging_context *msg_ctx,
				    uint32_t msg_type, DATA_BLOB* data)
{
	NTSTATUS status;
	struct smbd_parent_context *parent = am_parent;
	struct smbd_child_pid *child;

	if (parent == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	for (child = parent->children; child != NULL; child = child->next) {
		status = messaging_send(parent->msg_ctx,
					pid_to_procid(child->pid),
					msg_type, data);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	return NT_STATUS_OK;
}

/*
 * Parent smbd process sets its own debug level first and then
 * sends a message to all the smbd children to adjust their debug
 * level to that of the parent.
 */

static void smbd_msg_debug(struct messaging_context *msg_ctx,
			   void *private_data,
			   uint32_t msg_type,
			   struct server_id server_id,
			   DATA_BLOB *data)
{
	debug_message(msg_ctx, private_data, MSG_DEBUG, server_id, data);

	messaging_send_to_children(msg_ctx, MSG_DEBUG, data);
}

static void smbd_parent_id_cache_kill(struct messaging_context *msg_ctx,
				      void *private_data,
				      uint32_t msg_type,
				      struct server_id server_id,
				      DATA_BLOB* data)
{
	const char *msg = (data && data->data)
		? (const char *)data->data : "<NULL>";
	struct id_cache_ref id;

	if (!id_cache_ref_parse(msg, &id)) {
		DEBUG(0, ("Invalid ?ID: %s\n", msg));
		return;
	}

	id_cache_delete_from_cache(&id);

	messaging_send_to_children(msg_ctx, msg_type, data);
}

static void smbd_parent_id_cache_delete(struct messaging_context *ctx,
					void* data,
					uint32_t msg_type,
					struct server_id srv_id,
					DATA_BLOB* msg_data)
{
	id_cache_delete_message(ctx, data, msg_type, srv_id, msg_data);

	messaging_send_to_children(ctx, msg_type, msg_data);
}

struct smbd_parent_notify_state {
	struct tevent_context *ev;
	struct messaging_context *msg;
	uint32_t msgtype;
	struct notify_context *notify;
};

static int smbd_parent_notify_cleanup(void *private_data);
static void smbd_parent_notify_cleanup_done(struct tevent_req *req);
static void smbd_parent_notify_proxy_done(struct tevent_req *req);

static bool smbd_parent_notify_init(TALLOC_CTX *mem_ctx,
				    struct messaging_context *msg,
				    struct tevent_context *ev)
{
	struct smbd_parent_notify_state *state;
	struct tevent_req *req;

	state = talloc(mem_ctx, struct smbd_parent_notify_state);
	if (state == NULL) {
		return NULL;
	}
	state->msg = msg;
	state->ev = ev;
	state->msgtype = MSG_SMB_NOTIFY_CLEANUP;

	state->notify = notify_init(state, msg, ev);
	if (state->notify == NULL) {
		goto fail;
	}
	req = background_job_send(
		state, state->ev, state->msg, &state->msgtype, 1,
		lp_parm_int(-1, "smbd", "notify cleanup interval", 60),
		smbd_parent_notify_cleanup, state->notify);
	if (req == NULL) {
		goto fail;
	}
	tevent_req_set_callback(req, smbd_parent_notify_cleanup_done, state);

	if (!lp_clustering()) {
		return true;
	}

	req = notify_cluster_proxy_send(state, ev, state->notify);
	if (req == NULL) {
		goto fail;
	}
	tevent_req_set_callback(req, smbd_parent_notify_proxy_done, state);

	return true;
fail:
	TALLOC_FREE(state);
	return false;
}

static int smbd_parent_notify_cleanup(void *private_data)
{
	struct notify_context *notify = talloc_get_type_abort(
		private_data, struct notify_context);
	notify_cleanup(notify);
	return lp_parm_int(-1, "smbd", "notify cleanup interval", 60);
}

static void smbd_parent_notify_cleanup_done(struct tevent_req *req)
{
	struct smbd_parent_notify_state *state = tevent_req_callback_data(
		req, struct smbd_parent_notify_state);
	NTSTATUS status;

	status = background_job_recv(req);
	TALLOC_FREE(req);
	DEBUG(1, ("notify cleanup job ended with %s\n", nt_errstr(status)));

	/*
	 * Provide self-healing: Whatever the error condition was, it
	 * will have printed it into log.smbd. Just retrying and
	 * spamming log.smbd once a minute should be fine.
	 */
	req = background_job_send(
		state, state->ev, state->msg, &state->msgtype, 1, 60,
		smbd_parent_notify_cleanup, state->notify);
	if (req == NULL) {
		DEBUG(1, ("background_job_send failed\n"));
		return;
	}
	tevent_req_set_callback(req, smbd_parent_notify_cleanup_done, state);
}

static void smbd_parent_notify_proxy_done(struct tevent_req *req)
{
	int ret;

	ret = notify_cluster_proxy_recv(req);
	TALLOC_FREE(req);
	DEBUG(1, ("notify proxy job ended with %s\n", strerror(ret)));
}

static void smb_parent_force_tdis(struct messaging_context *ctx,
				  void* data,
				  uint32_t msg_type,
				  struct server_id srv_id,
				  DATA_BLOB* msg_data)
{
	messaging_send_to_children(ctx, msg_type, msg_data);
}

static void add_child_pid(struct smbd_parent_context *parent,
			  pid_t pid)
{
	struct smbd_child_pid *child;

	child = talloc_zero(parent, struct smbd_child_pid);
	if (child == NULL) {
		DEBUG(0, ("Could not add child struct -- malloc failed\n"));
		return;
	}
	child->pid = pid;
	DLIST_ADD(parent->children, child);
	parent->num_children += 1;
}

/*
  at most every smbd:cleanuptime seconds (default 20), we scan the BRL
  and locking database for entries to cleanup. As a side effect this
  also cleans up dead entries in the connections database (due to the
  traversal in message_send_all()

  Using a timer for this prevents a flood of traversals when a large
  number of clients disconnect at the same time (perhaps due to a
  network outage).  
*/

static void cleanup_timeout_fn(struct event_context *event_ctx,
				struct timed_event *te,
				struct timeval now,
				void *private_data)
{
	struct smbd_parent_context *parent =
		talloc_get_type_abort(private_data,
		struct smbd_parent_context);

	parent->cleanup_te = NULL;

	DEBUG(1,("Cleaning up brl and lock database after unclean shutdown\n"));
	message_send_all(parent->msg_ctx, MSG_SMB_UNLOCK, NULL, 0, NULL);
	messaging_send_buf(parent->msg_ctx,
			   messaging_server_id(parent->msg_ctx),
			   MSG_SMB_BRL_VALIDATE, NULL, 0);
}

static void remove_child_pid(struct smbd_parent_context *parent,
			     pid_t pid,
			     bool unclean_shutdown)
{
	struct smbd_child_pid *child;
	struct server_id child_id;

	child_id = pid_to_procid(pid);

	for (child = parent->children; child != NULL; child = child->next) {
		if (child->pid == pid) {
			struct smbd_child_pid *tmp = child;
			DLIST_REMOVE(parent->children, child);
			TALLOC_FREE(tmp);
			parent->num_children -= 1;
			break;
		}
	}

	if (child == NULL) {
		/* not all forked child processes are added to the children list */
		DEBUG(2, ("Could not find child %d -- ignoring\n", (int)pid));
		return;
	}

	if (unclean_shutdown) {
		/* a child terminated uncleanly so tickle all
		   processes to see if they can grab any of the
		   pending locks
                */
		DEBUG(3,(__location__ " Unclean shutdown of pid %u\n",
			(unsigned int)pid));
		if (parent->cleanup_te == NULL) {
			/* call the cleanup timer, but not too often */
			int cleanup_time = lp_parm_int(-1, "smbd", "cleanuptime", 20);
			parent->cleanup_te = tevent_add_timer(parent->ev_ctx,
						parent,
						timeval_current_ofs(cleanup_time, 0),
						cleanup_timeout_fn,
						parent);
			DEBUG(1,("Scheduled cleanup of brl and lock database after unclean shutdown\n"));
		}
	}

	if (!serverid_deregister(child_id)) {
		DEBUG(1, ("Could not remove pid %d from serverid.tdb\n",
			  (int)pid));
	}
}

/****************************************************************************
 Have we reached the process limit ?
****************************************************************************/

static bool allowable_number_of_smbd_processes(struct smbd_parent_context *parent)
{
	int max_processes = lp_max_smbd_processes();

	if (!max_processes)
		return True;

	return parent->num_children < max_processes;
}

static void smbd_sig_chld_handler(struct tevent_context *ev,
				  struct tevent_signal *se,
				  int signum,
				  int count,
				  void *siginfo,
				  void *private_data)
{
	pid_t pid;
	int status;
	struct smbd_parent_context *parent =
		talloc_get_type_abort(private_data,
		struct smbd_parent_context);

	while ((pid = sys_waitpid(-1, &status, WNOHANG)) > 0) {
		bool unclean_shutdown = False;

		/* If the child terminated normally, assume
		   it was an unclean shutdown unless the
		   status is 0
		*/
		if (WIFEXITED(status)) {
			unclean_shutdown = WEXITSTATUS(status);
		}
		/* If the child terminated due to a signal
		   we always assume it was unclean.
		*/
		if (WIFSIGNALED(status)) {
			unclean_shutdown = True;
		}
		remove_child_pid(parent, pid, unclean_shutdown);
	}
}

static void smbd_setup_sig_chld_handler(struct smbd_parent_context *parent)
{
	struct tevent_signal *se;

	se = tevent_add_signal(parent->ev_ctx,
			       parent, /* mem_ctx */
			       SIGCHLD, 0,
			       smbd_sig_chld_handler,
			       parent);
	if (!se) {
		exit_server("failed to setup SIGCHLD handler");
	}
}

static void smbd_open_socket_close_fn(struct tevent_context *ev,
				      struct tevent_fd *fde,
				      int fd,
				      void *private_data)
{
	/* this might be the socket_wrapper swrap_close() */
	close(fd);
}

static void smbd_accept_connection(struct tevent_context *ev,
				   struct tevent_fd *fde,
				   uint16_t flags,
				   void *private_data)
{
	struct smbd_open_socket *s = talloc_get_type_abort(private_data,
				     struct smbd_open_socket);
	struct messaging_context *msg_ctx = s->parent->msg_ctx;
	struct sockaddr_storage addr;
	socklen_t in_addrlen = sizeof(addr);
	int fd;
	pid_t pid = 0;
	uint64_t unique_id;

	fd = accept(s->fd, (struct sockaddr *)(void *)&addr,&in_addrlen);
	if (fd == -1 && errno == EINTR)
		return;

	if (fd == -1) {
		DEBUG(0,("open_sockets_smbd: accept: %s\n",
			 strerror(errno)));
		return;
	}

	if (s->parent->interactive) {
		reinit_after_fork(msg_ctx, ev, true);
		smbd_process(ev, msg_ctx, fd, true);
		exit_server_cleanly("end of interactive mode");
		return;
	}

	if (!allowable_number_of_smbd_processes(s->parent)) {
		close(fd);
		return;
	}

	/*
	 * Generate a unique id in the parent process so that we use
	 * the global random state in the parent.
	 */
	unique_id = serverid_get_random_unique_id();

	pid = fork();
	if (pid == 0) {
		NTSTATUS status = NT_STATUS_OK;

		/* Child code ... */
		am_parent = NULL;

		/*
		 * Can't use TALLOC_FREE here. Nulling out the argument to it
		 * would overwrite memory we've just freed.
		 */
		talloc_free(s->parent);
		s = NULL;

		set_my_unique_id(unique_id);

		/* Stop zombies, the parent explicitly handles
		 * them, counting worker smbds. */
		CatchChild();

		status = reinit_after_fork(msg_ctx,
					   ev,
					   true);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status,
					    NT_STATUS_TOO_MANY_OPENED_FILES)) {
				DEBUG(0,("child process cannot initialize "
					 "because too many files are open\n"));
				goto exit;
			}
			if (lp_clustering() &&
			    NT_STATUS_EQUAL(status,
			    NT_STATUS_INTERNAL_DB_ERROR)) {
				DEBUG(1,("child process cannot initialize "
					 "because connection to CTDB "
					 "has failed\n"));
				goto exit;
			}

			DEBUG(0,("reinit_after_fork() failed\n"));
			smb_panic("reinit_after_fork() failed");
		}

		smbd_process(ev, msg_ctx, fd, false);
	 exit:
		exit_server_cleanly("end of child");
		return;
	}

	if (pid < 0) {
		DEBUG(0,("smbd_accept_connection: fork() failed: %s\n",
			 strerror(errno)));
	}

	/* The parent doesn't need this socket */
	close(fd);

	/* Sun May 6 18:56:14 2001 ackley@cs.unm.edu:
		Clear the closed fd info out of server_fd --
		and more importantly, out of client_fd in
		util_sock.c, to avoid a possible
		getpeername failure if we reopen the logs
		and use %I in the filename.
	*/

	if (pid != 0) {
		add_child_pid(s->parent, pid);
	}

	/* Force parent to check log size after
	 * spawning child.  Fix from
	 * klausr@ITAP.Physik.Uni-Stuttgart.De.  The
	 * parent smbd will log to logserver.smb.  It
	 * writes only two messages for each child
	 * started/finished. But each child writes,
	 * say, 50 messages also in logserver.smb,
	 * begining with the debug_count of the
	 * parent, before the child opens its own log
	 * file logserver.client. In a worst case
	 * scenario the size of logserver.smb would be
	 * checked after about 50*50=2500 messages
	 * (ca. 100kb).
	 * */
	force_check_log_size();
}

static bool smbd_open_one_socket(struct smbd_parent_context *parent,
				 struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 const struct sockaddr_storage *ifss,
				 uint16_t port)
{
	struct smbd_open_socket *s;

	s = talloc(parent, struct smbd_open_socket);
	if (!s) {
		return false;
	}

	s->parent = parent;
	s->fd = open_socket_in(SOCK_STREAM,
			       port,
			       parent->sockets == NULL ? 0 : 2,
			       ifss,
			       true);
	if (s->fd == -1) {
		DEBUG(0,("smbd_open_once_socket: open_socket_in: "
			"%s\n", strerror(errno)));
		TALLOC_FREE(s);
		/*
		 * We ignore an error here, as we've done before
		 */
		return true;
	}

	/* ready to listen */
	set_socket_options(s->fd, "SO_KEEPALIVE");
	set_socket_options(s->fd, lp_socket_options());

	/* Set server socket to
	 * non-blocking for the accept. */
	set_blocking(s->fd, False);

	if (listen(s->fd, SMBD_LISTEN_BACKLOG) == -1) {
		DEBUG(0,("open_sockets_smbd: listen: "
			"%s\n", strerror(errno)));
			close(s->fd);
		TALLOC_FREE(s);
		return false;
	}

	s->fde = tevent_add_fd(ev_ctx,
			       s,
			       s->fd, TEVENT_FD_READ,
			       smbd_accept_connection,
			       s);
	if (!s->fde) {
		DEBUG(0,("open_sockets_smbd: "
			 "tevent_add_fd: %s\n",
			 strerror(errno)));
		close(s->fd);
		TALLOC_FREE(s);
		return false;
	}
	tevent_fd_set_close_fn(s->fde, smbd_open_socket_close_fn);

	DLIST_ADD_END(parent->sockets, s, struct smbd_open_socket *);

	return true;
}

/****************************************************************************
 Open the socket communication.
****************************************************************************/

static bool open_sockets_smbd(struct smbd_parent_context *parent,
			      struct tevent_context *ev_ctx,
			      struct messaging_context *msg_ctx,
			      const char *smb_ports)
{
	int num_interfaces = iface_count();
	int i,j;
	const char **ports;
	unsigned dns_port = 0;

#ifdef HAVE_ATEXIT
	atexit(killkids);
#endif

	/* Stop zombies */
	smbd_setup_sig_chld_handler(parent);

	ports = lp_smb_ports();

	/* use a reasonable default set of ports - listing on 445 and 139 */
	if (smb_ports) {
		ports = (const char **)str_list_make_v3(talloc_tos(), smb_ports, NULL);
	}

	for (j = 0; ports && ports[j]; j++) {
		unsigned port = atoi(ports[j]);

		if (port == 0 || port > 0xffff) {
			exit_server_cleanly("Invalid port in the config or on "
					    "the commandline specified!");
		}
	}

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		/* We have been given an interfaces line, and been
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/

		/* Now open a listen socket for each of the
		   interfaces. */
		for(i = 0; i < num_interfaces; i++) {
			const struct sockaddr_storage *ifss =
					iface_n_sockaddr_storage(i);
			if (ifss == NULL) {
				DEBUG(0,("open_sockets_smbd: "
					"interface %d has NULL IP address !\n",
					i));
				continue;
			}

			for (j = 0; ports && ports[j]; j++) {
				unsigned port = atoi(ports[j]);

				/* Keep the first port for mDNS service
				 * registration.
				 */
				if (dns_port == 0) {
					dns_port = port;
				}

				if (!smbd_open_one_socket(parent,
							  ev_ctx,
							  msg_ctx,
							  ifss,
							  port)) {
					return false;
				}
			}
		}
	} else {
		/* Just bind to 0.0.0.0 - accept connections
		   from anywhere. */

		const char *sock_addr;
		char *sock_tok;
		const char *sock_ptr;

#if HAVE_IPV6
		sock_addr = "::,0.0.0.0";
#else
		sock_addr = "0.0.0.0";
#endif

		for (sock_ptr=sock_addr;
		     next_token_talloc(talloc_tos(), &sock_ptr, &sock_tok, " \t,"); ) {
			for (j = 0; ports && ports[j]; j++) {
				struct sockaddr_storage ss;
				unsigned port = atoi(ports[j]);

				/* Keep the first port for mDNS service
				 * registration.
				 */
				if (dns_port == 0) {
					dns_port = port;
				}

				/* open an incoming socket */
				if (!interpret_string_addr(&ss, sock_tok,
						AI_NUMERICHOST|AI_PASSIVE)) {
					continue;
				}

				if (!smbd_open_one_socket(parent,
							  ev_ctx,
							  msg_ctx,
							  &ss,
							  port)) {
					return false;
				}
			}
		}
	}

	if (parent->sockets == NULL) {
		DEBUG(0,("open_sockets_smbd: No "
			"sockets available to bind to.\n"));
		return false;
	}

	/* Setup the main smbd so that we can get messages. Note that
	   do this after starting listening. This is needed as when in
	   clustered mode, ctdb won't allow us to start doing database
	   operations until it has gone thru a full startup, which
	   includes checking to see that smbd is listening. */

	if (!serverid_register(messaging_server_id(msg_ctx),
			       FLAG_MSG_GENERAL|FLAG_MSG_SMBD
			       |FLAG_MSG_PRINT_GENERAL
			       |FLAG_MSG_DBWRAP)) {
		DEBUG(0, ("open_sockets_smbd: Failed to register "
			  "myself in serverid.tdb\n"));
		return false;
	}

        /* Listen to messages */

	messaging_register(msg_ctx, NULL, MSG_SHUTDOWN, msg_exit_server);
	messaging_register(msg_ctx, ev_ctx, MSG_SMB_CONF_UPDATED,
			   smbd_parent_conf_updated);
	messaging_register(msg_ctx, NULL, MSG_SMB_STAT_CACHE_DELETE,
			   smb_stat_cache_delete);
	messaging_register(msg_ctx, NULL, MSG_DEBUG, smbd_msg_debug);
	messaging_register(msg_ctx, ev_ctx, MSG_PRINTER_PCAP,
			   smb_pcap_updated);
	messaging_register(msg_ctx, NULL, MSG_SMB_BRL_VALIDATE,
			   brl_revalidate);
	messaging_register(msg_ctx, NULL, MSG_SMB_FORCE_TDIS,
			   smb_parent_force_tdis);

	messaging_register(msg_ctx, NULL,
			   ID_CACHE_DELETE, smbd_parent_id_cache_delete);
	messaging_register(msg_ctx, NULL,
			   ID_CACHE_KILL, smbd_parent_id_cache_kill);

#ifdef CLUSTER_SUPPORT
	if (lp_clustering()) {
		ctdbd_register_reconfigure(messaging_ctdbd_connection());
	}
#endif

#ifdef DEVELOPER
	messaging_register(msg_ctx, NULL, MSG_SMB_INJECT_FAULT,
			   msg_inject_fault);
#endif

	if (lp_multicast_dns_register() && (dns_port != 0)) {
#ifdef WITH_DNSSD_SUPPORT
		smbd_setup_mdns_registration(ev_ctx,
					     parent, dns_port);
#endif
#ifdef WITH_AVAHI_SUPPORT
		void *avahi_conn;

		avahi_conn = avahi_start_register(ev_ctx,
						  ev_ctx,
						  dns_port);
		if (avahi_conn == NULL) {
			DEBUG(10, ("avahi_start_register failed\n"));
		}
#endif
	}

	return true;
}


/*
  handle stdin becoming readable when we are in --foreground mode
 */
static void smbd_stdin_handler(struct tevent_context *ev,
			       struct tevent_fd *fde,
			       uint16_t flags,
			       void *private_data)
{
	char c;
	if (read(0, &c, 1) != 1) {
		/* we have reached EOF on stdin, which means the
		   parent has exited. Shutdown the server */
		exit_server_cleanly("EOF on stdin");
	}
}

static void smbd_parent_loop(struct tevent_context *ev_ctx,
			     struct smbd_parent_context *parent)
{
	/* now accept incoming connections - forking a new process
	   for each incoming connection */
	DEBUG(2,("waiting for connections\n"));
	while (1) {
		int ret;
		TALLOC_CTX *frame = talloc_stackframe();

		ret = tevent_loop_once(ev_ctx);
		if (ret != 0) {
			exit_server_cleanly("tevent_loop_once() error");
		}

		TALLOC_FREE(frame);
	} /* end while 1 */

/* NOTREACHED	return True; */
}


/****************************************************************************
 Initialise connect, service and file structs.
****************************************************************************/

static bool init_structs(void )
{
	/*
	 * Set the machine NETBIOS name if not already
	 * set from the config file.
	 */

	if (!init_names())
		return False;

	if (!secrets_init())
		return False;

	return True;
}

static void smbd_parent_sig_term_handler(struct tevent_context *ev,
					 struct tevent_signal *se,
					 int signum,
					 int count,
					 void *siginfo,
					 void *private_data)
{
	exit_server_cleanly("termination signal");
}

static void smbd_parent_sig_hup_handler(struct tevent_context *ev,
					struct tevent_signal *se,
					int signum,
					int count,
					void *siginfo,
					void *private_data)
{
	struct smbd_parent_context *parent =
		talloc_get_type_abort(private_data,
		struct smbd_parent_context);

	change_to_root_user();
	DEBUG(1,("parent: Reloading services after SIGHUP\n"));
	reload_services(NULL, NULL, false);

	printing_subsystem_update(parent->ev_ctx, parent->msg_ctx, true);
}

/****************************************************************************
 main program.
****************************************************************************/

/* Declare prototype for build_options() to avoid having to run it through
   mkproto.h.  Mixing $(builddir) and $(srcdir) source files in the current
   prototype generation system is too complicated. */

extern void build_options(bool screen);

 int main(int argc,const char *argv[])
{
	/* shall I run as a daemon */
	bool is_daemon = false;
	bool interactive = false;
	bool Fork = true;
	bool no_process_group = false;
	bool log_stdout = false;
	char *ports = NULL;
	char *profile_level = NULL;
	int opt;
	poptContext pc;
	bool print_build_options = False;
        enum {
		OPT_DAEMON = 1000,
		OPT_INTERACTIVE,
		OPT_FORK,
		OPT_NO_PROCESS_GROUP,
		OPT_LOG_STDOUT
	};
	struct poptOption long_options[] = {
	POPT_AUTOHELP
	{"daemon", 'D', POPT_ARG_NONE, NULL, OPT_DAEMON, "Become a daemon (default)" },
	{"interactive", 'i', POPT_ARG_NONE, NULL, OPT_INTERACTIVE, "Run interactive (not a daemon)"},
	{"foreground", 'F', POPT_ARG_NONE, NULL, OPT_FORK, "Run daemon in foreground (for daemontools, etc.)" },
	{"no-process-group", '\0', POPT_ARG_NONE, NULL, OPT_NO_PROCESS_GROUP, "Don't create a new process group" },
	{"log-stdout", 'S', POPT_ARG_NONE, NULL, OPT_LOG_STDOUT, "Log to stdout" },
	{"build-options", 'b', POPT_ARG_NONE, NULL, 'b', "Print build options" },
	{"port", 'p', POPT_ARG_STRING, &ports, 0, "Listen on the specified ports"},
	{"profiling-level", 'P', POPT_ARG_STRING, &profile_level, 0, "Set profiling level","PROFILE_LEVEL"},
	POPT_COMMON_SAMBA
	POPT_COMMON_DYNCONFIG
	POPT_TABLEEND
	};
	struct smbd_parent_context *parent = NULL;
	TALLOC_CTX *frame;
	NTSTATUS status;
	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct server_id server_id;
	struct tevent_signal *se;
	char *np_dir = NULL;
	static const struct smbd_shim smbd_shim_fns =
	{
		.cancel_pending_lock_requests_by_fid = smbd_cancel_pending_lock_requests_by_fid,
		.send_stat_cache_delete_message = smbd_send_stat_cache_delete_message,
		.change_to_root_user = smbd_change_to_root_user,

		.contend_level2_oplocks_begin = smbd_contend_level2_oplocks_begin,
		.contend_level2_oplocks_end = smbd_contend_level2_oplocks_end,

		.become_root = smbd_become_root,
		.unbecome_root = smbd_unbecome_root,

		.exit_server = smbd_exit_server,
		.exit_server_cleanly = smbd_exit_server_cleanly,
	};

	/*
	 * Do this before any other talloc operation
	 */
	talloc_enable_null_tracking();
	frame = talloc_stackframe();

	setup_logging(argv[0], DEBUG_DEFAULT_STDOUT);

	load_case_tables();

	set_smbd_shim(&smbd_shim_fns);

	smbd_init_globals();

	TimeInit();

#ifdef HAVE_SET_AUTH_PARAMETERS
	set_auth_parameters(argc,argv);
#endif

	pc = poptGetContext("smbd", argc, argv, long_options, 0);
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt)  {
		case OPT_DAEMON:
			is_daemon = true;
			break;
		case OPT_INTERACTIVE:
			interactive = true;
			break;
		case OPT_FORK:
			Fork = false;
			break;
		case OPT_NO_PROCESS_GROUP:
			no_process_group = true;
			break;
		case OPT_LOG_STDOUT:
			log_stdout = true;
			break;
		case 'b':
			print_build_options = True;
			break;
		default:
			d_fprintf(stderr, "\nInvalid option %s: %s\n\n",
				  poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
	}
	poptFreeContext(pc);

	if (interactive) {
		Fork = False;
		log_stdout = True;
	}

	if (log_stdout) {
		setup_logging(argv[0], DEBUG_STDOUT);
	} else {
		setup_logging(argv[0], DEBUG_FILE);
	}

	if (print_build_options) {
		build_options(True); /* Display output to screen as well as debug */
		exit(0);
	}

#ifdef HAVE_SETLUID
	/* needed for SecureWare on SCO */
	setluid(0);
#endif

	set_remote_machine_name("smbd", False);

	if (interactive && (DEBUGLEVEL >= 9)) {
		talloc_enable_leak_report();
	}

	if (log_stdout && Fork) {
		DEBUG(0,("ERROR: Can't log to stdout (-S) unless daemon is in foreground (-F) or interactive (-i)\n"));
		exit(1);
	}

	/* we want to re-seed early to prevent time delays causing
           client problems at a later date. (tridge) */
	generate_random_buffer(NULL, 0);

	/* get initial effective uid and gid */
	sec_init();

	/* make absolutely sure we run as root - to handle cases where people
	   are crazy enough to have it setuid */
	gain_root_privilege();
	gain_root_group_privilege();

	fault_setup();
	dump_core_setup("smbd", lp_logfile(talloc_tos()));

	/* we are never interested in SIGPIPE */
	BlockSignals(True,SIGPIPE);

#if defined(SIGFPE)
	/* we are never interested in SIGFPE */
	BlockSignals(True,SIGFPE);
#endif

#if defined(SIGUSR2)
	/* We are no longer interested in USR2 */
	BlockSignals(True,SIGUSR2);
#endif

	/* POSIX demands that signals are inherited. If the invoking process has
	 * these signals masked, we will have problems, as we won't recieve them. */
	BlockSignals(False, SIGHUP);
	BlockSignals(False, SIGUSR1);
	BlockSignals(False, SIGTERM);

	/* Ensure we leave no zombies until we
	 * correctly set up child handling below. */

	CatchChild();

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	umask(0);

	reopen_logs();

	DEBUG(0,("smbd version %s started.\n", samba_version_string()));
	DEBUGADD(0,("%s\n", COPYRIGHT_STARTUP_MESSAGE));

	DEBUG(2,("uid=%d gid=%d euid=%d egid=%d\n",
		 (int)getuid(),(int)getgid(),(int)geteuid(),(int)getegid()));

	/* Output the build options to the debug log */ 
	build_options(False);

	if (sizeof(uint16) < 2 || sizeof(uint32) < 4) {
		DEBUG(0,("ERROR: Samba is not configured correctly for the word size on your machine\n"));
		exit(1);
	}

	if (!lp_load_initial_only(get_dyn_CONFIGFILE())) {
		DEBUG(0, ("error opening config file '%s'\n", get_dyn_CONFIGFILE()));
		exit(1);
	}

	/* Init the security context and global current_user */
	init_sec_ctx();

	/*
	 * Initialize the event context. The event context needs to be
	 * initialized before the messaging context, cause the messaging
	 * context holds an event context.
	 * FIXME: This should be s3_tevent_context_init()
	 */
	ev_ctx = server_event_context();
	if (ev_ctx == NULL) {
		exit(1);
	}

	/*
	 * Init the messaging context
	 * FIXME: This should only call messaging_init()
	 */
	msg_ctx = server_messaging_context();
	if (msg_ctx == NULL) {
		exit(1);
	}

	/*
	 * Reloading of the printers will not work here as we don't have a
	 * server info and rpc services set up. It will be called later.
	 */
	if (!reload_services(NULL, NULL, false)) {
		exit(1);
	}

	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC
	    && !lp_parm_bool(-1, "server role check", "inhibit", false)) {
		DEBUG(0, ("server role = 'active directory domain controller' not compatible with running smbd standalone. \n"));
		DEBUGADD(0, ("You should start 'samba' instead, and it will control starting smbd if required\n"));
		exit(1);
	}

	/* ...NOTE... Log files are working from this point! */

	DEBUG(3,("loaded services\n"));

	init_structs();

#ifdef WITH_PROFILE
	if (!profile_setup(msg_ctx, False)) {
		DEBUG(0,("ERROR: failed to setup profiling\n"));
		return -1;
	}
	if (profile_level != NULL) {
		int pl = atoi(profile_level);
		struct server_id src;

		DEBUG(1, ("setting profiling level: %s\n",profile_level));
		src.pid = getpid();
		set_profile_level(pl, src);
	}
#endif

	if (!is_daemon && !is_a_socket(0)) {
		if (!interactive)
			DEBUG(0,("standard input is not a socket, assuming -D option\n"));

		/*
		 * Setting is_daemon here prevents us from eventually calling
		 * the open_sockets_inetd()
		 */

		is_daemon = True;
	}

	if (is_daemon && !interactive) {
		DEBUG( 3, ( "Becoming a daemon.\n" ) );
		become_daemon(Fork, no_process_group, log_stdout);
	}

        set_my_unique_id(serverid_get_random_unique_id());

#if HAVE_SETPGID
	/*
	 * If we're interactive we want to set our own process group for
	 * signal management.
	 */
	if (interactive && !no_process_group)
		setpgid( (pid_t)0, (pid_t)0);
#endif

	if (!directory_exist(lp_lockdir()))
		mkdir(lp_lockdir(), 0755);

	if (!directory_exist(lp_piddir()))
		mkdir(lp_piddir(), 0755);

	if (is_daemon)
		pidfile_create(lp_piddir(), "smbd");

	status = reinit_after_fork(msg_ctx,
				   ev_ctx,
				   false);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		exit(1);
	}

	if (!interactive) {
		/*
		 * Do not initialize the parent-child-pipe before becoming a
		 * daemon: this is used to detect a died parent in the child
		 * process.
		 */
		status = init_before_fork();
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("init_before_fork failed: %s\n", nt_errstr(status)));
			exit(1);
		}
	}

	parent = talloc_zero(ev_ctx, struct smbd_parent_context);
	if (!parent) {
		exit_server("talloc(struct smbd_parent_context) failed");
	}
	parent->interactive = interactive;
	parent->ev_ctx = ev_ctx;
	parent->msg_ctx = msg_ctx;
	am_parent = parent;

	se = tevent_add_signal(parent->ev_ctx,
			       parent,
			       SIGTERM, 0,
			       smbd_parent_sig_term_handler,
			       parent);
	if (!se) {
		exit_server("failed to setup SIGTERM handler");
	}
	se = tevent_add_signal(parent->ev_ctx,
			       parent,
			       SIGHUP, 0,
			       smbd_parent_sig_hup_handler,
			       parent);
	if (!se) {
		exit_server("failed to setup SIGHUP handler");
	}

	/* Setup all the TDB's - including CLEAR_IF_FIRST tdb's. */

	if (smbd_memcache() == NULL) {
		exit(1);
	}

	memcache_set_global(smbd_memcache());

	/* Initialise the password backed before the global_sam_sid
	   to ensure that we fetch from ldap before we make a domain sid up */

	if(!initialize_password_db(false, ev_ctx))
		exit(1);

	if (!secrets_init()) {
		DEBUG(0, ("ERROR: smbd can not open secrets.tdb\n"));
		exit(1);
	}

	if (lp_server_role() == ROLE_DOMAIN_BDC || lp_server_role() == ROLE_DOMAIN_PDC) {
		struct loadparm_context *lp_ctx = loadparm_init_s3(NULL, loadparm_s3_helpers());
		if (!open_schannel_session_store(NULL, lp_ctx)) {
			DEBUG(0,("ERROR: Samba cannot open schannel store for secured NETLOGON operations.\n"));
			exit(1);
		}
		TALLOC_FREE(lp_ctx);
	}

	if(!get_global_sam_sid()) {
		DEBUG(0,("ERROR: Samba cannot create a SAM SID.\n"));
		exit(1);
	}

	server_id = messaging_server_id(msg_ctx);
	status = smbXsrv_version_global_init(&server_id);
	if (!NT_STATUS_IS_OK(status)) {
		exit(1);
	}

	status = smbXsrv_session_global_init();
	if (!NT_STATUS_IS_OK(status)) {
		exit(1);
	}

	status = smbXsrv_tcon_global_init();
	if (!NT_STATUS_IS_OK(status)) {
		exit(1);
	}

	if (!locking_init())
		exit(1);

	if (!messaging_tdb_parent_init(ev_ctx)) {
		exit(1);
	}

	if (!smbd_parent_notify_init(NULL, msg_ctx, ev_ctx)) {
		exit(1);
	}

	if (!smbd_scavenger_init(NULL, msg_ctx, ev_ctx)) {
		exit(1);
	}

	if (!serverid_parent_init(ev_ctx)) {
		exit(1);
	}

	if (!W_ERROR_IS_OK(registry_init_full()))
		exit(1);

	/* Open the share_info.tdb here, so we don't have to open
	   after the fork on every single connection.  This is a small
	   performance improvment and reduces the total number of system
	   fds used. */
	if (!share_info_db_init()) {
		DEBUG(0,("ERROR: failed to load share info db.\n"));
		exit(1);
	}

	status = init_system_session_info();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("ERROR: failed to setup system user info: %s.\n",
			  nt_errstr(status)));
		return -1;
	}

	if (!init_guest_info()) {
		DEBUG(0,("ERROR: failed to setup guest info.\n"));
		return -1;
	}

	if (!file_init_global()) {
		DEBUG(0, ("ERROR: file_init_global() failed\n"));
		return -1;
	}
	status = smbXsrv_open_global_init();
	if (!NT_STATUS_IS_OK(status)) {
		exit(1);
	}

	/* This MUST be done before start_epmd() because otherwise
	 * start_epmd() forks and races against dcesrv_ep_setup() to
	 * call directory_create_or_exist() */
	if (!directory_create_or_exist(lp_ncalrpc_dir(), geteuid(), 0755)) {
		DEBUG(0, ("Failed to create pipe directory %s - %s\n",
			  lp_ncalrpc_dir(), strerror(errno)));
		return -1;
	}

	np_dir = talloc_asprintf(talloc_tos(), "%s/np", lp_ncalrpc_dir());
	if (!np_dir) {
		DEBUG(0, ("%s: Out of memory\n", __location__));
		return -1;
	}

	if (!directory_create_or_exist(np_dir, geteuid(), 0700)) {
		DEBUG(0, ("Failed to create pipe directory %s - %s\n",
			  np_dir, strerror(errno)));
		return -1;
	}

	if (is_daemon && !interactive) {
		if (rpc_epmapper_daemon() == RPC_DAEMON_FORK) {
			start_epmd(ev_ctx, msg_ctx);
		}
	}

	if (!dcesrv_ep_setup(ev_ctx, msg_ctx)) {
		exit(1);
	}

	/* only start other daemons if we are running as a daemon
	 * -- bad things will happen if smbd is launched via inetd
	 *  and we fork a copy of ourselves here */
	if (is_daemon && !interactive) {

		if (rpc_lsasd_daemon() == RPC_DAEMON_FORK) {
			start_lsasd(ev_ctx, msg_ctx);
		}

		if (!lp__disable_spoolss() &&
		    (rpc_spoolss_daemon() != RPC_DAEMON_DISABLED)) {
			bool bgq = lp_parm_bool(-1, "smbd", "backgroundqueue", true);

			if (!printing_subsystem_init(ev_ctx, msg_ctx, true, bgq)) {
				exit(1);
			}
		}
	} else if (!lp__disable_spoolss() &&
		   (rpc_spoolss_daemon() != RPC_DAEMON_DISABLED)) {
		if (!printing_subsystem_init(ev_ctx, msg_ctx, false, false)) {
			exit(1);
		}
	}

	if (!is_daemon) {
		int sock;

		/* inetd mode */
		TALLOC_FREE(frame);

		/* Started from inetd. fd 0 is the socket. */
		/* We will abort gracefully when the client or remote system
		   goes away */
		sock = dup(0);

		/* close stdin, stdout (if not logging to it), but not stderr */
		close_low_fds(true, !debug_get_output_is_stdout(), false);

#ifdef HAVE_ATEXIT
		atexit(killkids);
#endif

	        /* Stop zombies */
		smbd_setup_sig_chld_handler(parent);

		smbd_process(ev_ctx, msg_ctx, sock, true);

		exit_server_cleanly(NULL);
		return(0);
	}

	if (!open_sockets_smbd(parent, ev_ctx, msg_ctx, ports))
		exit_server("open_sockets_smbd() failed");

	/* do a printer update now that all messaging has been set up,
	 * before we allow clients to start connecting */
	if (!lp__disable_spoolss() &&
	    (rpc_spoolss_daemon() != RPC_DAEMON_DISABLED)) {
		printing_subsystem_update(ev_ctx, msg_ctx, false);
	}

	TALLOC_FREE(frame);
	/* make sure we always have a valid stackframe */
	frame = talloc_stackframe();

	if (!Fork) {
		/* if we are running in the foreground then look for
		   EOF on stdin, and exit if it happens. This allows
		   us to die if the parent process dies
		   Only do this on a pipe or socket, no other device.
		*/
		struct stat st;
		if (fstat(0, &st) != 0) {
			return false;
		}
		if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
			tevent_add_fd(ev_ctx,
					parent,
					0,
					TEVENT_FD_READ,
					smbd_stdin_handler,
					NULL);
		}
	}

	smbd_parent_loop(ev_ctx, parent);

	exit_server_cleanly(NULL);
	TALLOC_FREE(frame);
	return(0);
}
