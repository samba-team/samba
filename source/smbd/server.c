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

static_decl_rpc;

static int am_parent = 1;

extern struct auth_context *negprot_global_auth_context;
extern SIG_ATOMIC_T got_sig_term;
extern SIG_ATOMIC_T reload_after_sighup;
static SIG_ATOMIC_T got_sig_cld;

#ifdef WITH_DFS
extern int dcelogin_atmost_once;
#endif /* WITH_DFS */

/* really we should have a top level context structure that has the
   client file descriptor as an element. That would require a major rewrite :(

   the following 2 functions are an alternative - they make the file
   descriptor private to smbd
 */
static int server_fd = -1;

int smbd_server_fd(void)
{
	return server_fd;
}

static void smbd_set_server_fd(int fd)
{
	server_fd = fd;
}

int get_client_fd(void)
{
	return server_fd;
}

#ifdef CLUSTER_SUPPORT
static int client_get_tcp_info(struct sockaddr_storage *server,
			       struct sockaddr_storage *client)
{
	socklen_t length;
	if (server_fd == -1) {
		return -1;
	}
	length = sizeof(*server);
	if (getsockname(server_fd, (struct sockaddr *)server, &length) != 0) {
		return -1;
	}
	length = sizeof(*client);
	if (getpeername(server_fd, (struct sockaddr *)client, &length) != 0) {
		return -1;
	}
	return 0;
}
#endif

struct event_context *smbd_event_context(void)
{
	static struct event_context *ctx;

	if (!ctx && !(ctx = event_context_init(talloc_autofree_context()))) {
		smb_panic("Could not init smbd event context");
	}
	return ctx;
}

struct messaging_context *smbd_messaging_context(void)
{
	static struct messaging_context *ctx;

	if (ctx == NULL) {
		ctx = messaging_init(talloc_autofree_context(), server_id_self(),
				     smbd_event_context());
	}
	if (ctx == NULL) {
		DEBUG(0, ("Could not init smbd messaging context.\n"));
	}
	return ctx;
}

struct memcache *smbd_memcache(void)
{
	static struct memcache *cache;

	if (!cache
	    && !(cache = memcache_init(talloc_autofree_context(),
				       lp_max_stat_cache_size()*1024))) {

		smb_panic("Could not init smbd memcache");
	}
	return cache;
}

/*******************************************************************
 What to do when smb.conf is updated.
 ********************************************************************/

static void smb_conf_updated(struct messaging_context *msg,
			     void *private_data,
			     uint32_t msg_type,
			     struct server_id server_id,
			     DATA_BLOB *data)
{
	DEBUG(10,("smb_conf_updated: Got message saying smb.conf was "
		  "updated. Reloading.\n"));
	reload_services(False);
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
 Terminate signal.
****************************************************************************/

static void sig_term(void)
{
	got_sig_term = 1;
	sys_select_signal(SIGTERM);
}

/****************************************************************************
 Catch a sighup.
****************************************************************************/

static void sig_hup(int sig)
{
	reload_after_sighup = 1;
	sys_select_signal(SIGHUP);
}

/****************************************************************************
 Catch a sigcld
****************************************************************************/
static void sig_cld(int sig)
{
	got_sig_cld = 1;
	sys_select_signal(SIGCLD);
}

/****************************************************************************
  Send a SIGTERM to our process group.
*****************************************************************************/

static void  killkids(void)
{
	if(am_parent) kill(0,SIGTERM);
}

/****************************************************************************
 Process a sam sync message - not sure whether to do this here or
 somewhere else.
****************************************************************************/

static void msg_sam_sync(struct messaging_context *msg,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id server_id,
			 DATA_BLOB *data)
{
        DEBUG(10, ("** sam sync message received, ignoring\n"));
}


/****************************************************************************
 Open the socket communication - inetd.
****************************************************************************/

static bool open_sockets_inetd(void)
{
	/* Started from inetd. fd 0 is the socket. */
	/* We will abort gracefully when the client or remote system 
	   goes away */
	smbd_set_server_fd(dup(0));
	
	/* close our standard file descriptors */
	close_low_fds(False); /* Don't close stderr */
	
	set_socket_options(smbd_server_fd(),"SO_KEEPALIVE");
	set_socket_options(smbd_server_fd(), lp_socket_options());

	return True;
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

	kill(sys_getpid(), sig);
}
#endif /* DEVELOPER */

struct child_pid {
	struct child_pid *prev, *next;
	pid_t pid;
};

static struct child_pid *children;
static int num_children;

static void add_child_pid(pid_t pid)
{
	struct child_pid *child;

	if (lp_max_smbd_processes() == 0) {
		/* Don't bother with the child list if we don't care anyway */
		return;
	}

	child = SMB_MALLOC_P(struct child_pid);
	if (child == NULL) {
		DEBUG(0, ("Could not add child struct -- malloc failed\n"));
		return;
	}
	child->pid = pid;
	DLIST_ADD(children, child);
	num_children += 1;
}

static void remove_child_pid(pid_t pid, bool unclean_shutdown)
{
	struct child_pid *child;

	if (unclean_shutdown) {
		/* a child terminated uncleanly so tickle all processes to see 
		   if they can grab any of the pending locks
		*/
		DEBUG(3,(__location__ " Unclean shutdown of pid %u\n", (unsigned int)pid));
		messaging_send_buf(smbd_messaging_context(), procid_self(), 
				   MSG_SMB_BRL_VALIDATE, NULL, 0);
		message_send_all(smbd_messaging_context(), 
				 MSG_SMB_UNLOCK, NULL, 0, NULL);
	}

	if (lp_max_smbd_processes() == 0) {
		/* Don't bother with the child list if we don't care anyway */
		return;
	}

	for (child = children; child != NULL; child = child->next) {
		if (child->pid == pid) {
			struct child_pid *tmp = child;
			DLIST_REMOVE(children, child);
			SAFE_FREE(tmp);
			num_children -= 1;
			return;
		}
	}

	DEBUG(0, ("Could not find child %d -- ignoring\n", (int)pid));
}

/****************************************************************************
 Have we reached the process limit ?
****************************************************************************/

static bool allowable_number_of_smbd_processes(void)
{
	int max_processes = lp_max_smbd_processes();

	if (!max_processes)
		return True;

	return num_children < max_processes;
}

/****************************************************************************
 Open the socket communication.
****************************************************************************/

static bool open_sockets_smbd(bool is_daemon, bool interactive, const char *smb_ports)
{
	int num_interfaces = iface_count();
	int num_sockets = 0;
	int fd_listenset[FD_SETSIZE];
	fd_set listen_set;
	int s;
	int maxfd = 0;
	int i;
	char *ports;
	struct dns_reg_state * dns_reg = NULL;
	unsigned dns_port = 0;

	if (!is_daemon) {
		return open_sockets_inetd();
	}

#ifdef HAVE_ATEXIT
	{
		static int atexit_set;
		if(atexit_set == 0) {
			atexit_set=1;
			atexit(killkids);
		}
	}
#endif

	/* Stop zombies */
	CatchSignal(SIGCLD, sig_cld);

	FD_ZERO(&listen_set);

	/* use a reasonable default set of ports - listing on 445 and 139 */
	if (!smb_ports) {
		ports = lp_smb_ports();
		if (!ports || !*ports) {
			ports = smb_xstrdup(SMB_PORTS);
		} else {
			ports = smb_xstrdup(ports);
		}
	} else {
		ports = smb_xstrdup(smb_ports);
	}

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		/* We have been given an interfaces line, and been
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/

		/* Now open a listen socket for each of the
		   interfaces. */
		for(i = 0; i < num_interfaces; i++) {
			TALLOC_CTX *frame = NULL;
			const struct sockaddr_storage *ifss =
					iface_n_sockaddr_storage(i);
			char *tok;
			const char *ptr;

			if (ifss == NULL) {
				DEBUG(0,("open_sockets_smbd: "
					"interface %d has NULL IP address !\n",
					i));
				continue;
			}

			frame = talloc_stackframe();
			for (ptr=ports;
					next_token_talloc(frame,&ptr, &tok, " \t,");) {
				unsigned port = atoi(tok);
				if (port == 0 || port > 0xffff) {
					continue;
				}

				/* Keep the first port for mDNS service
				 * registration.
				 */
				if (dns_port == 0) {
					dns_port = port;
				}

				s = fd_listenset[num_sockets] =
					open_socket_in(SOCK_STREAM,
							port,
							num_sockets == 0 ? 0 : 2,
							ifss,
							true);
				if(s == -1) {
					continue;
				}

				/* ready to listen */
				set_socket_options(s,"SO_KEEPALIVE");
				set_socket_options(s,lp_socket_options());

				/* Set server socket to
				 * non-blocking for the accept. */
				set_blocking(s,False);

				if (listen(s, SMBD_LISTEN_BACKLOG) == -1) {
					DEBUG(0,("open_sockets_smbd: listen: "
						"%s\n", strerror(errno)));
					close(s);
					TALLOC_FREE(frame);
					return False;
				}
				FD_SET(s,&listen_set);
				maxfd = MAX( maxfd, s);

				num_sockets++;
				if (num_sockets >= FD_SETSIZE) {
					DEBUG(0,("open_sockets_smbd: Too "
						"many sockets to bind to\n"));
					TALLOC_FREE(frame);
					return False;
				}
			}
			TALLOC_FREE(frame);
		}
	} else {
		/* Just bind to 0.0.0.0 - accept connections
		   from anywhere. */

		TALLOC_CTX *frame = talloc_stackframe();
		char *tok;
		const char *ptr;
		const char *sock_addr = lp_socket_address();
		char *sock_tok;
		const char *sock_ptr;

		if (strequal(sock_addr, "0.0.0.0") ||
		    strequal(sock_addr, "::")) {
#if HAVE_IPV6
			sock_addr = "::,0.0.0.0";
#else
			sock_addr = "0.0.0.0";
#endif
		}

		for (sock_ptr=sock_addr;
				next_token_talloc(frame, &sock_ptr, &sock_tok, " \t,"); ) {
			for (ptr=ports; next_token_talloc(frame, &ptr, &tok, " \t,"); ) {
				struct sockaddr_storage ss;

				unsigned port = atoi(tok);
				if (port == 0 || port > 0xffff) {
					continue;
				}

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

				s = open_socket_in(SOCK_STREAM,
						port,
						num_sockets == 0 ? 0 : 2,
						&ss,
						true);
				if (s == -1) {
					continue;
				}

				/* ready to listen */
				set_socket_options(s,"SO_KEEPALIVE");
				set_socket_options(s,lp_socket_options());

				/* Set server socket to non-blocking
				 * for the accept. */
				set_blocking(s,False);

				if (listen(s, SMBD_LISTEN_BACKLOG) == -1) {
					DEBUG(0,("open_sockets_smbd: "
						"listen: %s\n",
						 strerror(errno)));
					close(s);
					TALLOC_FREE(frame);
					return False;
				}

				fd_listenset[num_sockets] = s;
				FD_SET(s,&listen_set);
				maxfd = MAX( maxfd, s);

				num_sockets++;

				if (num_sockets >= FD_SETSIZE) {
					DEBUG(0,("open_sockets_smbd: Too "
						"many sockets to bind to\n"));
					TALLOC_FREE(frame);
					return False;
				}
			}
		}
		TALLOC_FREE(frame);
	}

	SAFE_FREE(ports);

	if (num_sockets == 0) {
		DEBUG(0,("open_sockets_smbd: No "
			"sockets available to bind to.\n"));
		return false;
	}

	/* Setup the main smbd so that we can get messages. Note that
	   do this after starting listening. This is needed as when in
	   clustered mode, ctdb won't allow us to start doing database
	   operations until it has gone thru a full startup, which
	   includes checking to see that smbd is listening. */
	claim_connection(NULL,"",
			 FLAG_MSG_GENERAL|FLAG_MSG_SMBD|FLAG_MSG_DBWRAP);

        /* Listen to messages */

	messaging_register(smbd_messaging_context(), NULL,
			   MSG_SMB_SAM_SYNC, msg_sam_sync);
	messaging_register(smbd_messaging_context(), NULL,
			   MSG_SHUTDOWN, msg_exit_server);
	messaging_register(smbd_messaging_context(), NULL,
			   MSG_SMB_FILE_RENAME, msg_file_was_renamed);
	messaging_register(smbd_messaging_context(), NULL,
			   MSG_SMB_CONF_UPDATED, smb_conf_updated);
	messaging_register(smbd_messaging_context(), NULL,
			   MSG_SMB_STAT_CACHE_DELETE, smb_stat_cache_delete);
	brl_register_msgs(smbd_messaging_context());

#ifdef CLUSTER_SUPPORT
	if (lp_clustering()) {
		ctdbd_register_reconfigure(messaging_ctdbd_connection());
	}
#endif

#ifdef DEVELOPER
	messaging_register(smbd_messaging_context(), NULL,
			   MSG_SMB_INJECT_FAULT, msg_inject_fault);
#endif

	/* now accept incoming connections - forking a new process
	   for each incoming connection */
	DEBUG(2,("waiting for a connection\n"));
	while (1) {
		struct timeval now, idle_timeout;
		fd_set r_fds, w_fds;
		int num;

		/* Ensure we respond to PING and DEBUG messages from the main smbd. */
		message_dispatch(smbd_messaging_context());

		if (got_sig_cld) {
			pid_t pid;
			int status;

			got_sig_cld = False;

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
				remove_child_pid(pid, unclean_shutdown);
			}
		}

		idle_timeout = timeval_zero();

		memcpy((char *)&r_fds, (char *)&listen_set,
		       sizeof(listen_set));
		FD_ZERO(&w_fds);
		GetTimeOfDay(&now);

		/* Kick off our mDNS registration. */
		if (dns_port != 0) {
			dns_register_smbd(&dns_reg, dns_port, &maxfd,
					&r_fds, &idle_timeout);
		}

		event_add_to_select_args(smbd_event_context(), &now,
					 &r_fds, &w_fds, &idle_timeout,
					 &maxfd);

		num = sys_select(maxfd+1,&r_fds,&w_fds,NULL,
				 timeval_is_zero(&idle_timeout) ?
				 NULL : &idle_timeout);

		if (num == -1 && errno == EINTR) {
			if (got_sig_term) {
				exit_server_cleanly(NULL);
			}

			/* check for sighup processing */
			if (reload_after_sighup) {
				change_to_root_user();
				DEBUG(1,("Reloading services after SIGHUP\n"));
				reload_services(False);
				reload_after_sighup = 0;
			}

			continue;
		}
		

		/* If the idle timeout fired and we don't have any connected
		 * users, exit gracefully. We should be running under a process
		 * controller that will restart us if necessry.
		 */
		if (num == 0 && count_all_current_connections() == 0) {
			exit_server_cleanly("idle timeout");
		}

		/* process pending nDNS responses */
		if (dns_register_smbd_reply(dns_reg, &r_fds, &idle_timeout)) {
			--num;
		}

		if (run_events(smbd_event_context(), num, &r_fds, &w_fds)) {
			continue;
		}

		/* check if we need to reload services */
		check_reload(time(NULL));

		/* Find the sockets that are read-ready -
		   accept on these. */
		for( ; num > 0; num--) {
			struct sockaddr addr;
			socklen_t in_addrlen = sizeof(addr);
			pid_t child = 0;

			s = -1;
			for(i = 0; i < num_sockets; i++) {
				if(FD_ISSET(fd_listenset[i],&r_fds)) {
					s = fd_listenset[i];
					/* Clear this so we don't look
					   at it again. */
					FD_CLR(fd_listenset[i],&r_fds);
					break;
				}
			}

			smbd_set_server_fd(accept(s,&addr,&in_addrlen));

			if (smbd_server_fd() == -1 && errno == EINTR)
				continue;

			if (smbd_server_fd() == -1) {
				DEBUG(2,("open_sockets_smbd: accept: %s\n",
					 strerror(errno)));
				continue;
			}

			/* Ensure child is set to blocking mode */
			set_blocking(smbd_server_fd(),True);

			if (smbd_server_fd() != -1 && interactive)
				return True;

			if (allowable_number_of_smbd_processes() &&
			    smbd_server_fd() != -1 &&
			    ((child = sys_fork())==0)) {
				char remaddr[INET6_ADDRSTRLEN];

				/* Child code ... */

				/* Stop zombies, the parent explicitly handles
				 * them, counting worker smbds. */
				CatchChild();

				/* close the listening socket(s) */
				for(i = 0; i < num_sockets; i++)
					close(fd_listenset[i]);

				/* close our mDNS daemon handle */
				dns_register_close(&dns_reg);

				/* close our standard file
				   descriptors */
				close_low_fds(False);
				am_parent = 0;

				set_socket_options(smbd_server_fd(),"SO_KEEPALIVE");
				set_socket_options(smbd_server_fd(),
						   lp_socket_options());

				/* this is needed so that we get decent entries
				   in smbstatus for port 445 connects */
				set_remote_machine_name(get_peer_addr(smbd_server_fd(),
								remaddr,
								sizeof(remaddr)),
								false);

				if (!reinit_after_fork(
					    smbd_messaging_context(),
					    smbd_event_context(),
					    true)) {
					DEBUG(0,("reinit_after_fork() failed\n"));
					smb_panic("reinit_after_fork() failed");
				}

				return True;
			}
			/* The parent doesn't need this socket */
			close(smbd_server_fd());

			/* Sun May 6 18:56:14 2001 ackley@cs.unm.edu:
				Clear the closed fd info out of server_fd --
				and more importantly, out of client_fd in
				util_sock.c, to avoid a possible
				getpeername failure if we reopen the logs
				and use %I in the filename.
			*/

			smbd_set_server_fd(-1);

			if (child != 0) {
				add_child_pid(child);
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

		} /* end for num */
	} /* end while 1 */

/* NOTREACHED	return True; */
}

/****************************************************************************
 Reload printers
**************************************************************************/
void reload_printers(void)
{
	int snum;
	int n_services = lp_numservices();
	int pnum = lp_servicenumber(PRINTERS_NAME);
	const char *pname;

	pcap_cache_reload();

	/* remove stale printers */
	for (snum = 0; snum < n_services; snum++) {
		/* avoid removing PRINTERS_NAME or non-autoloaded printers */
		if (snum == pnum || !(lp_snum_ok(snum) && lp_print_ok(snum) &&
		                      lp_autoloaded(snum)))
			continue;

		pname = lp_printername(snum);
		if (!pcap_printername_ok(pname)) {
			DEBUG(3, ("removing stale printer %s\n", pname));

			if (is_printer_published(NULL, snum, NULL))
				nt_printer_publish(NULL, snum, SPOOL_DS_UNPUBLISH);
			del_a_printer(pname);
			lp_killservice(snum);
		}
	}

	load_printers();
}

/****************************************************************************
 Reload the services file.
**************************************************************************/

bool reload_services(bool test)
{
	bool ret;

	if (lp_loaded()) {
		char *fname = lp_configfile();
		if (file_exist(fname, NULL) &&
		    !strcsequal(fname, get_dyn_CONFIGFILE())) {
			set_dyn_CONFIGFILE(fname);
			test = False;
		}
	}

	reopen_logs();

	if (test && !lp_file_list_changed())
		return(True);

	lp_killunused(conn_snum_used);

	ret = lp_load(get_dyn_CONFIGFILE(), False, False, True, True);

	reload_printers();

	/* perhaps the config filename is now set */
	if (!test)
		reload_services(True);

	reopen_logs();

	load_interfaces();

	if (smbd_server_fd() != -1) {
		set_socket_options(smbd_server_fd(),"SO_KEEPALIVE");
		set_socket_options(smbd_server_fd(), lp_socket_options());
	}

	mangle_reset_cache();
	reset_stat_cache();

	/* this forces service parameters to be flushed */
	set_current_service(NULL,0,True);

	return(ret);
}

/****************************************************************************
 Exit the server.
****************************************************************************/

/* Reasons for shutting down a server process. */
enum server_exit_reason { SERVER_EXIT_NORMAL, SERVER_EXIT_ABNORMAL };

static void exit_server_common(enum server_exit_reason how,
	const char *const reason) NORETURN_ATTRIBUTE;

static void exit_server_common(enum server_exit_reason how,
	const char *const reason)
{
	static int firsttime=1;
	bool had_open_conn;

	if (!firsttime)
		exit(0);
	firsttime = 0;

	change_to_root_user();

	if (negprot_global_auth_context) {
		(negprot_global_auth_context->free)(&negprot_global_auth_context);
	}

	had_open_conn = conn_close_all();

	invalidate_all_vuids();

	/* 3 second timeout. */
	print_notify_send_messages(smbd_messaging_context(), 3);

	/* delete our entry in the connections database. */
	yield_connection(NULL,"");

	respond_to_all_remaining_local_messages();

#ifdef WITH_DFS
	if (dcelogin_atmost_once) {
		dfs_unlogin();
	}
#endif

#ifdef USE_DMAPI
	/* Destroy Samba DMAPI session only if we are master smbd process */
	if (am_parent) {
		if (!dmapi_destroy_session()) {
			DEBUG(0,("Unable to close Samba DMAPI session\n"));
		}
	}
#endif

	locking_end();
	printing_end();

	if (how != SERVER_EXIT_NORMAL) {
		int oldlevel = DEBUGLEVEL;

		DEBUGLEVEL = 10;

		DEBUGSEP(0);
		DEBUG(0,("Abnormal server exit: %s\n",
			reason ? reason : "no explanation provided"));
		DEBUGSEP(0);

		log_stack_trace();

		DEBUGLEVEL = oldlevel;
		dump_core();

	} else {    
		DEBUG(3,("Server exit (%s)\n",
			(reason ? reason : "normal exit")));
	}

	/* if we had any open SMB connections when we exited then we
	   need to tell the parent smbd so that it can trigger a retry
	   of any locks we may have been holding or open files we were
	   blocking */
	if (had_open_conn) {
		exit(1);
	} else {
		exit(0);
	}
}

void exit_server(const char *const explanation)
{
	exit_server_common(SERVER_EXIT_ABNORMAL, explanation);
}

void exit_server_cleanly(const char *const explanation)
{
	exit_server_common(SERVER_EXIT_NORMAL, explanation);
}

void exit_server_fault(void)
{
	exit_server("critical server fault");
}


/****************************************************************************
received when we should release a specific IP
****************************************************************************/
static void release_ip(const char *ip, void *priv)
{
	char addr[INET6_ADDRSTRLEN];

	if (strcmp(client_socket_addr(get_client_fd(),addr,sizeof(addr)), ip) == 0) {
		/* we can't afford to do a clean exit - that involves
		   database writes, which would potentially mean we
		   are still running after the failover has finished -
		   we have to get rid of this process ID straight
		   away */
		DEBUG(0,("Got release IP message for our IP %s - exiting immediately\n",
			ip));
		/* note we must exit with non-zero status so the unclean handler gets
		   called in the parent, so that the brl database is tickled */
		_exit(1);
	}
}

static void msg_release_ip(struct messaging_context *msg_ctx, void *private_data,
			   uint32_t msg_type, struct server_id server_id, DATA_BLOB *data)
{
	release_ip((char *)data->data, NULL);
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

	conn_init();

	file_init();

	/* for RPC pipes */
	init_rpc_pipe_hnd();

	init_dptrs();

	if (!secrets_init())
		return False;

	return True;
}

/*
 * Send keepalive packets to our client
 */
static bool keepalive_fn(const struct timeval *now, void *private_data)
{
	if (!send_keepalive(smbd_server_fd())) {
		DEBUG( 2, ( "Keepalive failed - exiting.\n" ) );
		return False;
	}
	return True;
}

/*
 * Do the recurring check if we're idle
 */
static bool deadtime_fn(const struct timeval *now, void *private_data)
{
	if ((conn_num_open() == 0)
	    || (conn_idle_all(now->tv_sec))) {
		DEBUG( 2, ( "Closing idle connection\n" ) );
		messaging_send(smbd_messaging_context(), procid_self(),
			       MSG_SHUTDOWN, &data_blob_null);
		return False;
	}

	return True;
}

/*
 * Do the recurring log file and smb.conf reload checks.
 */

static bool housekeeping_fn(const struct timeval *now, void *private_data)
{
	change_to_root_user();

	/* update printer queue caches if necessary */
	update_monitored_printq_cache();

	/* check if we need to reload services */
	check_reload(time(NULL));

	/* Change machine password if neccessary. */
	attempt_machine_password_change();

        /*
	 * Force a log file check.
	 */
        force_check_log_size();
        check_log_size();
	return true;
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
	static bool is_daemon = False;
	static bool interactive = False;
	static bool Fork = True;
	static bool no_process_group = False;
	static bool log_stdout = False;
	static char *ports = NULL;
	static char *profile_level = NULL;
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
	TALLOC_CTX *frame = talloc_stackframe(); /* Setup tos. */

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

	setup_logging(argv[0],log_stdout);

	if (print_build_options) {
		build_options(True); /* Display output to screen as well as debug */
		exit(0);
	}

	load_case_tables();

#ifdef HAVE_SETLUID
	/* needed for SecureWare on SCO */
	setluid(0);
#endif

	sec_init();

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

	/* make absolutely sure we run as root - to handle cases where people
	   are crazy enough to have it setuid */

	gain_root_privilege();
	gain_root_group_privilege();

	fault_setup((void (*)(void *))exit_server_fault);
	dump_core_setup("smbd");

	CatchSignal(SIGTERM , SIGNAL_CAST sig_term);
	CatchSignal(SIGHUP,SIGNAL_CAST sig_hup);
	
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

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	umask(0);

	init_sec_ctx();

	reopen_logs();

	DEBUG(0,("smbd version %s started.\n", SAMBA_VERSION_STRING));
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
		DEBUG(0, ("error opening config file\n"));
		exit(1);
	}

	if (smbd_messaging_context() == NULL)
		exit(1);

	if (!reload_services(False))
		return(-1);	

	init_structs();

#ifdef WITH_PROFILE
	if (!profile_setup(smbd_messaging_context(), False)) {
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

	DEBUG(3,( "loaded services\n"));

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
		become_daemon(Fork, no_process_group);
	}

#if HAVE_SETPGID
	/*
	 * If we're interactive we want to set our own process group for
	 * signal management.
	 */
	if (interactive && !no_process_group)
		setpgid( (pid_t)0, (pid_t)0);
#endif

	if (!directory_exist(lp_lockdir(), NULL))
		mkdir(lp_lockdir(), 0755);

	if (is_daemon)
		pidfile_create("smbd");

	if (!reinit_after_fork(smbd_messaging_context(),
			       smbd_event_context(), false)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		exit(1);
	}

	/* Setup all the TDB's - including CLEAR_IF_FIRST tdb's. */

	if (smbd_memcache() == NULL) {
		exit(1);
	}

	memcache_set_global(smbd_memcache());

	/* Initialise the password backed before the global_sam_sid
	   to ensure that we fetch from ldap before we make a domain sid up */

	if(!initialize_password_db(False, smbd_event_context()))
		exit(1);

	if (!secrets_init()) {
		DEBUG(0, ("ERROR: smbd can not open secrets.tdb\n"));
		exit(1);
	}

	if(!get_global_sam_sid()) {
		DEBUG(0,("ERROR: Samba cannot create a SAM SID.\n"));
		exit(1);
	}

	if (!session_init())
		exit(1);

	if (!connections_init(True))
		exit(1);

	if (!locking_init())
		exit(1);

	namecache_enable();

	if (!W_ERROR_IS_OK(registry_init_full()))
		exit(1);

#if 0
	if (!init_svcctl_db())
                exit(1);
#endif

	if (!print_backend_init(smbd_messaging_context()))
		exit(1);

	if (!init_guest_info()) {
		DEBUG(0,("ERROR: failed to setup guest info.\n"));
		return -1;
	}

	/* only start the background queue daemon if we are 
	   running as a daemon -- bad things will happen if
	   smbd is launched via inetd and we fork a copy of 
	   ourselves here */

	if (is_daemon && !interactive
	    && lp_parm_bool(-1, "smbd", "backgroundqueue", true)) {
		start_background_queue();
	}

	if (!open_sockets_smbd(is_daemon, interactive, ports))
		exit(1);

	/*
	 * everything after this point is run after the fork()
	 */ 

	static_init_rpc;

	init_modules();

	/* Possibly reload the services file. Only worth doing in
	 * daemon mode. In inetd mode, we know we only just loaded this.
	 */
	if (is_daemon) {
		reload_services(True);
	}

	if (!init_account_policy()) {
		DEBUG(0,("Could not open account policy tdb.\n"));
		exit(1);
	}

	if (*lp_rootdir()) {
		if (sys_chroot(lp_rootdir()) != 0) {
			DEBUG(0,("Failed to change root to %s\n", lp_rootdir()));
			exit(1);
		}
		if (chdir("/") == -1) {
			DEBUG(0,("Failed to chdir to / on chroot to %s\n", lp_rootdir()));
			exit(1);
		}
		DEBUG(0,("Changed root to %s\n", lp_rootdir()));
	}

	/* Setup oplocks */
	if (!init_oplocks(smbd_messaging_context()))
		exit(1);

	/* Setup aio signal handler. */
	initialize_async_io_handler();

	/* register our message handlers */
	messaging_register(smbd_messaging_context(), NULL,
			   MSG_SMB_FORCE_TDIS, msg_force_tdis);
	messaging_register(smbd_messaging_context(), NULL,
			   MSG_SMB_RELEASE_IP, msg_release_ip);
	messaging_register(smbd_messaging_context(), NULL,
			   MSG_SMB_CLOSE_FILE, msg_close_file);

	if ((lp_keepalive() != 0)
	    && !(event_add_idle(smbd_event_context(), NULL,
				timeval_set(lp_keepalive(), 0),
				"keepalive", keepalive_fn,
				NULL))) {
		DEBUG(0, ("Could not add keepalive event\n"));
		exit(1);
	}

	if (!(event_add_idle(smbd_event_context(), NULL,
			     timeval_set(IDLE_CLOSED_TIMEOUT, 0),
			     "deadtime", deadtime_fn, NULL))) {
		DEBUG(0, ("Could not add deadtime event\n"));
		exit(1);
	}

	if (!(event_add_idle(smbd_event_context(), NULL,
			     timeval_set(SMBD_SELECT_TIMEOUT, 0),
			     "housekeeping", housekeeping_fn, NULL))) {
		DEBUG(0, ("Could not add housekeeping event\n"));
		exit(1);
	}

#ifdef CLUSTER_SUPPORT

	if (lp_clustering()) {
		/*
		 * We need to tell ctdb about our client's TCP
		 * connection, so that for failover ctdbd can send
		 * tickle acks, triggering a reconnection by the
		 * client.
		 */

		struct sockaddr_storage srv, clnt;

		if (client_get_tcp_info(&srv, &clnt) == 0) {

			NTSTATUS status;

			status = ctdbd_register_ips(
				messaging_ctdbd_connection(),
				&srv, &clnt, release_ip, NULL);

			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0, ("ctdbd_register_ips failed: %s\n",
					  nt_errstr(status)));
			}
		} else
		{
			DEBUG(0,("Unable to get tcp info for "
				 "CTDB_CONTROL_TCP_CLIENT: %s\n",
				 strerror(errno)));
		}
	}

#endif

	TALLOC_FREE(frame);

	smbd_process();

	namecache_shutdown();

	exit_server_cleanly(NULL);
	return(0);
}
