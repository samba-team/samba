/*
   Unix SMB/CIFS implementation.

   Send messages to other Samba daemons

   Copyright (C) Tim Potter 2003
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Martin Pool 2001-2002
   Copyright (C) Simo Sorce 2002
   Copyright (C) James Peach 2006

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
#include "lib/util/server_id.h"
#include "popt_common.h"
#include "librpc/gen_ndr/spoolss.h"
#include "nt_printing.h"
#include "printing/notify.h"
#include "libsmb/nmblib.h"
#include "messages.h"
#include "util_tdb.h"
#include "../lib/util/pidfile.h"
#include "serverid.h"
#include "cmdline_contexts.h"

#ifdef HAVE_LIBUNWIND_H
#include <libunwind.h>
#endif

#ifdef HAVE_LIBUNWIND_PTRACE_H
#include <libunwind-ptrace.h>
#endif

#ifdef HAVE_SYS_PTRACE_H
#include <sys/ptrace.h>
#endif

/* Default timeout value when waiting for replies (in seconds) */

#define DEFAULT_TIMEOUT 10

static int timeout = DEFAULT_TIMEOUT;
static int num_replies;		/* Used by message callback fns */

/* Send a message to a destination pid.  Zero means broadcast smbd. */

static bool send_message(struct messaging_context *msg_ctx,
			 struct server_id pid, int msg_type,
			 const void *buf, int len)
{
	if (procid_to_pid(&pid) != 0)
		return NT_STATUS_IS_OK(
			messaging_send_buf(msg_ctx, pid, msg_type,
					   (const uint8_t *)buf, len));

	messaging_send_all(msg_ctx, msg_type, buf, len);

	return true;
}

static void smbcontrol_timeout(struct tevent_context *event_ctx,
			       struct tevent_timer *te,
			       struct timeval now,
			       void *private_data)
{
	bool *timed_out = (bool *)private_data;
	TALLOC_FREE(te);
	*timed_out = True;
}

/* Wait for one or more reply messages */

static void wait_replies(struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 bool multiple_replies)
{
	struct tevent_timer *te;
	bool timed_out = False;

	te = tevent_add_timer(ev_ctx, NULL,
			      timeval_current_ofs(timeout, 0),
			      smbcontrol_timeout, (void *)&timed_out);
	if (te == NULL) {
		DEBUG(0, ("tevent_add_timer failed\n"));
		return;
	}

	while (!timed_out) {
		int ret;
		if (num_replies > 0 && !multiple_replies)
			break;
		ret = tevent_loop_once(ev_ctx);
		if (ret != 0) {
			break;
		}
	}
}

/* Message handler callback that displays the PID and a string on stdout */

static void print_pid_string_cb(struct messaging_context *msg,
				void *private_data, 
				uint32_t msg_type, 
				struct server_id pid,
				DATA_BLOB *data)
{
	struct server_id_buf pidstr;

	printf("PID %s: %.*s", server_id_str_buf(pid, &pidstr),
	       (int)data->length, (const char *)data->data);
	num_replies++;
}

/* Send no message.  Useful for testing. */

static bool do_noop(struct tevent_context *ev_ctx,
		    struct messaging_context *msg_ctx,
		    const struct server_id pid,
		    const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> noop\n");
		return False;
	}

	/* Move along, nothing to see here */

	return True;
}

/* Send a debug string */

static bool do_debug(struct tevent_context *ev_ctx,
		     struct messaging_context *msg_ctx,
		     const struct server_id pid,
		     const int argc, const char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: smbcontrol <dest> debug "
			"<debug-string>\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_DEBUG, argv[1],
			    strlen(argv[1]) + 1);
}


static bool do_idmap(struct tevent_context *ev,
		     struct messaging_context *msg_ctx,
		     const struct server_id pid,
		     const int argc, const char **argv)
{
	static const char* usage = "Usage: "
		"smbcontrol <dest> idmap <cmd> [arg]\n"
		"\tcmd:"
		"\tdelete \"UID <uid>\"|\"GID <gid>\"|<sid>\n"
		"\t\tkill \"UID <uid>\"|\"GID <gid>\"|<sid>\n";
	const char* arg = NULL;
	int arglen = 0;
	int msg_type;

	switch (argc) {
	case 2:
		break;
	case 3:
		arg = argv[2];
		arglen = strlen(arg) + 1;
		break;
	default:
		fprintf(stderr, "%s", usage);
		return false;
	}

	if (strcmp(argv[1], "delete") == 0) {
		msg_type = ID_CACHE_DELETE;
	}
	else if (strcmp(argv[1], "kill") == 0) {
		msg_type = ID_CACHE_KILL;
	}
	else if (strcmp(argv[1], "help") == 0) {
		fprintf(stdout, "%s", usage);
		return true;
	}
	else {
		fprintf(stderr, "%s", usage);
		return false;
	}

	return send_message(msg_ctx, pid, msg_type, arg, arglen);
}


#if defined(HAVE_LIBUNWIND_PTRACE) && defined(HAVE_LINUX_PTRACE)

/* Return the name of a process given it's PID. This will only work on Linux,
 * but that's probably moot since this whole stack tracing implementation is
 * Linux-specific anyway.
 */
static const char * procname(pid_t pid, char * buf, size_t bufsz)
{
	char path[64];
	FILE * fp;

	snprintf(path, sizeof(path), "/proc/%llu/cmdline",
		(unsigned long long)pid);
	if ((fp = fopen(path, "r")) == NULL) {
		return NULL;
	}

	fgets(buf, bufsz, fp);

	fclose(fp);
	return buf;
}

static void print_stack_trace(pid_t pid, int * count)
{
	void *		    pinfo = NULL;
	unw_addr_space_t    aspace = NULL;
	unw_cursor_t	    cursor;
	unw_word_t	    ip, sp;

	char		    nbuf[256];
	unw_word_t	    off;

	int ret;

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		fprintf(stderr,
			"Failed to attach to process %llu: %s\n",
			(unsigned long long)pid, strerror(errno));
		return;
	}

	/* Wait until the attach is complete. */
	waitpid(pid, NULL, 0);

	if (((pinfo = _UPT_create(pid)) == NULL) ||
	    ((aspace = unw_create_addr_space(&_UPT_accessors, 0)) == NULL)) {
		/* Probably out of memory. */
		fprintf(stderr,
			"Unable to initialize stack unwind for process %llu\n",
			(unsigned long long)pid);
		goto cleanup;
	}

	if ((ret = unw_init_remote(&cursor, aspace, pinfo))) {
		fprintf(stderr,
			"Unable to unwind stack for process %llu: %s\n",
			(unsigned long long)pid, unw_strerror(ret));
		goto cleanup;
	}

	if (*count > 0) {
		printf("\n");
	}

	if (procname(pid, nbuf, sizeof(nbuf))) {
		printf("Stack trace for process %llu (%s):\n",
			(unsigned long long)pid, nbuf);
	} else {
		printf("Stack trace for process %llu:\n",
			(unsigned long long)pid);
	}

	while (unw_step(&cursor) > 0) {
		ip = sp = off = 0;
		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);

		ret = unw_get_proc_name(&cursor, nbuf, sizeof(nbuf), &off);
		if (ret != 0 && ret != -UNW_ENOMEM) {
			snprintf(nbuf, sizeof(nbuf), "<unknown symbol>");
		}
		printf("    %s + %#llx [ip=%#llx] [sp=%#llx]\n",
			nbuf, (long long)off, (long long)ip,
			(long long)sp);
	}

	(*count)++;

cleanup:
	if (aspace) {
		unw_destroy_addr_space(aspace);
	}

	if (pinfo) {
		_UPT_destroy(pinfo);
	}

	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

static int stack_trace_server(pid_t pid, void *priv)
{
	print_stack_trace(pid, (int *)priv);
	return 0;
}

static bool do_daemon_stack_trace(struct tevent_context *ev_ctx,
				  struct messaging_context *msg_ctx,
				  const struct server_id pid,
				  const int argc, const char **argv)
{
	pid_t	dest;
	int	count = 0;

	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> stacktrace\n");
		return False;
	}

	dest = procid_to_pid(&pid);

	if (dest != 0) {
		/* It would be nice to be able to make sure that this PID is
		 * the PID of a smbd/winbind/nmbd process, not some random PID
		 * the user liked the look of. It doesn't seem like it's worth
		 * the effort at the moment, however.
		 */
		print_stack_trace(dest, &count);
	} else {
		messaging_dgm_forall(stack_trace_server, &count);
	}

	return True;
}

#else /* defined(HAVE_LIBUNWIND_PTRACE) && defined(HAVE_LINUX_PTRACE) */

static bool do_daemon_stack_trace(struct tevent_context *ev_ctx,
				  struct messaging_context *msg_ctx,
				  const struct server_id pid,
				  const int argc, const char **argv)
{
	fprintf(stderr,
		"Daemon stack tracing is not supported on this platform\n");
	return False;
}

#endif /* defined(HAVE_LIBUNWIND_PTRACE) && defined(HAVE_LINUX_PTRACE) */

/* Inject a fault (fatal signal) into a running smbd */

static bool do_inject_fault(struct tevent_context *ev_ctx,
			    struct messaging_context *msg_ctx,
			    const struct server_id pid,
			    const int argc, const char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: smbcontrol <dest> inject "
			"<bus|hup|term|internal|segv>\n");
		return False;
	}

#if !defined(DEVELOPER) && !defined(ENABLE_SELFTEST)
	fprintf(stderr, "Fault injection is only available in "
		"developer and self test builds\n");
	return False;
#else /* DEVELOPER || ENABLE_SELFTEST */
	{
		int sig = 0;

		if (strcmp(argv[1], "bus") == 0) {
			sig = SIGBUS;
		} else if (strcmp(argv[1], "hup") == 0) {
			sig = SIGHUP;
		} else if (strcmp(argv[1], "term") == 0) {
			sig = SIGTERM;
		} else if (strcmp(argv[1], "segv") == 0) {
			sig = SIGSEGV;
		} else if (strcmp(argv[1], "internal") == 0) {
			/* Force an internal error, ie. an unclean exit. */
			sig = -1;
		} else {
			fprintf(stderr, "Unknown signal name '%s'\n", argv[1]);
			return False;
		}

		return send_message(msg_ctx, pid, MSG_SMB_INJECT_FAULT,
				    &sig, sizeof(int));
	}
#endif /* DEVELOPER || ENABLE_SELFTEST */
}

static bool do_sleep(struct tevent_context *ev_ctx,
		     struct messaging_context *msg_ctx,
		     const struct server_id pid,
		     const int argc, const char **argv)
{
#if defined(DEVELOPER) || defined(ENABLE_SELFTEST)
	unsigned int seconds;
	long input;
	const long MAX_SLEEP = 60 * 60; /* One hour maximum sleep */
#endif

	if (argc != 2) {
		fprintf(stderr, "Usage: smbcontrol <dest> sleep seconds\n");
		return False;
	}

#if !defined(DEVELOPER) && !defined(ENABLE_SELFTEST)
	fprintf(stderr, "Sleep is only available in "
		"developer and self test builds\n");
	return False;
#else /* DEVELOPER || ENABLE_SELFTEST */

	input = atol(argv[1]);
	if (input < 1 || input > MAX_SLEEP) {
		fprintf(stderr,
			"Invalid duration for sleep '%s'\n"
			"It should be at least 1 second and no more than %ld\n",
			argv[1],
			MAX_SLEEP);
		return False;
	}
	seconds = input;
	return send_message(msg_ctx, pid,
			    MSG_SMB_SLEEP,
			    &seconds,
			    sizeof(unsigned int));
#endif /* DEVELOPER || ENABLE_SELFTEST */
}

/* Force a browser election */

static bool do_election(struct tevent_context *ev_ctx,
			struct messaging_context *msg_ctx,
			const struct server_id pid,
			const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> force-election\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_FORCE_ELECTION, NULL, 0);
}

/* Ping a samba daemon process */

static void pong_cb(struct messaging_context *msg,
		    void *private_data, 
		    uint32_t msg_type, 
		    struct server_id pid,
		    DATA_BLOB *data)
{
	struct server_id_buf src_string;
	printf("PONG from pid %s\n", server_id_str_buf(pid, &src_string));
	num_replies++;
}

static bool do_ping(struct tevent_context *ev_ctx,
		    struct messaging_context *msg_ctx,
		    const struct server_id pid,
		    const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> ping\n");
		return False;
	}

	/* Send a message and register our interest in a reply */

	if (!send_message(msg_ctx, pid, MSG_PING, NULL, 0))
		return False;

	messaging_register(msg_ctx, NULL, MSG_PONG, pong_cb);

	wait_replies(ev_ctx, msg_ctx, procid_to_pid(&pid) == 0);

	/* No replies were received within the timeout period */

	if (num_replies == 0)
		printf("No replies received\n");

	messaging_deregister(msg_ctx, MSG_PONG, NULL);

	return num_replies;
}

/* Set profiling options */

static bool do_profile(struct tevent_context *ev_ctx,
		       struct messaging_context *msg_ctx,
		       const struct server_id pid,
		       const int argc, const char **argv)
{
	int v;

	if (argc != 2) {
		fprintf(stderr, "Usage: smbcontrol <dest> profile "
			"<off|count|on|flush>\n");
		return False;
	}

	if (strcmp(argv[1], "off") == 0) {
		v = 0;
	} else if (strcmp(argv[1], "count") == 0) {
		v = 1;
	} else if (strcmp(argv[1], "on") == 0) {
		v = 2;
	} else if (strcmp(argv[1], "flush") == 0) {
		v = 3;
	} else {
		fprintf(stderr, "Unknown profile command '%s'\n", argv[1]);
		return False;
	}

	return send_message(msg_ctx, pid, MSG_PROFILE, &v, sizeof(int));
}

/* Return the profiling level */

static void profilelevel_cb(struct messaging_context *msg_ctx,
			    void *private_data, 
			    uint32_t msg_type, 
			    struct server_id pid,
			    DATA_BLOB *data)
{
	int level;
	const char *s;

	num_replies++;

	if (data->length != sizeof(int)) {
		fprintf(stderr, "invalid message length %ld returned\n", 
			(unsigned long)data->length);
		return;
	}

	memcpy(&level, data->data, sizeof(int));

	switch (level) {
	case 0:
		s = "not enabled";
		break;
	case 1:
		s = "off";
		break;
	case 3:
		s = "count only";
		break;
	case 7:
		s = "count and time";
		break;
	default:
		s = "BOGUS";
		break;
	}

	printf("Profiling %s on pid %u\n",s,(unsigned int)procid_to_pid(&pid));
}

static void profilelevel_rqst(struct messaging_context *msg_ctx,
			      void *private_data, 
			      uint32_t msg_type, 
			      struct server_id pid,
			      DATA_BLOB *data)
{
	int v = 0;

	/* Send back a dummy reply */

	send_message(msg_ctx, pid, MSG_PROFILELEVEL, &v, sizeof(int));
}

static bool do_profilelevel(struct tevent_context *ev_ctx,
			    struct messaging_context *msg_ctx,
			    const struct server_id pid,
			    const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> profilelevel\n");
		return False;
	}

	/* Send a message and register our interest in a reply */

	if (!send_message(msg_ctx, pid, MSG_REQ_PROFILELEVEL, NULL, 0))
		return False;

	messaging_register(msg_ctx, NULL, MSG_PROFILELEVEL, profilelevel_cb);
	messaging_register(msg_ctx, NULL, MSG_REQ_PROFILELEVEL,
			   profilelevel_rqst);

	wait_replies(ev_ctx, msg_ctx, procid_to_pid(&pid) == 0);

	/* No replies were received within the timeout period */

	if (num_replies == 0)
		printf("No replies received\n");

	messaging_deregister(msg_ctx, MSG_PROFILE, NULL);

	return num_replies;
}

/* Display debug level settings */

static bool do_debuglevel(struct tevent_context *ev_ctx,
			  struct messaging_context *msg_ctx,
			  const struct server_id pid,
			  const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> debuglevel\n");
		return False;
	}

	/* Send a message and register our interest in a reply */

	if (!send_message(msg_ctx, pid, MSG_REQ_DEBUGLEVEL, NULL, 0))
		return False;

	messaging_register(msg_ctx, NULL, MSG_DEBUGLEVEL, print_pid_string_cb);

	wait_replies(ev_ctx, msg_ctx, procid_to_pid(&pid) == 0);

	/* No replies were received within the timeout period */

	if (num_replies == 0)
		printf("No replies received\n");

	messaging_deregister(msg_ctx, MSG_DEBUGLEVEL, NULL);

	return num_replies;
}

/* Send a print notify message */

static bool do_printnotify(struct tevent_context *ev_ctx,
			   struct messaging_context *msg_ctx,
			   const struct server_id pid,
			   const int argc, const char **argv)
{
	const char *cmd;

	/* Check for subcommand */

	if (argc == 1) {
		fprintf(stderr, "Must specify subcommand:\n");
		fprintf(stderr, "\tqueuepause <printername>\n");
		fprintf(stderr, "\tqueueresume <printername>\n");
		fprintf(stderr, "\tjobpause <printername> <unix jobid>\n");
		fprintf(stderr, "\tjobresume <printername> <unix jobid>\n");
		fprintf(stderr, "\tjobdelete <printername> <unix jobid>\n");
		fprintf(stderr, "\tprinter <printername> <comment|port|"
			"driver> <value>\n");

		return False;
	}

	cmd = argv[1];

	if (strcmp(cmd, "queuepause") == 0) {

		if (argc != 3) {
			fprintf(stderr, "Usage: smbcontrol <dest> printnotify"
				" queuepause <printername>\n");
			return False;
		}

		notify_printer_status_byname(ev_ctx, msg_ctx, argv[2],
					     PRINTER_STATUS_PAUSED);

		goto send;

	} else if (strcmp(cmd, "queueresume") == 0) {

		if (argc != 3) {
			fprintf(stderr, "Usage: smbcontrol <dest> printnotify"
				" queuereume <printername>\n");
			return False;
		}

		notify_printer_status_byname(ev_ctx, msg_ctx, argv[2],
					     PRINTER_STATUS_OK);

		goto send;

	} else if (strcmp(cmd, "jobpause") == 0) {
		int jobid;

		if (argc != 4) {
			fprintf(stderr, "Usage: smbcontrol <dest> printnotify"
				" jobpause <printername> <unix-jobid>\n");
			return False;
		}

		jobid = atoi(argv[3]);

		notify_job_status_byname(
			ev_ctx, msg_ctx,
			argv[2], jobid, JOB_STATUS_PAUSED,
			SPOOLSS_NOTIFY_MSG_UNIX_JOBID);

		goto send;

	} else if (strcmp(cmd, "jobresume") == 0) {
		int jobid;

		if (argc != 4) {
			fprintf(stderr, "Usage: smbcontrol <dest> printnotify"
				" jobpause <printername> <unix-jobid>\n");
			return False;
		}

		jobid = atoi(argv[3]);

		notify_job_status_byname(
			ev_ctx, msg_ctx,
			argv[2], jobid, JOB_STATUS_QUEUED, 
			SPOOLSS_NOTIFY_MSG_UNIX_JOBID);

		goto send;

	} else if (strcmp(cmd, "jobdelete") == 0) {
		int jobid;

		if (argc != 4) {
			fprintf(stderr, "Usage: smbcontrol <dest> printnotify"
				" jobpause <printername> <unix-jobid>\n");
			return False;
		}

		jobid = atoi(argv[3]);

		notify_job_status_byname(
			ev_ctx, msg_ctx,
			argv[2], jobid, JOB_STATUS_DELETING,
			SPOOLSS_NOTIFY_MSG_UNIX_JOBID);

		notify_job_status_byname(
			ev_ctx, msg_ctx,
			argv[2], jobid, JOB_STATUS_DELETING|
			JOB_STATUS_DELETED,
			SPOOLSS_NOTIFY_MSG_UNIX_JOBID);

		goto send;

	} else if (strcmp(cmd, "printer") == 0) {
		uint32_t attribute;

		if (argc != 5) {
			fprintf(stderr, "Usage: smbcontrol <dest> printnotify "
				"printer <printername> <comment|port|driver> "
				"<value>\n");
			return False;
		}

		if (strcmp(argv[3], "comment") == 0) {
			attribute = PRINTER_NOTIFY_FIELD_COMMENT;
		} else if (strcmp(argv[3], "port") == 0) {
			attribute = PRINTER_NOTIFY_FIELD_PORT_NAME;
		} else if (strcmp(argv[3], "driver") == 0) {
			attribute = PRINTER_NOTIFY_FIELD_DRIVER_NAME;
		} else {
			fprintf(stderr, "Invalid printer command '%s'\n",
				argv[3]);
			return False;
		}

		notify_printer_byname(ev_ctx, msg_ctx, argv[2], attribute,
				      discard_const_p(char, argv[4]));

		goto send;
	}

	fprintf(stderr, "Invalid subcommand '%s'\n", cmd);
	return False;

send:
	print_notify_send_messages(msg_ctx, 0);
	return True;
}

/* Close a share */

static bool do_closeshare(struct tevent_context *ev_ctx,
			  struct messaging_context *msg_ctx,
			  const struct server_id pid,
			  const int argc, const char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: smbcontrol <dest> close-share "
			"<sharename>\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_SMB_FORCE_TDIS, argv[1],
			    strlen(argv[1]) + 1);
}

/*
 * Close a share if access denied by now
 **/

static bool do_close_denied_share(
	struct tevent_context *ev_ctx,
	struct messaging_context *msg_ctx,
	const struct server_id pid,
	const int argc, const char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: smbcontrol <dest> close-denied-share "
			"<sharename>\n");
		return False;
	}

	return send_message(
		msg_ctx,
		pid,
		MSG_SMB_FORCE_TDIS_DENIED,
		argv[1],
		strlen(argv[1]) + 1);
}

/* Kill a client by IP address */
static bool do_kill_client_by_ip(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 const struct server_id pid,
				 const int argc, const char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: smbcontrol <dest> kill-client-ip "
			"<IP address>\n");
		return false;
	}

	if (!is_ipaddress_v4(argv[1]) && !is_ipaddress_v6(argv[1])) {
		fprintf(stderr, "%s is not a valid IP address!\n", argv[1]);
		return false;
	}

	return send_message(msg_ctx, pid, MSG_SMB_KILL_CLIENT_IP,
			    argv[1], strlen(argv[1]) + 1);
}

/* Tell winbindd an IP got dropped */

static bool do_ip_dropped(struct tevent_context *ev_ctx,
			  struct messaging_context *msg_ctx,
			  const struct server_id pid,
			  const int argc, const char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: smbcontrol <dest> ip-dropped "
			"<ip-address>\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_WINBIND_IP_DROPPED, argv[1],
			    strlen(argv[1]) + 1);
}

/* Display talloc pool usage */

static bool do_poolusage(struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 const struct server_id dst,
			 const int argc, const char **argv)
{
	pid_t pid = procid_to_pid(&dst);
	int stdout_fd = 1;

	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> pool-usage\n");
		return False;
	}

	if (pid == 0) {
		fprintf(stderr, "Can only send to a specific PID\n");
		return false;
	}

	messaging_send_iov(
		msg_ctx,
		dst,
		MSG_REQ_POOL_USAGE,
		NULL,
		0,
		&stdout_fd,
		1);

	return true;
}

/* Fetch and print the ringbuf log */

static void print_ringbuf_log_cb(struct messaging_context *msg,
				 void *private_data,
				 uint32_t msg_type,
				 struct server_id pid,
				 DATA_BLOB *data)
{
	printf("%s", (const char *)data->data);
	num_replies++;
}

static bool do_ringbuflog(struct tevent_context *ev_ctx,
			  struct messaging_context *msg_ctx,
			  const struct server_id pid,
			  const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> ringbuf-log\n");
		return false;
	}

	messaging_register(msg_ctx, NULL, MSG_RINGBUF_LOG,
			   print_ringbuf_log_cb);

	/* Send a message and register our interest in a reply */

	if (!send_message(msg_ctx, pid, MSG_REQ_RINGBUF_LOG, NULL, 0)) {
		return false;
	}

	wait_replies(ev_ctx, msg_ctx, procid_to_pid(&pid) == 0);

	/* No replies were received within the timeout period */

	if (num_replies == 0) {
		printf("No replies received\n");
	}

	messaging_deregister(msg_ctx, MSG_RINGBUF_LOG, NULL);

	return num_replies != 0;
}

/* Perform a dmalloc mark */

static bool do_dmalloc_mark(struct tevent_context *ev_ctx,
			    struct messaging_context *msg_ctx,
			    const struct server_id pid,
			    const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> dmalloc-mark\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_REQ_DMALLOC_MARK, NULL, 0);
}

/* Perform a dmalloc changed */

static bool do_dmalloc_changed(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx,
			       const struct server_id pid,
			       const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> "
			"dmalloc-log-changed\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_REQ_DMALLOC_LOG_CHANGED,
			    NULL, 0);
}

static void print_uint32_cb(struct messaging_context *msg, void *private_data,
			    uint32_t msg_type, struct server_id pid,
			    DATA_BLOB *data)
{
	uint32_t num_children;

	if (data->length != sizeof(uint32_t)) {
		printf("Invalid response: %d bytes long\n",
		       (int)data->length);
		goto done;
	}
	num_children = IVAL(data->data, 0);
	printf("%u children\n", (unsigned)num_children);
done:
	num_replies++;
}

static bool do_num_children(struct tevent_context *ev_ctx,
			    struct messaging_context *msg_ctx,
			    const struct server_id pid,
			    const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> num-children\n");
		return False;
	}

	messaging_register(msg_ctx, NULL, MSG_SMB_NUM_CHILDREN,
			   print_uint32_cb);

	/* Send a message and register our interest in a reply */

	if (!send_message(msg_ctx, pid, MSG_SMB_TELL_NUM_CHILDREN, NULL, 0))
		return false;

	wait_replies(ev_ctx, msg_ctx, procid_to_pid(&pid) == 0);

	/* No replies were received within the timeout period */

	if (num_replies == 0)
		printf("No replies received\n");

	messaging_deregister(msg_ctx, MSG_SMB_NUM_CHILDREN, NULL);

	return num_replies;
}

static bool do_msg_cleanup(struct tevent_context *ev_ctx,
			   struct messaging_context *msg_ctx,
			   const struct server_id pid,
			   const int argc, const char **argv)
{
	int ret;

	ret = messaging_cleanup(msg_ctx, pid.pid);

	printf("cleanup(%u) returned %s\n", (unsigned)pid.pid,
	       ret ? strerror(ret) : "ok");

	return (ret == 0);
}

/* Shutdown a server process */

static bool do_shutdown(struct tevent_context *ev_ctx,
			struct messaging_context *msg_ctx,
			const struct server_id pid,
			const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> shutdown\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_SHUTDOWN, NULL, 0);
}

/* Notify a driver upgrade */

static bool do_drvupgrade(struct tevent_context *ev_ctx,
			  struct messaging_context *msg_ctx,
			  const struct server_id pid,
			  const int argc, const char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: smbcontrol <dest> drvupgrade "
			"<driver-name>\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_PRINTER_DRVUPGRADE, argv[1],
			    strlen(argv[1]) + 1);
}

static bool do_winbind_online(struct tevent_context *ev_ctx,
			      struct messaging_context *msg_ctx,
			      const struct server_id pid,
			      const int argc, const char **argv)
{
	TDB_CONTEXT *tdb;
	char *db_path;

	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol winbindd online\n");
		return False;
	}

	db_path = state_path(talloc_tos(), "winbindd_cache.tdb");
	if (db_path == NULL) {
		return false;
	}

	/* Remove the entry in the winbindd_cache tdb to tell a later
	   starting winbindd that we're online. */

	tdb = tdb_open_log(db_path, 0, TDB_DEFAULT, O_RDWR, 0600);
	if (!tdb) {
		fprintf(stderr, "Cannot open the tdb %s for writing.\n",
			db_path);
		TALLOC_FREE(db_path);
		return False;
	}

	TALLOC_FREE(db_path);
	tdb_delete_bystring(tdb, "WINBINDD_OFFLINE");
	tdb_close(tdb);

	return send_message(msg_ctx, pid, MSG_WINBIND_ONLINE, NULL, 0);
}

static bool do_winbind_offline(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx,
			       const struct server_id pid,
			       const int argc, const char **argv)
{
	TDB_CONTEXT *tdb;
	bool ret = False;
	int retry = 0;
	char *db_path;

	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol winbindd offline\n");
		return False;
	}

	db_path = state_path(talloc_tos(), "winbindd_cache.tdb");
	if (db_path == NULL) {
		return false;
	}

	/* Create an entry in the winbindd_cache tdb to tell a later
	   starting winbindd that we're offline. We may actually create
	   it here... */

	tdb = tdb_open_log(db_path,
				WINBINDD_CACHE_TDB_DEFAULT_HASH_SIZE,
				TDB_DEFAULT|TDB_INCOMPATIBLE_HASH /* TDB_CLEAR_IF_FIRST */,
				O_RDWR|O_CREAT, 0600);

	if (!tdb) {
		fprintf(stderr, "Cannot open the tdb %s for writing.\n",
			db_path);
		TALLOC_FREE(db_path);
		return False;
	}
	TALLOC_FREE(db_path);

	/* There's a potential race condition that if a child
	   winbindd detects a domain is online at the same time
	   we're trying to tell it to go offline that it might 
	   delete the record we add between us adding it and
	   sending the message. Minimize this by retrying up to
	   5 times. */

	for (retry = 0; retry < 5; retry++) {
		uint8_t buf[4];
		TDB_DATA d = { .dptr = buf, .dsize = sizeof(buf) };

		SIVAL(buf, 0, time(NULL));

		tdb_store_bystring(tdb, "WINBINDD_OFFLINE", d, TDB_INSERT);

		ret = send_message(msg_ctx, pid, MSG_WINBIND_OFFLINE,
				   NULL, 0);

		/* Check that the entry "WINBINDD_OFFLINE" still exists. */
		d = tdb_fetch_bystring( tdb, "WINBINDD_OFFLINE" );
		if (d.dptr != NULL && d.dsize == 4) {
			SAFE_FREE(d.dptr);
			break;
		}

		SAFE_FREE(d.dptr);
		DEBUG(10,("do_winbind_offline: offline state not set - retrying.\n"));
	}

	tdb_close(tdb);
	return ret;
}

static bool do_winbind_onlinestatus(struct tevent_context *ev_ctx,
				    struct messaging_context *msg_ctx,
				    const struct server_id pid,
				    const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol winbindd onlinestatus\n");
		return False;
	}

	messaging_register(msg_ctx, NULL, MSG_WINBIND_ONLINESTATUS,
			   print_pid_string_cb);

	if (!send_message(msg_ctx, pid, MSG_WINBIND_ONLINESTATUS, NULL, 0)) {
		return False;
	}

	wait_replies(ev_ctx, msg_ctx, procid_to_pid(&pid) == 0);

	/* No replies were received within the timeout period */

	if (num_replies == 0)
		printf("No replies received\n");

	messaging_deregister(msg_ctx, MSG_WINBIND_ONLINESTATUS, NULL);

	return num_replies;
}

static bool do_winbind_dump_domain_list(struct tevent_context *ev_ctx,
					struct messaging_context *msg_ctx,
					const struct server_id pid,
					const int argc, const char **argv)
{
	const char *domain = NULL;
	int domain_len = 0;

	if (argc < 1 || argc > 2) {
		fprintf(stderr, "Usage: smbcontrol <dest> dump-domain-list "
			"<domain>\n");
		return false;
	}

	if (argc == 2) {
		domain = argv[1];
		domain_len = strlen(argv[1]) + 1;
	}

	messaging_register(msg_ctx, NULL, MSG_WINBIND_DUMP_DOMAIN_LIST,
			   print_pid_string_cb);

	if (!send_message(msg_ctx, pid, MSG_WINBIND_DUMP_DOMAIN_LIST,
			  domain, domain_len))
	{
		return false;
	}

	wait_replies(ev_ctx, msg_ctx, procid_to_pid(&pid) == 0);

	/* No replies were received within the timeout period */

	if (num_replies == 0) {
		printf("No replies received\n");
	}

	messaging_deregister(msg_ctx, MSG_WINBIND_DUMP_DOMAIN_LIST, NULL);

	return num_replies;
}

static bool do_msg_disconnect_dc(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 const struct server_id pid,
				 const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> disconnect-dc\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_WINBIND_DISCONNECT_DC, NULL, 0);
}

static void winbind_validate_cache_cb(struct messaging_context *msg,
				      void *private_data,
				      uint32_t msg_type,
				      struct server_id pid,
				      DATA_BLOB *data)
{
	struct server_id_buf src_string;
	printf("Winbindd cache is %svalid. (answer from pid %s)\n",
	       (*(data->data) == 0 ? "" : "NOT "),
	       server_id_str_buf(pid, &src_string));
	num_replies++;
}

static bool do_winbind_validate_cache(struct tevent_context *ev_ctx,
				      struct messaging_context *msg_ctx,
				      const struct server_id pid,
				      const int argc, const char **argv)
{
	struct server_id myid;

	myid = messaging_server_id(msg_ctx);

	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol winbindd validate-cache\n");
		return False;
	}

	messaging_register(msg_ctx, NULL, MSG_WINBIND_VALIDATE_CACHE,
			   winbind_validate_cache_cb);

	if (!send_message(msg_ctx, pid, MSG_WINBIND_VALIDATE_CACHE, &myid,
			  sizeof(myid))) {
		return False;
	}

	wait_replies(ev_ctx, msg_ctx, procid_to_pid(&pid) == 0);

	if (num_replies == 0) {
		printf("No replies received\n");
	}

	messaging_deregister(msg_ctx, MSG_WINBIND_VALIDATE_CACHE, NULL);

	return num_replies;
}

static bool do_reload_config(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx,
			     const struct server_id pid,
			     const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> reload-config\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_SMB_CONF_UPDATED, NULL, 0);
}

static bool do_reload_printers(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx,
			       const struct server_id pid,
			       const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> reload-printers\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_PRINTER_PCAP, NULL, 0);
}

static void my_make_nmb_name( struct nmb_name *n, const char *name, int type)
{
	fstring unix_name;
	memset( (char *)n, '\0', sizeof(struct nmb_name) );
	fstrcpy(unix_name, name);
	(void)strupper_m(unix_name);
	push_ascii(n->name, unix_name, sizeof(n->name), STR_TERMINATE);
	n->name_type = (unsigned int)type & 0xFF;
	push_ascii(n->scope,  lp_netbios_scope(), 64, STR_TERMINATE);
}

static bool do_nodestatus(struct tevent_context *ev_ctx,
			  struct messaging_context *msg_ctx,
			  const struct server_id pid,
			  const int argc, const char **argv)
{
	struct packet_struct p;

	if (argc != 2) {
		fprintf(stderr, "Usage: smbcontrol nmbd nodestatus <ip>\n");
		return False;
	}

	ZERO_STRUCT(p);

	p.ip = interpret_addr2(argv[1]);
	p.port = 137;
	p.packet_type = NMB_PACKET;

	p.packet.nmb.header.name_trn_id = 10;
	p.packet.nmb.header.opcode = 0;
	p.packet.nmb.header.response = False;
	p.packet.nmb.header.nm_flags.bcast = False;
	p.packet.nmb.header.nm_flags.recursion_available = False;
	p.packet.nmb.header.nm_flags.recursion_desired = False;
	p.packet.nmb.header.nm_flags.trunc = False;
	p.packet.nmb.header.nm_flags.authoritative = False;
	p.packet.nmb.header.rcode = 0;
	p.packet.nmb.header.qdcount = 1;
	p.packet.nmb.header.ancount = 0;
	p.packet.nmb.header.nscount = 0;
	p.packet.nmb.header.arcount = 0;
	my_make_nmb_name(&p.packet.nmb.question.question_name, "*", 0x00);
	p.packet.nmb.question.question_type = 0x21;
	p.packet.nmb.question.question_class = 0x1;

	return send_message(msg_ctx, pid, MSG_SEND_PACKET, &p, sizeof(p));
}

static bool do_notify_cleanup(struct tevent_context *ev_ctx,
			      struct messaging_context *msg_ctx,
			      const struct server_id pid,
			      const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol smbd notify-cleanup\n");
		return false;
	}
	return send_message(msg_ctx, pid, MSG_SMB_NOTIFY_CLEANUP, NULL, 0);
}

/* A list of message type supported */

static const struct {
	const char *name;	/* Option name */
	bool (*fn)(struct tevent_context *ev_ctx,
		   struct messaging_context *msg_ctx,
		   const struct server_id pid,
		   const int argc, const char **argv);
	const char *help;	/* Short help text */
} msg_types[] = {
	{
		.name = "debug",
		.fn   = do_debug,
		.help = "Set debuglevel",
	},
	{
		.name = "idmap",
		.fn   = do_idmap,
		.help = "Manipulate idmap cache",
	},
	{
		.name = "force-election",
		.fn   = do_election,
		.help = "Force a browse election",
	},
	{
		.name = "ping",
		.fn   = do_ping,
		.help = "Elicit a response",
	},
	{
		.name = "profile",
		.fn   = do_profile,
		.help = "",
	},
	{
		.name = "inject",
		.fn   = do_inject_fault,
		.help = "Inject a fatal signal into a running smbd"},
	{
		.name = "stacktrace",
		.fn   = do_daemon_stack_trace,
		.help = "Display a stack trace of a daemon",
	},
	{
		.name = "profilelevel",
		.fn   = do_profilelevel,
		.help = "",
	},
	{
		.name = "debuglevel",
		.fn   = do_debuglevel,
		.help = "Display current debuglevels",
	},
	{
		.name = "printnotify",
		.fn   = do_printnotify,
		.help = "Send a print notify message",
	},
	{
		.name = "close-share",
		.fn   = do_closeshare,
		.help = "Forcibly disconnect a share",
	},
	{
		.name = "close-denied-share",
		.fn   = do_close_denied_share,
		.help = "Forcibly disconnect users from shares disallowed now",
	},
	{
		.name = "kill-client-ip",
		.fn   = do_kill_client_by_ip,
		.help = "Forcibly disconnect a client with a specific IP address",
	},
	{
		.name = "ip-dropped",
		.fn   = do_ip_dropped,
		.help = "Tell winbind that an IP got dropped",
	},
	{
		.name = "pool-usage",
		.fn   = do_poolusage,
		.help = "Display talloc memory usage",
	},
	{
		.name = "ringbuf-log",
		.fn   = do_ringbuflog,
		.help = "Display ringbuf log",
	},
	{
		.name = "dmalloc-mark",
		.fn   = do_dmalloc_mark,
		.help = "",
	},
	{
		.name = "dmalloc-log-changed",
		.fn   = do_dmalloc_changed,
		.help = "",
	},
	{
		.name = "shutdown",
		.fn   = do_shutdown,
		.help = "Shut down daemon",
	},
	{
		.name = "drvupgrade",
		.fn   = do_drvupgrade,
		.help = "Notify a printer driver has changed",
	},
	{
		.name = "reload-config",
		.fn   = do_reload_config,
		.help = "Force smbd or winbindd to reload config file"},
	{
		.name = "reload-printers",
		.fn   = do_reload_printers,
		.help = "Force smbd to reload printers"},
	{
		.name = "nodestatus",
		.fn   = do_nodestatus,
		.help = "Ask nmbd to do a node status request"},
	{
		.name = "online",
		.fn   = do_winbind_online,
		.help = "Ask winbind to go into online state"},
	{
		.name = "offline",
		.fn   = do_winbind_offline,
		.help = "Ask winbind to go into offline state"},
	{
		.name = "onlinestatus",
		.fn   = do_winbind_onlinestatus,
		.help = "Request winbind online status"},
	{
		.name = "validate-cache" ,
		.fn   = do_winbind_validate_cache,
		.help = "Validate winbind's credential cache",
	},
	{
		.name = "dump-domain-list",
		.fn   = do_winbind_dump_domain_list,
		.help = "Dump winbind domain list"},
	{
		.name = "disconnect-dc",
		.fn   = do_msg_disconnect_dc,
	},
	{
		.name = "notify-cleanup",
		.fn   = do_notify_cleanup,
	},
	{
		.name = "num-children",
		.fn   = do_num_children,
		.help = "Print number of smbd child processes",
	},
	{
		.name = "msg-cleanup",
		.fn   = do_msg_cleanup,
	},
	{
		.name = "noop",
		.fn   = do_noop,
		.help = "Do nothing",
	},
	{
		.name = "sleep",
		.fn   = do_sleep,
		.help = "Cause the target process to sleep",
	},
	{ .name = NULL, },
};

/* Display usage information */

static void usage(poptContext pc)
{
	int i;

	poptPrintHelp(pc, stderr, 0);

	fprintf(stderr, "\n");
	fprintf(stderr, "<destination> is one of \"nmbd\", \"smbd\", \"winbindd\" or a "
		"process ID\n");

	fprintf(stderr, "\n");
	fprintf(stderr, "<message-type> is one of:\n");

	for (i = 0; msg_types[i].name; i++) {
		const char *help = msg_types[i].help;
		if (help == NULL) {
			help = "";
		}
		fprintf(stderr, "\t%-30s%s\n", msg_types[i].name, help);
	}

	fprintf(stderr, "\n");

	exit(1);
}

/* Return the pid number for a string destination */

static struct server_id parse_dest(struct messaging_context *msg,
				   const char *dest)
{
	struct server_id result = {
		.pid = (uint64_t)-1,
	};
	pid_t pid;

	/* Zero is a special return value for broadcast to all processes */

	if (strequal(dest, "all")) {
		return interpret_pid(MSG_BROADCAST_PID_STR);
	}

	/* Try self - useful for testing */

	if (strequal(dest, "self")) {
		return messaging_server_id(msg);
	}

	/* Fix winbind typo. */
	if (strequal(dest, "winbind")) {
		dest = "winbindd";
	}

	/* Check for numeric pid number */
	result = interpret_pid(dest);

	/* Zero isn't valid if not "all". */
	if (result.pid && procid_valid(&result)) {
		return result;
	}

	/* Look up other destinations in pidfile directory */

	if ((pid = pidfile_pid(lp_pid_directory(), dest)) != 0) {
		return pid_to_procid(pid);
	}

	fprintf(stderr,"Can't find pid for destination '%s'\n", dest);

	return result;
}

/* Execute smbcontrol command */

static bool do_command(struct tevent_context *ev_ctx,
		       struct messaging_context *msg_ctx,
		       int argc, const char **argv)
{
	const char *dest = argv[0], *command = argv[1];
	struct server_id pid;
	int i;

	/* Check destination */

	pid = parse_dest(msg_ctx, dest);
	if (!procid_valid(&pid)) {
		return False;
	}

	/* Check command */

	for (i = 0; msg_types[i].name; i++) {
		if (strequal(command, msg_types[i].name))
			return msg_types[i].fn(ev_ctx, msg_ctx, pid,
					       argc - 1, argv + 1);
	}

	fprintf(stderr, "smbcontrol: unknown command '%s'\n", command);

	return False;
}

static void smbcontrol_help(poptContext pc,
		    enum poptCallbackReason preason,
		    struct poptOption * poption,
		    const char * parg,
		    void * pdata)
{
	if (poption->shortName != '?') {
		poptPrintUsage(pc, stdout, 0);
	} else {
		usage(pc);
	}

	exit(0);
}

struct poptOption help_options[] = {
	{ NULL, '\0', POPT_ARG_CALLBACK, (void *)&smbcontrol_help, '\0',
	  NULL, NULL },
	{ "help", '?', 0, NULL, '?', "Show this help message", NULL },
	{ "usage", '\0', 0, NULL, 'u', "Display brief usage message", NULL },
	{0}
} ;

/* Main program */

int main(int argc, const char **argv)
{
	poptContext pc;
	int opt;
	struct tevent_context *evt_ctx;
	struct messaging_context *msg_ctx;

	static struct poptOption long_options[] = {
		/* POPT_AUTOHELP */
		{ NULL, '\0', POPT_ARG_INCLUDE_TABLE, help_options,
		                        0, "Help options:", NULL },
		{ "timeout", 't', POPT_ARG_INT, &timeout, 't', 
		  "Set timeout value in seconds", "TIMEOUT" },

		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};
	TALLOC_CTX *frame = talloc_stackframe();
	int ret = 0;

	smb_init_locale();

	setup_logging(argv[0], DEBUG_STDOUT);
	lp_set_cmdline("log level", "0");

	/* Parse command line arguments using popt */

	pc = poptGetContext(
		"smbcontrol", argc, (const char **)argv, long_options, 0);

	poptSetOtherOptionHelp(pc, "[OPTION...] <destination> <message-type> "
			       "<parameters>");

	if (argc == 1)
		usage(pc);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch(opt) {
		case 't':	/* --timeout */
			break;
		default:
			fprintf(stderr, "Invalid option\n");
			poptPrintHelp(pc, stderr, 0);
			break;
		}
	}

	/* We should now have the remaining command line arguments in
           argv.  The argc parameter should have been decremented to the
           correct value in the above switch statement. */

	argv = (const char **)poptGetArgs(pc);
	argc = 0;
	if (argv != NULL) {
		while (argv[argc] != NULL) {
			argc++;
		}
	}

	if (argc <= 1)
		usage(pc);

	msg_ctx = cmdline_messaging_context(get_dyn_CONFIGFILE());
	if (msg_ctx == NULL) {
		fprintf(stderr,
			"Could not init messaging context, not root?\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	evt_ctx = global_event_context();

	lp_load_global(get_dyn_CONFIGFILE());

	/* Need to invert sense of return code -- samba
         * routines mostly return True==1 for success, but
         * shell needs 0. */ 

	ret = !do_command(evt_ctx, msg_ctx, argc, argv);

	poptFreeContext(pc);
	TALLOC_FREE(frame);
	return ret;
}
