/* 
   Unix SMB/CIFS implementation.
   program to send control messages to Samba processes
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) 2001, 2002 by Martin Pool
   Copyright (C) Simo Sorce 2002
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

extern BOOL AllowDebugChange;

static const struct {
	const char *name;
	int value;
} msg_types[] = {
	{"debug", MSG_DEBUG},
	{"force-election", MSG_FORCE_ELECTION},
	{"ping", MSG_PING},
	{"profile", MSG_PROFILE},
	{"profilelevel", MSG_REQ_PROFILELEVEL},
	{"debuglevel", MSG_REQ_DEBUGLEVEL},
	{"printnotify", MSG_PRINTER_NOTIFY2 },
	{"close-share", MSG_SMB_FORCE_TDIS},
        {"samsync", MSG_SMB_SAM_SYNC},
        {"samrepl", MSG_SMB_SAM_REPL},
	{"pool-usage", MSG_REQ_POOL_USAGE },
	{"dmalloc-mark", MSG_REQ_DMALLOC_MARK },
	{"dmalloc-log-changed", MSG_REQ_DMALLOC_LOG_CHANGED },
	{"shutdown", MSG_SHUTDOWN },
	{"drvupgrade", MSG_PRINTER_DRVUPGRADE},
	{"tallocdump", MSG_REQ_TALLOC_USAGE},
	{NULL, -1}
};

time_t timeout_start;

#define MAX_WAIT	10

/* we need these because we link to printing*.o */

void become_root(void) {}
void unbecome_root(void) {}


static void usage(BOOL doexit)
{
	int i;
	if (doexit) {
		printf("Usage: smbcontrol -i -s configfile\n");
		printf("       smbcontrol <destination> <message-type> <parameters>\n\n");
	} else {
		printf("<destination> <message-type> <parameters>\n\n");
	}
	printf("\t<destination> is one of \"nmbd\", \"smbd\" or a process ID\n");
	printf("\t<message-type> is one of:\n");
	for (i=0; msg_types[i].name; i++) 
	    printf("\t\t%s\n", msg_types[i].name);
	printf("\n");
	if (doexit) exit(1);
}

static int pong_count;
static BOOL got_level;
static BOOL got_pool;
static BOOL pong_registered = False;
static BOOL debuglevel_registered = False;
static BOOL poolusage_registered = False;
static BOOL profilelevel_registered = False;


/**
 * Wait for replies for up to @p *max_secs seconds, or until @p
 * max_replies are received.  max_replies may be NULL in which case it
 * is ignored.
 *
 * @note This is a pretty lame timeout; all it means is that after
 * max_secs we won't look for any more messages.
 **/
static void wait_for_replies(int max_secs, int *max_replies)
{
	time_t timeout_end = time(NULL) + max_secs;

	while ((!max_replies || (*max_replies)-- > 0)
	       &&  (time(NULL) < timeout_end)) {
		message_dispatch();
	}
}


/****************************************************************************
a useful function for testing the message system
****************************************************************************/
void pong_function(int msg_type, pid_t src, void *buf, size_t len)
{
	pong_count++;
	printf("PONG from PID %u\n",(unsigned int)src);
}

/****************************************************************************
 Prints out the current talloc list.
****************************************************************************/
void tallocdump_function(int msg_type, pid_t src, void *buf, size_t len)
{
	char *info = (char *)buf;

	printf("Current talloc contexts for process %u\n", (unsigned int)src );
	if (len == 0)
		printf("None returned\n");
	else
		printf(info);
	printf("\n");
	got_pool = True;
}

/****************************************************************************
Prints out the current Debug level returned by MSG_DEBUGLEVEL
****************************************************************************/
void debuglevel_function(int msg_type, pid_t src, void *buf, size_t len)
{
	const char *levels = (char *)buf;

	printf("Current debug levels of PID %u are:\n",(unsigned int)src);
	printf("%s\n", levels);
	
	got_level = True;
}

/****************************************************************************
Prints out the current Profile level returned by MSG_PROFILELEVEL
****************************************************************************/
void profilelevel_function(int msg_type, pid_t src, void *buf, size_t len)
{
        int level;
	const char *s=NULL;
        memcpy(&level, buf, sizeof(int));

	if (level) {
	    switch (level) {
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
	    printf("Profiling %s on PID %u\n",s,(unsigned int)src);
	} else {
	    printf("Profiling not available on PID %u\n",(unsigned int)src);
	}
	got_level = True;
}

/**
 * Handle reply from POOL_USAGE.
 **/
static void pool_usage_cb(int msg_type, pid_t src_pid, void *buf, size_t len)
{
	printf("Got POOL_USAGE reply from pid%u:\n%.*s",
	       (unsigned int) src_pid, (int) len, (const char *) buf);
}


/**
 * Send a message to a named destination
 *
 * @return False if an error occurred.
 **/
static BOOL send_message(char *dest, int msg_type, void *buf, int len, BOOL duplicates)
{
	pid_t pid;
	/* "smbd" is the only broadcast operation */
	if (strequal(dest,"smbd")) {
		TDB_CONTEXT *tdb;
		BOOL ret;
		int n_sent = 0;

		tdb = tdb_open_log(lock_path("connections.tdb"), 0, TDB_DEFAULT, O_RDWR, 0);
		if (!tdb) {
			fprintf(stderr,"Failed to open connections database in send_message.\n");
			return False;
		}

		ret = message_send_all(tdb,msg_type, buf, len, duplicates,
				       &n_sent);
		DEBUG(10,("smbcontrol/send_message: broadcast message to "
			  "%d processes\n", n_sent));
		tdb_close(tdb);

		return ret;
	} else if (strequal(dest,"nmbd")) {
		pid = pidfile_pid(dest);
		if (pid == 0) {
			fprintf(stderr,"Can't find pid for nmbd\n");
			return False;
		}
	} else if (strequal(dest,"self")) {
		pid = sys_getpid();
	} else {
		pid = atoi(dest);
		if (pid == 0) {
			fprintf(stderr,"Not a valid pid\n");
			return False;
		}		
	} 

	DEBUG(10,("smbcontrol/send_message: send message to pid%d\n", pid));
	return message_send_pid(pid, msg_type, buf, len, duplicates);
}

/****************************************************************************
evaluate a message type string
****************************************************************************/
static int parse_type(char *mtype)
{
	int i;
	for (i=0;msg_types[i].name;i++) {
		if (strequal(mtype, msg_types[i].name)) return msg_types[i].value;
	}
	return -1;
}


static void register_all(void)
{
	message_register(MSG_POOL_USAGE, pool_usage_cb);
}

/* This guy is here so we can link printing/notify.c to the smbcontrol
   binary without having to pull in tons of other crap. */

TDB_CONTEXT *conn_tdb_ctx(void)
{
	static TDB_CONTEXT *tdb;

	if (tdb)
		return tdb;

	tdb = tdb_open_log(lock_path("connections.tdb"), 0, TDB_DEFAULT, O_RDONLY, 0);

	if (!tdb)
		DEBUG(3, ("Failed to open connections database in send_spoolss_notify2_msg\n"));

	return tdb;
}

/****************************************************************************
do command
****************************************************************************/
static BOOL do_command(char *dest, char *msg_name, int iparams, char **params)
{
	int i, n, v;
	int mtype;
	BOOL retval=False;
	BOOL check_notify_msgs = False;

	mtype = parse_type(msg_name);
	if (mtype == -1) {
		fprintf(stderr,"Couldn't resolve message type: %s\n", msg_name);
		return(False);
	}

	switch (mtype) {
	case MSG_DEBUG: {
		char *buf, *b;
		char **p;
		int dim = 0;

		if (!params || !params[0]) {
			fprintf(stderr,"MSG_DEBUG needs a parameter\n");
			return(False);
		}

		/* first pass retrieve total lenght */
		for (p = params; p && *p ; p++)
			dim += (strnlen(*p, 1024) +1); /* lenght + space */
		b = buf = malloc(dim);
		if (!buf) {
			fprintf(stderr, "Out of memory!");
			return(False);
		}
		/* now build a single string with all parameters */
		for(p = params; p && *p; p++) {
			int l = strnlen(*p, 1024);
			strncpy(b, *p, l);
			b[l] = ' ';
			b = b + l + 1;
		}
		b[-1] = '\0';

		send_message(dest, MSG_DEBUG, buf, dim, False);

		free(buf);
  
		break;
	}

	case MSG_PROFILE:
		if (!params || !params[0]) {
			fprintf(stderr,"MSG_PROFILE needs a parameter\n");
			return(False);
		}
		if (strequal(params[0], "off")) {
			v = 0;
		} else if (strequal(params[0], "count")) {
			v = 1;
		} else if (strequal(params[0], "on")) {
			v = 2;
		} else if (strequal(params[0], "flush")) {
			v = 3;
		} else {
		    fprintf(stderr,
			"MSG_PROFILE parameter must be off, count, on, or flush\n");
		    return(False);
		}
		send_message(dest, MSG_PROFILE, &v, sizeof(int), False);
		break;

	case MSG_FORCE_ELECTION:
		if (!strequal(dest, "nmbd")) {
			fprintf(stderr,"force-election can only be sent to nmbd\n");
			return(False);
		}
		send_message(dest, MSG_FORCE_ELECTION, NULL, 0, False);
		break;

	case MSG_REQ_PROFILELEVEL:
		if (!profilelevel_registered) {
		    message_register(MSG_PROFILELEVEL, profilelevel_function);
		    profilelevel_registered = True;
		}
		got_level = False;
		retval = send_message(dest, MSG_REQ_PROFILELEVEL, NULL, 0, True);
		if (retval) {
			timeout_start = time(NULL);
			while (!got_level) {
				message_dispatch();
				if ((time(NULL) - timeout_start) > MAX_WAIT) {
					fprintf(stderr,"profilelevel timeout\n");
					break;
				}
			}
		}
		break;

	case MSG_REQ_TALLOC_USAGE:
		if (!poolusage_registered) {
			message_register(MSG_TALLOC_USAGE, tallocdump_function);
			poolusage_registered = True;
		}
		got_pool = False;
		retval = send_message(dest, MSG_REQ_TALLOC_USAGE, NULL, 0, True);
		if (retval) {
			timeout_start = time(NULL);
			while (!got_pool) {
				message_dispatch();
				if ((time(NULL) - timeout_start) > MAX_WAIT) {
					fprintf(stderr,"tallocdump timeout\n");
					break;
				}
			}
		}
		break;

	case MSG_REQ_DEBUGLEVEL:
		if (!debuglevel_registered) {
		    message_register(MSG_DEBUGLEVEL, debuglevel_function);
		    debuglevel_registered = True;
		}
		got_level = False;
		retval = send_message(dest, MSG_REQ_DEBUGLEVEL, NULL, 0, True);
		if (retval) {
			timeout_start = time(NULL);
			while (!got_level) {
				message_dispatch();
				if ((time(NULL) - timeout_start) > MAX_WAIT) {
					fprintf(stderr,"debuglevel timeout\n");
					break;
				}
			}
		}
		break;

		/* Send a notification message to a printer */

	case MSG_PRINTER_NOTIFY2: {
		char *cmd;

		/* Read subcommand */

		if (!params || !params[0]) {
			fprintf(stderr, "Must specify subcommand:\n");
			fprintf(stderr, "\tqueuepause <printername>\n");
			fprintf(stderr, "\tqueueresume <printername>\n");
			fprintf(stderr, "\tjobpause <printername> <unix jobid>\n");
			fprintf(stderr, "\tjobresume <printername> <unix jobid>\n");
			fprintf(stderr, "\tjobdelete <printername> <unix jobid>\n");
			fprintf(stderr, "\tprinter <printername> <comment|port|driver> <new value>\n");
			return False;
		}

		cmd = params[0];

		check_notify_msgs = True;

		/* Pause a print queue */

		if (strequal(cmd, "queuepause")) {

			if (!params[1]) {
				fprintf(stderr, "queuepause command requires a printer name\n");
				return False;
			}

			notify_printer_status_byname(params[1], PRINTER_STATUS_PAUSED);
			break;
		}

		/* Resume a print queue */

		if (strequal(cmd, "queueresume")) {

			if (!params[1]) {
				fprintf(stderr, "queueresume command requires a printer name\n");
				return False;
			}

			notify_printer_status_byname(params[1], PRINTER_STATUS_OK);
			break;
		}

		/* Pause a print job */

		if (strequal(cmd, "jobpause")) {
			int jobid;

			if (!params[1] || !params[2]) {
				fprintf(stderr, "jobpause command requires a printer name and a jobid\n");
				return False;
			}

			jobid = atoi(params[2]);

			notify_job_status_byname(
				params[1], jobid, JOB_STATUS_PAUSED, 
				SPOOLSS_NOTIFY_MSG_UNIX_JOBID);
			break;
		}

		/* Resume a print job */

		if (strequal(cmd, "jobresume")) {
			int jobid;

			if (!params[1] || !params[2]) {
				fprintf(stderr, "jobresume command requires a printer name and a jobid\n");
				return False;
			}

			jobid = atoi(params[2]);

			notify_job_status_byname(
				params[1], jobid, JOB_STATUS_QUEUED,
				SPOOLSS_NOTIFY_MSG_UNIX_JOBID);
			break;
		}

		/* Delete a print job */

		if (strequal(cmd, "jobdelete")) {
			int jobid;

			if (!params[1] || !params[2]) {
				fprintf(stderr, "jobdelete command requires a printer name and a jobid\n");
				return False;
			}

			jobid = atoi(params[2]);

			notify_job_status_byname(
				params[1], jobid, JOB_STATUS_DELETING,
				SPOOLSS_NOTIFY_MSG_UNIX_JOBID);

			notify_job_status_byname(
				params[1], jobid, JOB_STATUS_DELETING|
				JOB_STATUS_DELETED,
				SPOOLSS_NOTIFY_MSG_UNIX_JOBID);
		}
		
		/* printer change notify */
		
		if (strequal(cmd, "printer")) {
			int attribute = -1;
			
			if (!params[1] || !params[2] || !params[3]) {
				fprintf(stderr, "printer command requires an and attribute name and value!\n");
				fprintf(stderr, "supported attributes:\n");
				fprintf(stderr, "\tcomment:\n");
				fprintf(stderr, "\tport:\n");
				fprintf(stderr, "\tdriver:\n");
				return False;
			}
			if ( strequal(params[2], "comment") )
				attribute = PRINTER_NOTIFY_COMMENT;
			else if ( strequal(params[2], "port") )
				attribute = PRINTER_NOTIFY_PORT_NAME;
			else if ( strequal(params[2], "driver") )
				attribute = PRINTER_NOTIFY_DRIVER_NAME;
			
			if ( attribute == -1 ) {
				fprintf(stderr, "bad attribute!\n");
				return False;
			}
			
			notify_printer_byname( params[1], attribute, params[3]);
			
			break;
		}
		
		break;
	  }


	case MSG_SMB_FORCE_TDIS:
		if (!strequal(dest, "smbd")) {
			fprintf(stderr,"close-share can only be sent to smbd\n");
			return(False);
		}
		if (!params || !params[0]) {
			fprintf(stderr, "close-share needs a share name or '*'\n");
			return (False);
		}
		retval = send_message(dest, MSG_SMB_FORCE_TDIS, params[0],
				      strlen(params[0]) + 1, False);
		break;

        case MSG_SMB_SAM_SYNC:
                if (!strequal(dest, "smbd")) {
                        fprintf(stderr, "samsync can only be sent to smbd\n");
                        return False;
                }

                if (params) {
                        fprintf(stderr, "samsync does not take any parameters\n");
                        return False;
                }

                retval = send_message(dest, MSG_SMB_SAM_SYNC, NULL, 0, False);

                break;

        case MSG_SMB_SAM_REPL: {
                uint32 seqnum;

                if (!strequal(dest, "smbd")) {
                        fprintf(stderr, "sam repl can only be sent to smbd\n");
                        return False;
                }

                if (!params || !params[0]) {
                        fprintf(stderr, "SAM_REPL needs a parameter\n");
                        return False;
                }

                seqnum = atoi(params[0]);

                retval = send_message(dest, MSG_SMB_SAM_SYNC, 
                                      (char *)&seqnum, sizeof(uint32), False); 

                break;
        }

	case MSG_PING:
		if (!pong_registered) {
		    message_register(MSG_PONG, pong_function);
		    pong_registered = True;
		}
		if (!params || !params[0]) {
			fprintf(stderr,"MSG_PING needs a parameter\n");
			return(False);
		}
		n = atoi(params[0]);
		pong_count = 0;
		for (i=0;i<n;i++) {
			if (iparams > 1)
				retval = send_message(dest, MSG_PING, params[1], strlen(params[1]) + 1, True);
			else
				retval = send_message(dest, MSG_PING, NULL, 0, True);
			if (retval == False)
				return False;
		}
		wait_for_replies(MAX_WAIT, &n);
		if (n > 0) {
			fprintf(stderr,"PING timeout\n");
		}
		break;

	case MSG_REQ_POOL_USAGE:
		if (!send_message(dest, MSG_REQ_POOL_USAGE, NULL, 0, True))
			return False;
		wait_for_replies(MAX_WAIT, NULL);
		
		break;

	case MSG_REQ_DMALLOC_LOG_CHANGED:
	case MSG_REQ_DMALLOC_MARK:
		if (!send_message(dest, mtype, NULL, 0, False))
			return False;
		break;

	case MSG_SHUTDOWN:
		if (!send_message(dest, MSG_SHUTDOWN, NULL, 0, False))
			return False;
		break;
	case MSG_PRINTER_DRVUPGRADE:
		if (!send_message(dest, MSG_PRINTER_DRVUPGRADE, params[0], 0, False))
			return False;
		break;
	}

	/* check if we have any pending print notify messages */

	if ( check_notify_msgs )
		print_notify_send_messages(0);
		
	return (True);
}

 int main(int argc, char *argv[])
{
	int opt;
	char temp[255];
	extern int optind;
	BOOL interactive = False;

	AllowDebugChange = False;
	DEBUGLEVEL = 0;

	setup_logging(argv[0],True);
	
	if (argc < 2) usage(True);

	while ((opt = getopt(argc, argv,"is:")) != EOF) {
		switch (opt) {
		case 'i':
			interactive = True;
			break;
		case 's':
			pstrcpy(dyn_CONFIGFILE, optarg);
			break;
		default:
			printf("Unknown option %c (%d)\n", (char)opt, opt);
			usage(True);
		}
	}

	lp_load(dyn_CONFIGFILE,False,False,False);

	if (!message_init()) exit(1);

	argc -= optind;
	argv = &argv[optind];

	register_all();

	if (!interactive) {
		if (argc < 2) usage(True);
		/* Need to invert sense of return code -- samba
		 * routines mostly return True==1 for success, but
		 * shell needs 0. */ 
		return ! do_command(argv[0],argv[1], argc-2, argc > 2 ? &argv[2] : 0);
	}

	while (True) {
		char *myargv[4];
		int myargc;

		printf("smbcontrol> ");
		if (!fgets(temp, sizeof(temp)-1, stdin)) break;
		myargc = 0;
		while ((myargc < 4) && 
		       (myargv[myargc] = strtok(myargc?NULL:temp," \t\n"))) {
			myargc++;
		}
		if (!myargc) break;
		if (strequal(myargv[0],"q")) break;
		if (myargc < 2)
			usage(False);
		else if (!do_command(myargv[0],myargv[1],myargc-2,myargc > 2 ? &myargv[2] : 0))
			usage(False);
	}
	return(0);
}

