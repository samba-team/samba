/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   program to send control messages to Samba processes
   Copyright (C) Andrew Tridgell 1994-1998
   
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

static struct {
	const char *name;
	int value;
} msg_types[] = {
	{"debug", MSG_DEBUG},
	{"force-election", MSG_FORCE_ELECTION},
	{"ping", MSG_PING},
	{"profile", MSG_PROFILE},
	{"profilelevel", MSG_REQ_PROFILELEVEL},
	{"debuglevel", MSG_REQ_DEBUGLEVEL},
	{"printer-notify", MSG_PRINTER_NOTIFY},
	{"close-share", MSG_SMB_FORCE_TDIS},
	{NULL, -1}
};

time_t timeout_start;

#define MAX_WAIT	10

static void usage(BOOL doexit)
{
	int i;
	if (doexit) {
		printf("Usage: smbcontrol [-d debuglevel] [-s configfile] [-i]\n");
		printf("       smbcontrol [-d debuglevel] [-s configfile] <destination> <message-type> <parameters>\n\n");
	} else {
		printf("<destination> <message-type> <parameters>\n\n");
	}
	printf("\t<destination> is one of \"nmbd\", \"smbd\" or a process ID\n");
	printf("\t<message-type> is one of: ");
	for (i=0; msg_types[i].name; i++) 
	    printf("%s%s", i?", ":"",msg_types[i].name);
	printf("\n");
	if (doexit) exit(1);
}

static int pong_count;
static BOOL got_level;
static BOOL pong_registered = False;
static BOOL debuglevel_registered = False;
static BOOL profilelevel_registered = False;


/****************************************************************************
a useful function for testing the message system
****************************************************************************/
void pong_function(int msg_type, pid_t src, void *buf, size_t len)
{
	pong_count++;
	printf("PONG from PID %u\n",(unsigned int)src);
}

/****************************************************************************
Prints out the current Debug level returned by MSG_DEBUGLEVEL
****************************************************************************/
void debuglevel_function(int msg_type, pid_t src, void *buf, size_t len)
{
	int i;
	int debuglevel_class[DBGC_LAST];

	memcpy(debuglevel_class, buf, len);

	printf("Current debug level of PID %u is %d ",(unsigned int)src, debuglevel_class[0]);
	for (i=1;i<DBGC_LAST;i++)
		if (debuglevel_class[i])
			printf("%s:%d ", debug_classname_from_index(i), debuglevel_class[i]);
	printf("\n");

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
	    }
	    printf("Profiling %s on PID %u\n",s,(unsigned int)src);
	} else {
	    printf("Profiling not available on PID %u\n",(unsigned int)src);
	}
	got_level = True;
}

/****************************************************************************
send a message to a named destination
****************************************************************************/
static BOOL send_message(char *dest, int msg_type, void *buf, int len, BOOL duplicates)
{
	BOOL retval = False;
	pid_t pid = 0;
	TDB_CONTEXT *the_tdb;

	the_tdb = tdb_open_log(lock_path("connections.tdb"), 0, TDB_DEFAULT, O_RDWR, 0);
	if (!the_tdb) {
		fprintf(stderr,"Failed to open connections database in send_message.\n");
		return False;
	}

	/* "smbd" is the only broadcast operation */
	if (strequal(dest,"smbd")) {
		retval = message_send_all(the_tdb,msg_type, buf, len, duplicates, NULL);
	} else if (strequal(dest,"nmbd")) {
		pid = pidfile_pid(dest);
		if (pid == 0) {
			fprintf(stderr,"Can't find pid for nmbd\n");
		}
	} else if (strequal(dest,"self")) {
		pid = getpid();
	} else {
		pid = atoi(dest);
		if (pid == 0) {
			fprintf(stderr,"Not a valid pid\n");
		}		
	} 

	tdb_close(the_tdb);
	if (pid)
		return message_send_pid(pid, msg_type, buf, len, duplicates);
	else
		return retval;
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


/****************************************************************************
do command
****************************************************************************/
static BOOL do_command(char *dest, char *msg_name, int iparams, char **params)
{
	int i, n, v;
	int mtype;
	BOOL retval=False;
	int debuglevel_class[DBGC_LAST];

	mtype = parse_type(msg_name);
	if (mtype == -1) {
		fprintf(stderr,"Couldn't resolve message type: %s\n", msg_name);
		return(False);
	}

	switch (mtype) {
	case MSG_DEBUG:
		if (!params || !params[0]) {
			fprintf(stderr,"MSG_DEBUG needs a parameter\n");
			return(False);
		}

		ZERO_ARRAY(debuglevel_class);
		if (!debug_parse_params(params, debuglevel_class)) {
			fprintf(stderr, "MSG_DEBUG error. Expected <class name>:level\n");
			return(False);
		} else
			send_message(dest, MSG_DEBUG, debuglevel_class, sizeof(debuglevel_class), False);
		break;

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

	case MSG_PRINTER_NOTIFY:
		if (!strequal(dest, "smbd")) {
			fprintf(stderr,"printer-notify can only be sent to smbd\n");
			return(False);
		}
		if (!params || !params[0]) {
			fprintf(stderr, "printer-notify needs a printer name\n");
			return (False);
		}
		{
			char msg[8 + sizeof(fstring)+4];
			SIVAL(msg,0,PRINTER_CHANGE_ALL);
			SIVAL(msg,4,0);
			fstrcpy(&msg[8], params[0]);
			SIVAL(msg,8+strlen(params[0])+1, PRINTER_MESSAGE_DRIVER);

			retval = send_message(dest, MSG_PRINTER_NOTIFY, msg, 8 + strlen(params[0]) + 1 + 4, False);
		}
		break;

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
			if (retval == False) break;
		}
		if (retval) {
			timeout_start = time(NULL);
			while (pong_count < n) {
				message_dispatch();
				if ((time(NULL) - timeout_start) > MAX_WAIT) {
					fprintf(stderr,"PING timeout\n");
					break;
				}
			}
		}
		break;

	}
	
	return (True);
}

 int main(int argc, char *argv[])
{
	int opt;
	char temp[255];
	extern char *optarg;
	extern int optind;
	pstring servicesf = CONFIGFILE;
	BOOL interactive = False;

	TimeInit();
	setup_logging(argv[0],True);
	
	AllowDebugChange = False;
	DEBUGLEVEL = 0;
	charset_initialise();

	if (argc < 2) usage(True);

	while ((opt = getopt(argc, argv,"is:d:")) != EOF) {
		switch (opt) {
		case 'd':
			DEBUGLEVEL = atoi(optarg);
			break;
		case 'i':
			interactive = True;
			break;
		case 's':
			pstrcpy(servicesf, optarg);
			break;
		default:
			printf("Unknown option %c (%d)\n", (char)opt, opt);
			usage(True);
		}
	}

	lp_load(servicesf,False,False,False);

	if (!message_init()) exit(1);

	argc -= optind;
	argv = &argv[optind];

	if (!interactive) {
		if (argc < 2) usage(True);
		/*
		 * We want to return !do_command so we get the 
		 * right shell semantics (0 = success, 1 = fail)
		 */
		return (!do_command(argv[0],argv[1], argc-2, argc > 2 ? &argv[2] : 0));
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

