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

#define NO_SYSLOG

#include "includes.h"

static struct {
	char *name;
	int value;
} msg_types[] = {
	{"debug", MSG_DEBUG},
	{"force-election", MSG_FORCE_ELECTION},
	{"ping", MSG_PING},
	{NULL, -1}
};

static void usage(void)
{
	int i;
	printf("Usage: smbcontrol <destination> <message-type> <parameters>\n\n");
	printf("\t<destination> is one of \"nmbd\", \"smbd\" or a process ID\n");
	printf("\t<message-type> is one of: ");
	for (i=0; msg_types[i].name; i++) printf("%s, ", msg_types[i].name);
	printf("\n");
	exit(1);
}

static int pong_count;

/****************************************************************************
a useful function for testing the message system
****************************************************************************/
void pong_function(int msg_type, pid_t src, void *buf, size_t len)
{
	pong_count++;
}

/****************************************************************************
send a message to a named destination
****************************************************************************/
static BOOL send_message(char *dest, int msg_type, void *buf, int len)
{
	pid_t pid;

	/* "smbd" is the only broadcast operation */
	if (strequal(dest,"smbd")) {
		return message_send_all(msg_type, buf, len);
	} else if (strequal(dest,"nmbd")) {
		pid = pidfile_pid(dest);
		if (pid == 0) {
			fprintf(stderr,"Can't find pid for nmbd\n");
			return False;
		}
	} else {
		pid = atoi(dest);
		if (pid == 0) {
			fprintf(stderr,"Not a valid pid\n");
			return False;
		}		
	} 

	return message_send_pid(pid, msg_type, buf, len);
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


 int main(int argc, char *argv[])
{
	char *dest;
	int i, n, v;
	pstring servicesf = CONFIGFILE;
	int mtype;

	TimeInit();
	setup_logging(argv[0],True);
	
	charset_initialise();
	lp_load(servicesf,False,False,False);

	message_init();

	if (argc < 3) usage();

	dest = argv[1];
	mtype = parse_type(argv[2]);
	if (mtype == -1) {
		fprintf(stderr,"Couldn't resolve message type: %s\n", argv[2]);
		exit(1);
	}

	argc -= 2;
	argv += 2;
	
	switch (mtype) {
	case MSG_DEBUG:
		if (argc < 2) {
			fprintf(stderr,"MSG_DEBUG needs a parameter\n");
			exit(1);
		}
		v = atoi(argv[1]);
		send_message(dest, MSG_DEBUG, &v, sizeof(int));
		break;

	case MSG_FORCE_ELECTION:
		if (!strequal(dest, "nmbd")) {
			fprintf(stderr,"force-election can only be sent to nmbd\n");
			exit(1);
		}
		send_message(dest, MSG_FORCE_ELECTION, NULL, 0);
		break;

	case MSG_PING:
		message_register(MSG_PONG, pong_function);
		n = atoi(argv[1]);
		for (i=0;i<n;i++) {
			send_message(dest, MSG_PING, NULL, 0);
		}
		while (pong_count < n) message_dispatch();
		break;

	}
	
	return (0);
}

