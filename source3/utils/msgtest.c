/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Copyright (C) Andrew Tridgell 2000
   
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

/*
  test code for internal messaging
 */

#define NO_SYSLOG

#include "includes.h"

static int pong_count;

/****************************************************************************
a useful function for testing the message system
****************************************************************************/
void pong_message(int msg_type, pid_t src, void *buf, size_t len)
{
	pong_count++;
}

 int main(int argc, char *argv[])
{
	pid_t pid;
	int i, n;
	static pstring servicesf = CONFIGFILE;
	char buf[12];

	TimeInit();
	setup_logging(argv[0],True);
	
	charset_initialise();

	lp_load(servicesf,False,False,False);

	message_init();

	if (argc != 3) {
		fprintf(stderr, "%s: Usage - %s pid count\n", argv[0], argv[0]);
		exit(1);
	}

	pid = atoi(argv[1]);
	n = atoi(argv[2]);

	message_register(MSG_PONG, pong_message);

	for (i=0;i<n;i++) {
		message_send_pid(pid, MSG_PING, NULL, 0, True);
	}

	while (pong_count < i) {
		message_dispatch();
		msleep(1);
	}

	/* Now test that the duplicate filtering code works. */
	pong_count = 0;

	safe_strcpy(buf, "1234567890", sizeof(buf)-1);

	for (i=0;i<n;i++) {
		message_send_pid(getpid(), MSG_PING, NULL, 0, False);
		message_send_pid(getpid(), MSG_PING, buf, 11, False);
	}

	for (i=0;i<n;i++) {
		message_dispatch();
		msleep(1);
	}

	if (pong_count != 2) {
		fprintf(stderr, "Duplicate filter failed (%d).\n", pong_count);
		exit(1);
	}

	return (0);
}

