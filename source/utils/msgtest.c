/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   status reporting
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

   Revision History:

   12 aug 96: Erik.Devriendt@te6.siemens.be
   added support for shared memory implementation of share mode locking

   21-Jul-1998: rsharpe@ns.aus.com (Richard Sharpe)
   Added -L (locks only) -S (shares only) flags and code

*/

/*
 * This program reports current SMB connections
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

	TimeInit();
	setup_logging(argv[0],True);
	
	charset_initialise();

	lp_load(servicesf,False,False,False);

	message_init();

	pid = atoi(argv[1]);
	n = atoi(argv[2]);

	message_register(MSG_PONG, pong_message);

	for (i=0;i<n;i++) {
		message_send_pid(pid, MSG_PING, NULL, 0);
	}

	while (pong_count < n) {
		message_dispatch();
		msleep(1);
	}

	return (0);
}

