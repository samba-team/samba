/* 
   test of messaging

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "system/network.h"
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"

#define CTDB_SOCKET "/tmp/ctdb.socket.127.0.0.1"


/*
  connect to the unix domain socket
*/
static int ux_socket_connect(const char *name)
{
	struct sockaddr_un addr;
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, name, sizeof(addr.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}
	
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		close(fd);
		return -1;
	}

	return fd;
}

void register_svid_with_daemon(int fd, int pid)
{
	struct ctdb_req_register r;

	bzero(&r, sizeof(r));
	r.hdr.length       = sizeof(r);
	r.hdr.ctdb_magic   = CTDB_MAGIC;
	r.hdr.ctdb_version = CTDB_VERSION;
	r.hdr.operation    = CTDB_REQ_REGISTER;
	r.srvid            = pid;

	/* XXX must deal with partial writes here */
	write(fd, &r, sizeof(r));
}

int main(int argc, const char *argv[])
{
	int fd, pid;

	/* open the socket to talk to the local ctdb daemon */
	fd=ux_socket_connect(CTDB_SOCKET);
	if (fd==-1) {
		printf("failed to open domain socket\n");
		exit(10);
	}

	/* register our local server id with the daemon */
	pid=getpid();
	register_svid_with_daemon(fd, pid);


	return 0;
}
