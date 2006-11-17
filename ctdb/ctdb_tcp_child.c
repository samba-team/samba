/* 
   ctdb over TCP

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
#include "system/filesys.h"
#include "ctdb_private.h"

struct ctdb_child_state {
	int sock;
	struct event_context *ev;
};


/*
  create a unix domain socket and bind it
  return a file descriptor open on the socket 
*/
static int ux_socket_bind(const char *name)
{
	int fd;
        struct sockaddr_un addr;

	/* get rid of any old socket */
	unlink(name);

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd == -1) return -1;

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, name, sizeof(addr.sun_path));

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		close(fd);
		return -1;
	}	

	return fd;
}

/*
  start the ctdb tcp child daemon
*/
int ctdb_tcp_child(void)
{
	struct ctdb_child_state *state;

	state = talloc(NULL, struct ctdb_child_state);
	state->sock = ux_socket_bind(CTDB_SOCKET);

	return 0;
}
