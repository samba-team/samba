/*
   CTDB TCP connection killing code

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Martin Schwenke  2016

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _CTDB_KILLTCP_H_
#define _CTDB_KILLTCP_H_

#include <talloc.h>
#include <tevent.h>

#include "replace.h"
#include "system/network.h"

#include "common/rb_tree.h"

#include "protocol/protocol.h"

/* Contains the listening socket and the list of TCP connections to
 * kill */
struct ctdb_kill_tcp {
	int capture_fd;
	struct tevent_fd *fde;
	trbt_tree_t *connections;
	void *private_data;
	void *destructor_data;
};


/* Add a TCP socket to the list of connections we want to RST.  The
 * list is attached to *killtcp_arg.  If this is NULL then allocate
 * the structure.  */
int ctdb_killtcp(struct tevent_context *ev,
		 TALLOC_CTX *mem_ctx,
		 const char *iface,
		 const ctdb_sock_addr *src,
		 const ctdb_sock_addr *dst,
		 struct ctdb_kill_tcp **killtcp_arg);

#endif /* _CTDB_KILLTCP_H_ */
