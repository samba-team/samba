/*
   CTDB protocol marshalling

   Copyright (C) Amitay Isaacs  2015

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

#ifndef __CTDB_PROTOCOL_UTIL_H__
#define __CTDB_PROTOCOL_UTIL_H__

#include <talloc.h>

#include "protocol/protocol.h"

const char *ctdb_runstate_to_string(enum ctdb_runstate runstate);
enum ctdb_runstate ctdb_runstate_from_string(const char *runstate_str);

const char *ctdb_event_to_string(enum ctdb_event event);
enum ctdb_event ctdb_event_from_string(const char *event_str);

/*
 * buflen must be long enough to hold the longest possible "address:port".
 * For example, 1122:3344:5566:7788:99aa:bbcc:ddee:ff00:12345.
 * 64 is sane value for buflen.
 */
int ctdb_sock_addr_to_buf(char *buf, socklen_t buflen,
			  ctdb_sock_addr *addr, bool with_port);
char *ctdb_sock_addr_to_string(TALLOC_CTX *mem_ctx,
				     ctdb_sock_addr *addr, bool with_port);
int ctdb_sock_addr_from_string(const char *str,
			       ctdb_sock_addr *addr, bool with_port);
int ctdb_sock_addr_mask_from_string(const char *str,
				    ctdb_sock_addr *addr,
				    unsigned int *mask);
unsigned int ctdb_sock_addr_port(ctdb_sock_addr *addr);
void ctdb_sock_addr_set_port(ctdb_sock_addr *addr, unsigned int port);
int ctdb_sock_addr_cmp_ip(const ctdb_sock_addr *addr1,
			  const ctdb_sock_addr *addr2);
int ctdb_sock_addr_cmp(const ctdb_sock_addr *addr1,
		       const ctdb_sock_addr *addr2);
bool ctdb_sock_addr_same_ip(const ctdb_sock_addr *addr1,
			    const ctdb_sock_addr *addr2);
bool ctdb_sock_addr_same(const ctdb_sock_addr *addr1,
			 const ctdb_sock_addr *addr2);

int ctdb_connection_to_buf(char *buf, size_t buflen,
			   struct ctdb_connection * conn, bool client_first);
char *ctdb_connection_to_string(TALLOC_CTX *mem_ctx,
				struct ctdb_connection * conn,
				bool client_first);
int ctdb_connection_from_string(const char *str, bool client_first,
				struct ctdb_connection *conn);

int ctdb_connection_list_add(struct ctdb_connection_list *conn_list,
			     struct ctdb_connection *conn);
int ctdb_connection_list_sort(struct ctdb_connection_list *conn_list);
char *ctdb_connection_list_to_string(
	TALLOC_CTX *mem_ctx,
	struct ctdb_connection_list *conn_list, bool client_first);
int ctdb_connection_list_read(TALLOC_CTX *mem_ctx,
			      int fd,
			      bool client_first,
			      struct ctdb_connection_list **conn_list);

#endif /* __CTDB_PROTOCOL_UTIL_H__ */
