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

const char *ctdb_sock_addr_to_string(TALLOC_CTX *mem_ctx, ctdb_sock_addr *addr);
int ctdb_sock_addr_cmp_ip(const ctdb_sock_addr *addr1,
			  const ctdb_sock_addr *addr2);
int ctdb_sock_addr_cmp(const ctdb_sock_addr *addr1,
		       const ctdb_sock_addr *addr2);
bool ctdb_sock_addr_same_ip(const ctdb_sock_addr *addr1,
			    const ctdb_sock_addr *addr2);
bool ctdb_sock_addr_same(const ctdb_sock_addr *addr1,
			 const ctdb_sock_addr *addr2);

#endif /* __CTDB_PROTOCOL_UTIL_H__ */
