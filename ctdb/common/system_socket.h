/*
   System specific network code

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

#ifndef __CTDB_SYSTEM_SOCKET_H__
#define __CTDB_SYSTEM_SOCKET_H__

#include "protocol/protocol.h"

uint32_t uint16_checksum(uint16_t *data, size_t n);
bool ctdb_sys_have_ip(ctdb_sock_addr *addr);

bool parse_ip_mask(const char *str,
		   const char *ifaces,
		   ctdb_sock_addr *addr,
		   unsigned *mask);

#endif /* __CTDB_SYSTEM_SOCKET_H__ */
