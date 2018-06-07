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

bool ctdb_sys_have_ip(ctdb_sock_addr *addr);

int ctdb_sys_send_arp(const ctdb_sock_addr *addr, const char *iface);

int ctdb_sys_send_tcp(const ctdb_sock_addr *dest,
		      const ctdb_sock_addr *src,
		      uint32_t seq,
		      uint32_t ack,
		      int rst);

int ctdb_sys_open_capture_socket(const char *iface, void **private_data);
int ctdb_sys_close_capture_socket(void *private_data);
int ctdb_sys_read_tcp_packet(int s,
			     void *private_data,
			     ctdb_sock_addr *src,
			     ctdb_sock_addr *dst,
			     uint32_t *ack_seq,
			     uint32_t *seq,
			     int *rst,
			     uint16_t *window);

#endif /* __CTDB_SYSTEM_SOCKET_H__ */
