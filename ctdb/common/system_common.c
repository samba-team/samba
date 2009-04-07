/* 
   ctdb system specific code to manage raw sockets on linux

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007

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

#include "includes.h"
#include "system/network.h"

/*
  uint16 checksum for n bytes
 */
uint32_t uint16_checksum(uint16_t *data, size_t n)
{
	uint32_t sum=0;
	while (n>=2) {
		sum += (uint32_t)ntohs(*data);
		data++;
		n -= 2;
	}
	if (n == 1) {
		sum += (uint32_t)ntohs(*(uint8_t *)data);
	}
	return sum;
}

/*
  see if we currently have an interface with the given IP

  we try to bind to it, and if that fails then we don't have that IP
  on an interface
 */
bool ctdb_sys_have_ip(ctdb_sock_addr *_addr)
{
	int s;
	int ret;
	ctdb_sock_addr __addr = *_addr;
	ctdb_sock_addr *addr = &__addr;

	switch (addr->sa.sa_family) {
	case AF_INET:
		addr->ip.sin_port = 0;
		break;
	case AF_INET6:
		addr->ip6.sin6_port = 0;
		break;
	}

	s = socket(addr->sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1) {
		return false;
	}

	ret = bind(s, (struct sockaddr *)addr, sizeof(ctdb_sock_addr));

	close(s);
	return ret == 0;
}
