/*
   Unix SMB/CIFS implementation.
   Utility functions for Samba
   Copyright (C) Samuel Cabrero 2019
   Copyright (C) Volker Lendecke 2020

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SAMBA_SOCKADDR_H_
#define _SAMBA_SOCKADDR_H_

#include <stdbool.h>
#include <stdint.h>

#include "system/network.h"

struct samba_sockaddr {
	socklen_t sa_socklen;
	union {
		struct sockaddr sa;
		struct sockaddr_in in;
#ifdef HAVE_IPV6
		struct sockaddr_in6 in6;
#endif
		struct sockaddr_un un;
#ifdef HAVE_PACKETSOCKET
		struct sockaddr_ll ll;
#endif
		struct sockaddr_storage ss;
	} u;
};

struct ssaddr_buf { char buf[INET6_ADDRSTRLEN]; };
char *ssaddr_str_buf(const struct samba_sockaddr *addr,
		     struct ssaddr_buf *dst);

bool sockaddr_storage_to_samba_sockaddr(struct samba_sockaddr *sa,
					const struct sockaddr_storage *ss);
bool samba_sockaddr_set_port(struct samba_sockaddr *sa, uint16_t port);
bool samba_sockaddr_get_port(const struct samba_sockaddr *sa, uint16_t *port);

#endif /* _SAMBA_SOCKADDR_H_ */
