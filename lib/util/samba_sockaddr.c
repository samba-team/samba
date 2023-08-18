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

#include "config.h"

#include "lib/util/samba_sockaddr.h"

/*
 * Utility function that copes only with AF_INET and AF_INET6
 * as that's all we're going to get out of DNS / NetBIOS / WINS
 * name resolution functions.
 */

bool sockaddr_storage_to_samba_sockaddr(
	struct samba_sockaddr *sa, const struct sockaddr_storage *ss)
{
	sa->u.ss = *ss;

	switch (ss->ss_family) {
	case AF_INET:
		sa->sa_socklen = sizeof(struct sockaddr_in);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		sa->sa_socklen = sizeof(struct sockaddr_in6);
		break;
#endif
	default:
		return false;
	}
	return true;
}

bool samba_sockaddr_set_port(struct samba_sockaddr *sa, uint16_t port)
{
	if (sa->u.sa.sa_family == AF_INET) {
		sa->u.in.sin_port = htons(port);
		return true;
	}
#ifdef HAVE_IPV6
	if (sa->u.sa.sa_family == AF_INET6) {
		sa->u.in6.sin6_port = htons(port);
		return true;
	}
#endif
	return false;
}

bool samba_sockaddr_get_port(const struct samba_sockaddr *sa, uint16_t *port)
{
	if (sa->u.sa.sa_family == AF_INET) {
		*port = ntohs(sa->u.in.sin_port);
		return true;
	}
#ifdef HAVE_IPV6
	if (sa->u.sa.sa_family == AF_INET6) {
		*port = ntohs(sa->u.in6.sin6_port);
		return true;
	}
#endif
	return false;
}
