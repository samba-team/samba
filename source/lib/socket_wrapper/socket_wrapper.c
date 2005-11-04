/* 
   Socket wrapper library. Passes all socket communication over 
   unix domain sockets if the environment variable SOCKET_WRAPPER_DIR 
   is set.
   Copyright (C) Jelmer Vernooij 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifdef _SAMBA_BUILD_
#include "includes.h"
#undef SOCKET_WRAPPER
#include "system/network.h"
#include "system/filesys.h"
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#endif
#include "dlinklist.h"

/* LD_PRELOAD doesn't work yet, so REWRITE_CALLS is all we support
 * for now */
#define REWRITE_CALLS 

#ifdef REWRITE_CALLS
#define real_accept accept
#define real_connect connect
#define real_bind bind
#define real_getpeername getpeername
#define real_getsockname getsockname
#define real_getsockopt getsockopt
#define real_setsockopt setsockopt
#define real_recvfrom recvfrom
#define real_sendto sendto
#define real_socket socket
#define real_close close
#endif

/* we need to use a very terse format here as IRIX 6.4 silently
   truncates names to 16 chars, so if we use a longer name then we
   can't tell which port a packet came from with recvfrom() 
   
   with this format we have 8 chars left for the directory name
*/
#define SOCKET_FORMAT "%u_%05u"

static struct sockaddr *sockaddr_dup(const void *data, socklen_t len)
{
	struct sockaddr *ret = (struct sockaddr *)malloc(len);
	memcpy(ret, data, len);
	return ret;
}

struct socket_info
{
	int fd;

	int domain;
	int type;
	int protocol;
	int bound;

	char *path;
	char *tmp_path;

	struct sockaddr *myname;
	socklen_t myname_len;

	struct sockaddr *peername;
	socklen_t peername_len;

	struct socket_info *prev, *next;
};

static struct socket_info *sockets = NULL;


static const char *socket_wrapper_dir(void)
{
	const char *s = getenv("SOCKET_WRAPPER_DIR");
	if (s == NULL) {
		return NULL;
	}
	if (strncmp(s, "./", 2) == 0) {
		s += 2;
	}
	return s;
}

static int convert_un_in(const struct sockaddr_un *un, struct sockaddr_in *in, socklen_t *len)
{
	unsigned int prt;
	const char *p;
	int type;

	if ((*len) < sizeof(struct sockaddr_in)) {
		return 0;
	}

	in->sin_family = AF_INET;
	in->sin_port = htons(1025); /* Default to 1025 */
	p = strrchr(un->sun_path, '/');
	if (p) p++; else p = un->sun_path;

	if (sscanf(p, SOCKET_FORMAT, &type, &prt) == 2) {
		in->sin_port = htons(prt);
	}
	in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	*len = sizeof(struct sockaddr_in);
	return 0;
}

static int convert_in_un(struct socket_info *si, const struct sockaddr_in *in, struct sockaddr_un *un)
{
	int type = si->type;
	uint16_t prt = ntohs(in->sin_port);
	if (prt == 0) {
		struct stat st;
		/* handle auto-allocation of ephemeral ports */
		prt = 5000;
		do {
			snprintf(un->sun_path, sizeof(un->sun_path), "%s/"SOCKET_FORMAT, 
				 socket_wrapper_dir(), type, ++prt);
		} while (stat(un->sun_path, &st) == 0 && prt < 10000);
		((struct sockaddr_in *)si->myname)->sin_port = htons(prt);
	} 
	snprintf(un->sun_path, sizeof(un->sun_path), "%s/"SOCKET_FORMAT, 
		 socket_wrapper_dir(), type, prt);
	return 0;
}

static struct socket_info *find_socket_info(int fd)
{
	struct socket_info *i;
	for (i = sockets; i; i = i->next) {
		if (i->fd == fd) 
			return i;
	}

	return NULL;
}

static int sockaddr_convert_to_un(struct socket_info *si, const struct sockaddr *in_addr, socklen_t in_len, 
					 struct sockaddr_un *out_addr)
{
	if (!out_addr)
		return 0;

	out_addr->sun_family = AF_UNIX;

	switch (in_addr->sa_family) {
	case AF_INET:
		return convert_in_un(si, (const struct sockaddr_in *)in_addr, out_addr);
	case AF_UNIX:
		memcpy(out_addr, in_addr, sizeof(*out_addr));
		return 0;
	default:
		break;
	}
	
	errno = EAFNOSUPPORT;
	return -1;
}

static int sockaddr_convert_from_un(const struct socket_info *si, 
				    const struct sockaddr_un *in_addr, 
				    socklen_t un_addrlen,
				    int family,
				    struct sockaddr *out_addr,
				    socklen_t *out_len)
{
	if (out_addr == NULL || out_len == NULL) 
		return 0;

	if (un_addrlen == 0) {
		*out_len = 0;
		return 0;
	}

	switch (family) {
	case AF_INET:
		return convert_un_in(in_addr, (struct sockaddr_in *)out_addr, out_len);
	case AF_UNIX:
		memcpy(out_addr, in_addr, sizeof(*in_addr));
		*out_len = sizeof(*in_addr);
		return 0;
	default:
		break;
	}

	errno = EAFNOSUPPORT;
	return -1;
}

int swrap_socket(int domain, int type, int protocol)
{
	struct socket_info *si;
	int fd;

	if (!socket_wrapper_dir()) {
		return real_socket(domain, type, protocol);
	}
	
	fd = real_socket(AF_UNIX, type, 0);

	if (fd == -1) return -1;

	si = calloc(1, sizeof(struct socket_info));

	si->domain = domain;
	si->type = type;
	si->protocol = protocol;
	si->fd = fd;

	DLIST_ADD(sockets, si);

	return si->fd;
}

int swrap_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	struct socket_info *parent_si, *child_si;
	int fd;
	socklen_t un_addrlen = sizeof(struct sockaddr_un);
	struct sockaddr_un un_addr;
	int ret;

	parent_si = find_socket_info(s);
	if (!parent_si) {
		return real_accept(s, addr, addrlen);
	}

	memset(&un_addr, 0, sizeof(un_addr));

	ret = real_accept(s, (struct sockaddr *)&un_addr, &un_addrlen);
	if (ret == -1) return ret;

	fd = ret;

	ret = sockaddr_convert_from_un(parent_si, &un_addr, un_addrlen,
				       parent_si->domain, addr, addrlen);
	if (ret == -1) return ret;

	child_si = malloc(sizeof(struct socket_info));
	memset(child_si, 0, sizeof(*child_si));

	child_si->fd = fd;
	child_si->bound = 1;

	child_si->myname_len = parent_si->myname_len;
	child_si->myname = sockaddr_dup(parent_si->myname, parent_si->myname_len);

	child_si->peername_len = *addrlen;
	child_si->peername = sockaddr_dup(addr, *addrlen);

	DLIST_ADD(sockets, child_si);

	return fd;
}

/* using sendto() or connect() on an unbound socket would give the
   recipient no way to reply, as unlike UDP and TCP, a unix domain
   socket can't auto-assign emphemeral port numbers, so we need to
   assign it here */
static int swrap_auto_bind(struct socket_info *si)
{
	struct sockaddr_un un_addr;
	struct sockaddr_in in;
	int i;
	
	un_addr.sun_family = AF_UNIX;
	
	for (i=0;i<1000;i++) {
		snprintf(un_addr.sun_path, sizeof(un_addr.sun_path), 
			 "%s/"SOCKET_FORMAT, socket_wrapper_dir(),
			 SOCK_DGRAM, i + 10000);
		if (bind(si->fd, (struct sockaddr *)&un_addr, 
			 sizeof(un_addr)) == 0) {
			si->tmp_path = strdup(un_addr.sun_path);
			si->bound = 1;
			break;
		}
	}
	if (i == 1000) {
		return -1;
	}
	
	memset(&in, 0, sizeof(in));
	in.sin_family = AF_INET;
	in.sin_port   = htons(i);
	in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	
	si->myname_len = sizeof(in);
	si->myname = sockaddr_dup(&in, si->myname_len);
	si->bound = 1;
	return 0;
}


int swrap_connect(int s, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	int ret;
	struct sockaddr_un un_addr;
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return real_connect(s, serv_addr, addrlen);
	}

	/* only allow pseudo loopback connections */
	if (serv_addr->sa_family == AF_INET &&
		((const struct sockaddr_in *)serv_addr)->sin_addr.s_addr != 
	    htonl(INADDR_LOOPBACK)) {
		errno = ENETUNREACH;
		return -1;
	}

	if (si->bound == 0 && si->domain != AF_UNIX) {
		ret = swrap_auto_bind(si);
		if (ret == -1) return -1;
	}

	ret = sockaddr_convert_to_un(si, (const struct sockaddr *)serv_addr, addrlen, &un_addr);
	if (ret == -1) return -1;

	ret = real_connect(s, (struct sockaddr *)&un_addr, 
			   sizeof(struct sockaddr_un));

	if (ret == 0) {
		si->peername_len = addrlen;
		si->peername = sockaddr_dup(serv_addr, addrlen);
	}

	return ret;
}

int swrap_bind(int s, const struct sockaddr *myaddr, socklen_t addrlen)
{
	int ret;
	struct sockaddr_un un_addr;
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return real_bind(s, myaddr, addrlen);
	}

	si->myname_len = addrlen;
	si->myname = sockaddr_dup(myaddr, addrlen);

	if (myaddr->sa_family == AF_INET &&
	    ((const struct sockaddr_in *)myaddr)->sin_addr.s_addr == 0) {
		((struct sockaddr_in *)si->myname)->sin_addr.s_addr = 
			htonl(INADDR_LOOPBACK);
	}
	ret = sockaddr_convert_to_un(si, (const struct sockaddr *)myaddr, addrlen, &un_addr);
	if (ret == -1) return -1;

	unlink(un_addr.sun_path);

	ret = real_bind(s, (struct sockaddr *)&un_addr,
			sizeof(struct sockaddr_un));

	if (ret == 0) {
		si->bound = 1;
	}

	return ret;
}

int swrap_getpeername(int s, struct sockaddr *name, socklen_t *addrlen)
{
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return real_getpeername(s, name, addrlen);
	}

	if (!si->peername) 
	{
		errno = ENOTCONN;
		return -1;
	}

	memcpy(name, si->peername, si->peername_len);
	*addrlen = si->peername_len;

	return 0;
}

int swrap_getsockname(int s, struct sockaddr *name, socklen_t *addrlen)
{
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return real_getsockname(s, name, addrlen);
	}

	memcpy(name, si->myname, si->myname_len);
	*addrlen = si->myname_len;

	return 0;
}

int swrap_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return real_getsockopt(s, level, optname, optval, optlen);
	}

	if (level == SOL_SOCKET) {
		return real_getsockopt(s, level, optname, optval, optlen);
	} 

	switch (si->domain) {
	case AF_UNIX:
		return real_getsockopt(s, level, optname, optval, optlen);
	default:
		errno = ENOPROTOOPT;
		return -1;
	}
}

int swrap_setsockopt(int s, int  level,  int  optname,  const  void  *optval, socklen_t optlen)
{
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return real_setsockopt(s, level, optname, optval, optlen);
	}

	if (level == SOL_SOCKET) {
		return real_setsockopt(s, level, optname, optval, optlen);
	}

	switch (si->domain) {
	case AF_UNIX:
		return real_setsockopt(s, level, optname, optval, optlen);
	case AF_INET:
		/* Silence some warnings */
#ifdef TCP_NODELAY
		if (optname == TCP_NODELAY) 
			return 0;
#endif
	default:
		errno = ENOPROTOOPT;
		return -1;
	}
}

ssize_t swrap_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
	struct sockaddr_un un_addr;
	socklen_t un_addrlen = sizeof(un_addr);
	int ret;
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return real_recvfrom(s, buf, len, flags, from, fromlen);
	}

	/* irix 6.4 forgets to null terminate the sun_path string :-( */
	memset(&un_addr, 0, sizeof(un_addr));
	ret = real_recvfrom(s, buf, len, flags, (struct sockaddr *)&un_addr, &un_addrlen);
	if (ret == -1) 
		return ret;

	if (sockaddr_convert_from_un(si, &un_addr, un_addrlen,
				     si->domain, from, fromlen) == -1) {
		return -1;
	}
	
	return ret;
}


ssize_t swrap_sendto(int  s,  const  void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen)
{
	struct sockaddr_un un_addr;
	int ret;
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return real_sendto(s, buf, len, flags, to, tolen);
	}

	if (si->bound == 0 && si->domain != AF_UNIX) {
		ret = swrap_auto_bind(si);
		if (ret == -1) return -1;
	}

	ret = sockaddr_convert_to_un(si, to, tolen, &un_addr);
	if (ret == -1) return -1;

	ret = real_sendto(s, buf, len, flags, (struct sockaddr *)&un_addr, sizeof(un_addr));

	return ret;
}

int swrap_close(int fd)
{
	struct socket_info *si = find_socket_info(fd);

	if (si) {
		DLIST_REMOVE(sockets, si);

		free(si->path);
		free(si->myname);
		free(si->peername);
		if (si->tmp_path) {
			unlink(si->tmp_path);
			free(si->tmp_path);
		}
		free(si);
	}

	return real_close(fd);
}
