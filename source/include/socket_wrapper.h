/* 
   Copyright (C) Jelmer Vernooij 2005 <jelmer@samba.org>
   
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

#ifndef __SOCKET_WRAPPER_H__
#define __SOCKET_WRAPPER_H__

int swrap_socket(int domain, int type, int protocol);
int swrap_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int swrap_connect(int s, const struct sockaddr *serv_addr, socklen_t addrlen);
int swrap_bind(int s, const struct sockaddr *myaddr, socklen_t addrlen);
int swrap_getpeername(int s, struct sockaddr *name, socklen_t *addrlen);
int swrap_getsockname(int s, struct sockaddr *name, socklen_t *addrlen);
int swrap_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen);
int swrap_setsockopt(int s, int  level,  int  optname,  const  void  *optval, socklen_t optlen);
ssize_t swrap_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
ssize_t swrap_sendto(int  s,  const  void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);
int swrap_close(int);

#ifdef SOCKET_WRAPPER_REPLACE
#define accept 				swrap_accept
#define connect 			swrap_connect
#define bind 				swrap_bind
#define getpeername 		swrap_getpeername
#define getsockname 		swrap_getsockname
#define getsockopt 			swrap_getsockopt
#define setsockopt 			swrap_setsockopt
#define recvfrom 			swrap_recvfrom
#define sendto 				swrap_sendto
#define socket				swrap_socket
#define close				swrap_close
#endif

#endif /* __SOCKET_WRAPPER_H__ */
