/* 
   Unix SMB/CIFS implementation.
   SMB client socket context management functions
   Copyright (C) Andrew Tridgell 1994-2003
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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

#include "includes.h"

/*
  destroy a socket
 */
static int sock_destructor(void *ptr)
{
	struct smbcli_socket *sock = ptr;
	if (sock->fd != -1) {
		close(sock->fd);
		sock->fd = -1;
	}
	return 0;
}

/*
  create a smbcli_socket context
*/
struct smbcli_socket *smbcli_sock_init(void)
{
	struct smbcli_socket *sock;

	sock = talloc_p(NULL, struct smbcli_socket);
	if (!sock) {
		return NULL;
	}

	ZERO_STRUCTP(sock);
	sock->fd = -1;
	sock->port = 0;

	/* 20 second default timeout */
	sock->timeout = 20000;
	sock->hostname = NULL;

	talloc_set_destructor(sock, sock_destructor);

	return sock;
}

/*
  connect a smbcli_socket context to an IP/port pair
  if port is 0 then choose 445 then 139
*/
BOOL smbcli_sock_connect(struct smbcli_socket *sock, struct in_addr *ip, int port)
{
	if (getenv("LIBSMB_PROG")) {
		sock->fd = sock_exec(getenv("LIBSMB_PROG"));
		return sock->fd != -1;
	}

	if (port == 0) {
		int i;
		const char **ports = lp_smb_ports();
		for (i=0;ports[i];i++) {
			port = atoi(ports[i]);
			if (port != 0 && smbcli_sock_connect(sock, ip, port)) {
				return True;
			}
		}
		return False;
	}

	sock->dest_ip = *ip;
	sock->port = port;
	sock->fd = open_socket_out(SOCK_STREAM,
				   &sock->dest_ip,
				   sock->port, 
				   LONG_CONNECT_TIMEOUT);
	if (sock->fd == -1) {
		return False;
	}

	set_blocking(sock->fd, False);
	set_socket_options(sock->fd, lp_socket_options());

	return True;
}


/****************************************************************************
 mark the socket as dead
****************************************************************************/
void smbcli_sock_dead(struct smbcli_socket *sock)
{
	if (sock->fd != -1) {
		close(sock->fd);
		sock->fd = -1;
	}
}

/****************************************************************************
 Set socket options on a open connection.
****************************************************************************/
void smbcli_sock_set_options(struct smbcli_socket *sock, const char *options)
{
	set_socket_options(sock->fd, options);
}

/****************************************************************************
 Write to socket. Return amount written.
****************************************************************************/
ssize_t smbcli_sock_write(struct smbcli_socket *sock, const char *data, size_t len)
{
	if (sock->fd == -1) {
		errno = EIO;
		return -1;
	}

	return write(sock->fd, data, len);
}


/****************************************************************************
 Read from socket. return amount read
****************************************************************************/
ssize_t smbcli_sock_read(struct smbcli_socket *sock, char *data, size_t len)
{
	if (sock->fd == -1) {
		errno = EIO;
		return -1;
	}

	return read(sock->fd, data, len);
}

/****************************************************************************
resolve a hostname and connect 
****************************************************************************/
BOOL smbcli_sock_connect_byname(struct smbcli_socket *sock, const char *host, int port)
{
	int name_type = 0x20;
	struct in_addr ip;
	char *name, *p;
	BOOL ret;

	if (getenv("LIBSMB_PROG")) {
		sock->fd = sock_exec(getenv("LIBSMB_PROG"));
		return sock->fd != -1;
	}

	name = talloc_strdup(sock, host);

	/* allow hostnames of the form NAME#xx and do a netbios lookup */
	if ((p = strchr(name, '#'))) {
		name_type = strtol(p+1, NULL, 16);
		*p = 0;
	}

	if (!resolve_name(name, name, &ip, name_type)) {
		talloc_free(name);
		return False;
	}

	ret = smbcli_sock_connect(sock, &ip, port);

	if (ret) {
		sock->hostname = talloc_steal(sock, name);
	} else {
		talloc_free(name);
	}

	return ret;
}
