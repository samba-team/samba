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
  create a cli_socket context
*/
struct cli_socket *cli_sock_init(void)
{
	struct cli_socket *sock;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("cli_socket");
	if (!mem_ctx) return NULL;

	sock = talloc_zero(mem_ctx, sizeof(*sock));
	if (!sock) {
		talloc_destroy(mem_ctx);
		return NULL;
	}

	sock->mem_ctx = mem_ctx;
	sock->fd = -1;
	sock->port = 0;
	/* 20 second default timeout */
	sock->timeout = 20000;

	sock->hostname = NULL;

	return sock;
}

/*
  connect a cli_socket context to an IP/port pair
  if port is 0 then choose 445 then 139
*/
BOOL cli_sock_connect(struct cli_socket *sock, struct in_addr *ip, int port)
{
	if (getenv("LIBSMB_PROG")) {
		sock->fd = sock_exec(getenv("LIBSMB_PROG"));
		return sock->fd != -1;
	}

	if (port == 0) {
		return cli_sock_connect(sock, ip, 445) ||
			cli_sock_connect(sock, ip, 139);
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

	return True;
}


/****************************************************************************
 mark the socket as dead
****************************************************************************/
void cli_sock_dead(struct cli_socket *sock)
{
	if (sock->fd != -1) {
		close(sock->fd);
		sock->fd = -1;
	}
}

/****************************************************************************
 reduce socket reference count - if it becomes zero then close
****************************************************************************/
void cli_sock_close(struct cli_socket *sock)
{
	sock->reference_count--;
	if (sock->reference_count <= 0) {
		cli_sock_dead(sock);
	}
}

/****************************************************************************
 Set socket options on a open connection.
****************************************************************************/
void cli_sock_set_options(struct cli_socket *sock, const char *options)
{
	set_socket_options(sock->fd, options);
}

/****************************************************************************
 Write to socket. Return amount written.
****************************************************************************/
ssize_t cli_sock_write(struct cli_socket *sock, const char *data, size_t len)
{
	if (sock->fd == -1) {
		errno = EIO;
		return -1;
	}

	return write_data(sock->fd, data, len);
}


/****************************************************************************
 Read from socket. return amount read
****************************************************************************/
ssize_t cli_sock_read(struct cli_socket *sock, char *data, size_t len)
{
	if (sock->fd == -1) {
		errno = EIO;
		return -1;
	}

	return read_data(sock->fd, data, len);
}

/****************************************************************************
resolve a hostname and connect 
****************************************************************************/
BOOL cli_sock_connect_byname(struct cli_socket *sock, const char *host, int port)
{
	int name_type = 0x20;
	struct in_addr ip;
	TALLOC_CTX *mem_ctx;
	char *name, *p;
	BOOL ret;

	if (getenv("LIBSMB_PROG")) {
		sock->fd = sock_exec(getenv("LIBSMB_PROG"));
		return sock->fd != -1;
	}

	mem_ctx = talloc_init("cli_sock_connect_byname");
	if (!mem_ctx) return False;

	name = talloc_strdup(mem_ctx, host);

	/* allow hostnames of the form NAME#xx and do a netbios lookup */
	if ((p = strchr(name, '#'))) {
		name_type = strtol(p+1, NULL, 16);
		*p = 0;
	}

	if (!resolve_name(mem_ctx, name, &ip, name_type)) {
		talloc_destroy(mem_ctx);
		return False;
	}

	ret = cli_sock_connect(sock, &ip, port);

	if (ret) {
		sock->hostname = talloc_steal(mem_ctx, sock->mem_ctx, name);
	}

	talloc_destroy(mem_ctx);

	return ret;
}
