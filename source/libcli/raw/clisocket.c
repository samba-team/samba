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
#include "libcli/raw/libcliraw.h"

/*
  create a smbcli_socket context
*/
struct smbcli_socket *smbcli_sock_init(TALLOC_CTX *mem_ctx)
{
	struct smbcli_socket *sock;

	sock = talloc_p(mem_ctx, struct smbcli_socket);
	if (!sock) {
		return NULL;
	}

	ZERO_STRUCTP(sock);
	sock->sock = NULL;
	sock->port = 0;

	/* 20 second default timeout */
	sock->timeout = 20000;
	sock->hostname = NULL;

	return sock;
}

/*
  connect a smbcli_socket context to an IP/port pair
  if port is 0 then choose 445 then 139
*/
BOOL smbcli_sock_connect(struct smbcli_socket *sock, struct ipv4_addr *ip, int port)
{
	NTSTATUS status;

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

	status = socket_create("ip", SOCKET_TYPE_STREAM, &sock->sock, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	talloc_steal(sock, sock->sock);

	status = socket_connect(sock->sock, NULL, 0, sys_inet_ntoa(*ip), port, 0);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(sock->sock);
		sock->sock = NULL;
		return False;
	}

	sock->dest_ip = *ip;
	sock->port = port;

	socket_set_option(sock->sock, lp_socket_options(), NULL);

	return True;
}


/****************************************************************************
 mark the socket as dead
****************************************************************************/
void smbcli_sock_dead(struct smbcli_socket *sock)
{
	if (sock->sock != NULL) {
		talloc_free(sock->sock);
		sock->sock = NULL;
	}
}

/****************************************************************************
 Set socket options on a open connection.
****************************************************************************/
void smbcli_sock_set_options(struct smbcli_socket *sock, const char *options)
{
	socket_set_option(sock->sock, options, NULL);
}

/****************************************************************************
 Write to socket. Return amount written.
****************************************************************************/
ssize_t smbcli_sock_write(struct smbcli_socket *sock, const char *data, size_t len)
{
	NTSTATUS status;
	DATA_BLOB blob;
	size_t nsent;

	if (sock->sock == NULL) {
		errno = EIO;
		return -1;
	}

	blob.data = discard_const(data);
	blob.length = len;

	status = socket_send(sock->sock, &blob, &nsent, 0);
	if (NT_STATUS_IS_ERR(status)) {
		return -1;
	}

	return nsent;
}


/****************************************************************************
 Read from socket. return amount read
****************************************************************************/
ssize_t smbcli_sock_read(struct smbcli_socket *sock, char *data, size_t len)
{
	NTSTATUS status;
	size_t nread;

	if (sock->sock == NULL) {
		errno = EIO;
		return -1;
	}

	status = socket_recv(sock->sock, data, len, &nread, 0);
	if (NT_STATUS_IS_ERR(status)) {
		return -1;
	}

	return nread;
}

/****************************************************************************
resolve a hostname and connect 
****************************************************************************/
BOOL smbcli_sock_connect_byname(struct smbcli_socket *sock, const char *host, int port)
{
	int name_type = 0x20;
	struct ipv4_addr ip;
	char *name, *p;
	BOOL ret;

#if 0
	if (getenv("LIBSMB_PROG")) {
		sock->fd = sock_exec(getenv("LIBSMB_PROG"));
		return sock->fd != -1;
	}
#endif

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
