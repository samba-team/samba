/* 
   Unix SMB/CIFS implementation.
   Socket functions
   Copyright (C) Stefan Metzmacher 2004
   
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

#ifndef _SAMBA_SOCKET_H
#define _SAMBA_SOCKET_H

struct socket_context;

enum socket_type {
	SOCKET_TYPE_STREAM
};

struct socket_ops {
	const char *name;
	enum socket_type type;

	NTSTATUS (*init)(struct socket_context *sock);

	/* client ops */
	NTSTATUS (*connect)(struct socket_context *sock,
				const char *my_address, int my_port,
				const char *server_address, int server_port,
				uint32_t flags);

	/* server ops */
	NTSTATUS (*listen)(struct socket_context *sock,
				const char *my_address, int port, int queue_size, uint32_t flags);
	NTSTATUS (*accept)(struct socket_context *sock,
				struct socket_context **new_sock, uint32_t flags);

	/* general ops */
	NTSTATUS (*recv)(struct socket_context *sock, TALLOC_CTX *mem_ctx, 
				DATA_BLOB *blob, size_t wantlen, uint32_t flags);
	NTSTATUS (*send)(struct socket_context *sock, TALLOC_CTX *mem_ctx,
				const DATA_BLOB *blob, size_t *sendlen, uint32_t flags);

	void (*close)(struct socket_context *sock);

	NTSTATUS (*set_option)(struct socket_context *sock, const char *option, const char *val);

	char *(*get_peer_addr)(struct socket_context *sock, TALLOC_CTX *mem_ctx);
	int (*get_peer_port)(struct socket_context *sock);
	char *(*get_my_addr)(struct socket_context *sock, TALLOC_CTX *mem_ctx);
	int (*get_my_port)(struct socket_context *sock);

	int (*get_fd)(struct socket_context *sock);
};

enum socket_state {
	SOCKET_STATE_UNDEFINED,

	SOCKET_STATE_CLIENT_START,
	SOCKET_STATE_CLIENT_CONNECTED,
	SOCKET_STATE_CLIENT_STARTTLS,
	SOCKET_STATE_CLIENT_ERROR,
	
	SOCKET_STATE_SERVER_LISTEN,
	SOCKET_STATE_SERVER_CONNECTED,
	SOCKET_STATE_SERVER_STARTTLS,
	SOCKET_STATE_SERVER_ERROR
};

#define SOCKET_FLAG_BLOCK 0x00000001
#define SOCKET_FLAG_PEEK  0x00000002

struct socket_context {
	enum socket_type type;
	enum socket_state state;
	uint32_t flags;

	int fd;

	void *private_data;
	const struct socket_ops *ops;
};

#endif /* _SAMBA_SOCKET_H */
