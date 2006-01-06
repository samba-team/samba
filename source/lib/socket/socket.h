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
	SOCKET_TYPE_STREAM,
	SOCKET_TYPE_DGRAM
};

struct socket_ops {
	const char *name;

	NTSTATUS (*fn_init)(struct socket_context *sock);

	/* client ops */
	NTSTATUS (*fn_connect)(struct socket_context *sock,
				const char *my_address, int my_port,
				const char *server_address, int server_port,
				uint32_t flags);

	/* complete a non-blocking connect */
	NTSTATUS (*fn_connect_complete)(struct socket_context *sock,
					uint32_t flags);

	/* server ops */
	NTSTATUS (*fn_listen)(struct socket_context *sock,
				const char *my_address, int port, int queue_size, uint32_t flags);
	NTSTATUS (*fn_accept)(struct socket_context *sock,	struct socket_context **new_sock);

	/* general ops */
	NTSTATUS (*fn_recv)(struct socket_context *sock, void *buf,
			    size_t wantlen, size_t *nread, uint32_t flags);
	NTSTATUS (*fn_send)(struct socket_context *sock, 
			    const DATA_BLOB *blob, size_t *sendlen, uint32_t flags);

	NTSTATUS (*fn_sendto)(struct socket_context *sock, 
			      const DATA_BLOB *blob, size_t *sendlen, uint32_t flags,
			      const char *dest_addr, int dest_port);
	NTSTATUS (*fn_recvfrom)(struct socket_context *sock, 
				void *buf, size_t wantlen, size_t *nread, uint32_t flags,
				const char **src_addr, int *src_port);
	NTSTATUS (*fn_pending)(struct socket_context *sock, size_t *npending);      

	void (*fn_close)(struct socket_context *sock);

	NTSTATUS (*fn_set_option)(struct socket_context *sock, const char *option, const char *val);

	char *(*fn_get_peer_name)(struct socket_context *sock, TALLOC_CTX *mem_ctx);
	char *(*fn_get_peer_addr)(struct socket_context *sock, TALLOC_CTX *mem_ctx);
	int (*fn_get_peer_port)(struct socket_context *sock);
	char *(*fn_get_my_addr)(struct socket_context *sock, TALLOC_CTX *mem_ctx);
	int (*fn_get_my_port)(struct socket_context *sock);

	int (*fn_get_fd)(struct socket_context *sock);
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

#define SOCKET_FLAG_BLOCK        0x00000001
#define SOCKET_FLAG_PEEK         0x00000002
#define SOCKET_FLAG_TESTNONBLOCK 0x00000004

struct socket_context {
	enum socket_type type;
	enum socket_state state;
	uint32_t flags;

	int fd;

	void *private_data;
	const struct socket_ops *ops;
	const char *backend_name;
};


/* prototypes */
NTSTATUS socket_create(const char *name, enum socket_type type, 
		       struct socket_context **new_sock, uint32_t flags);
NTSTATUS socket_connect(struct socket_context *sock,
			const char *my_address, int my_port,
			const char *server_address, int server_port,
			uint32_t flags);
NTSTATUS socket_connect_complete(struct socket_context *sock, uint32_t flags);
NTSTATUS socket_listen(struct socket_context *sock, const char *my_address, int port, int queue_size, uint32_t flags);
NTSTATUS socket_accept(struct socket_context *sock, struct socket_context **new_sock);
NTSTATUS socket_recv(struct socket_context *sock, void *buf, 
		     size_t wantlen, size_t *nread, uint32_t flags);
NTSTATUS socket_recvfrom(struct socket_context *sock, void *buf, 
			 size_t wantlen, size_t *nread, uint32_t flags,
			 const char **src_addr, int *src_port);
NTSTATUS socket_send(struct socket_context *sock, 
		     const DATA_BLOB *blob, size_t *sendlen, uint32_t flags);
NTSTATUS socket_sendto(struct socket_context *sock, 
		       const DATA_BLOB *blob, size_t *sendlen, uint32_t flags,
		       const char *dest_addr, int dest_port);
NTSTATUS socket_pending(struct socket_context *sock, size_t *npending);
NTSTATUS socket_set_option(struct socket_context *sock, const char *option, const char *val);
char *socket_get_peer_name(struct socket_context *sock, TALLOC_CTX *mem_ctx);
char *socket_get_peer_addr(struct socket_context *sock, TALLOC_CTX *mem_ctx);
int socket_get_peer_port(struct socket_context *sock);
char *socket_get_my_addr(struct socket_context *sock, TALLOC_CTX *mem_ctx);
int socket_get_my_port(struct socket_context *sock);
int socket_get_fd(struct socket_context *sock);
NTSTATUS socket_dup(struct socket_context *sock);
const struct socket_ops *socket_getops_byname(const char *name, enum socket_type type);
BOOL allow_access(TALLOC_CTX *mem_ctx,
		  const char **deny_list, const char **allow_list,
		  const char *cname, const char *caddr);
BOOL socket_check_access(struct socket_context *sock, 
			 const char *service_name,
			 const char **allow_list, const char **deny_list);

struct composite_context *socket_connect_send(struct socket_context *sock,
					      const char *my_address,
					      int my_port,
					      const char *server_address,
					      int server_port,
					      uint32_t flags,
					      struct event_context *event_ctx);
NTSTATUS socket_connect_recv(struct composite_context *ctx);
NTSTATUS socket_connect_ev(struct socket_context *sock,
			   const char *my_address, int my_port,
			   const char *server_address, int server_port,
			   uint32_t flags, struct event_context *ev);

struct composite_context *socket_connect_multi_send(TALLOC_CTX *mem_ctx,
						    const char *server_address,
						    int num_server_ports,
						    uint16_t *server_ports,
						    struct event_context *event_ctx);
NTSTATUS socket_connect_multi_recv(struct composite_context *ctx,
				   TALLOC_CTX *mem_ctx,
				   struct socket_context **result,
				   uint16_t *port);
NTSTATUS socket_connect_multi(TALLOC_CTX *mem_ctx, const char *server_address,
			      int num_server_ports, uint16_t *server_ports,
			      struct event_context *event_ctx,
			      struct socket_context **result,
			      uint16_t *port);

#endif /* _SAMBA_SOCKET_H */
