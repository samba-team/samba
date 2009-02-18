/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2009

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _TSOCKET_INTERNAL_H
#define _TSOCKET_INTERNAL_H

struct tsocket_context_ops {
	const char *name;

	/* event handling */
	int (*set_event_context)(struct tsocket_context *sock,
				 struct tevent_context *ev);
	int (*set_read_handler)(struct tsocket_context *sock,
				tsocket_event_handler_t handler,
				void *private_data);
	int (*set_write_handler)(struct tsocket_context *sock,
				 tsocket_event_handler_t handler,
				 void *private_data);

	/* client ops */
	int (*connect_to)(struct tsocket_context *sock,
			  const struct tsocket_address *remote_addr);

	/* server ops */
	int (*listen_on)(struct tsocket_context *sock,
			 int queue_size);
	int (*accept_new)(struct tsocket_context *sock,
			  TALLOC_CTX *mem_ctx,
			  struct tsocket_context **new_sock,
			  const char *location);

	/* general ops */
	ssize_t (*pending_data)(struct tsocket_context *sock);

	int (*readv_data)(struct tsocket_context *sock,
			  const struct iovec *vector, size_t count);
	int (*writev_data)(struct tsocket_context *sock,
			   const struct iovec *vector, size_t count);

	ssize_t (*recvfrom_data)(struct tsocket_context *sock,
				 uint8_t *data, size_t len,
				 TALLOC_CTX *addr_ctx,
				 struct tsocket_address **remote_addr);
	ssize_t (*sendto_data)(struct tsocket_context *sock,
			       const uint8_t *data, size_t len,
			       const struct tsocket_address *remote_addr);

	/* info */
	int (*get_status)(const struct tsocket_context *sock);
	int (*get_local_address)(const struct tsocket_context *sock,
				TALLOC_CTX *mem_ctx,
				struct tsocket_address **local_addr,
				const char *location);
	int (*get_remote_address)(const struct tsocket_context *sock,
				  TALLOC_CTX *mem_ctx,
				  struct tsocket_address **remote_addr,
				  const char *location);

	/* options */
	int (*get_option)(const struct tsocket_context *sock,
			  const char *option,
			  TALLOC_CTX *mem_ctx,
			  char **value);
	int (*set_option)(const struct tsocket_context *sock,
			  const char *option,
			  bool force,
			  const char *value);

	/* close/disconnect */
	void (*disconnect)(struct tsocket_context *sock);
};

struct tsocket_context {
	const char *location;
	const struct tsocket_context_ops *ops;

	void *private_data;

	struct {
		struct tevent_context *ctx;
		void *read_private;
		tsocket_event_handler_t read_handler;
		void *write_private;
		tsocket_event_handler_t write_handler;
	} event;
};

struct tsocket_context *_tsocket_context_create(TALLOC_CTX *mem_ctx,
					const struct tsocket_context_ops *ops,
					void *pstate,
					size_t psize,
					const char *type,
					const char *location);
#define tsocket_context_create(mem_ctx, ops, state, type, location) \
	_tsocket_context_create(mem_ctx, ops, state, sizeof(type), \
				#type, location)

struct tsocket_address_ops {
	const char *name;

	char *(*string)(const struct tsocket_address *addr,
			TALLOC_CTX *mem_ctx);

	struct tsocket_address *(*copy)(const struct tsocket_address *addr,
					TALLOC_CTX *mem_ctx,
					const char *location);

	int (*create_socket)(const struct tsocket_address *addr,
			     enum tsocket_type,
			     TALLOC_CTX *mem_ctx,
			     struct tsocket_context **sock,
			     const char *location);
};

struct tsocket_address {
	const char *location;
	const struct tsocket_address_ops *ops;

	void *private_data;
};

struct tsocket_address *_tsocket_address_create(TALLOC_CTX *mem_ctx,
					const struct tsocket_address_ops *ops,
					void *pstate,
					size_t psize,
					const char *type,
					const char *location);
#define tsocket_address_create(mem_ctx, ops, state, type, location) \
	_tsocket_address_create(mem_ctx, ops, state, sizeof(type), \
				#type, location)

int tsocket_error_from_errno(int ret, int sys_errno, bool *retry);
int tsocket_simple_int_recv(struct tevent_req *req, int *perrno);
int tsocket_common_prepare_fd(int fd, bool high_fd);

#endif /* _TSOCKET_H */

