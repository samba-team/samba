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

#include "replace.h"
#include "system/network.h"
#include "tsocket.h"
#include "tsocket_internal.h"

static int tsocket_context_destructor(struct tsocket_context *sock)
{
	tsocket_disconnect(sock);
	return 0;
}

struct tsocket_context *_tsocket_context_create(TALLOC_CTX *mem_ctx,
						const struct tsocket_context_ops *ops,
						void *pstate,
						size_t psize,
						const char *type,
						const char *location)
{
	void **ppstate = (void **)pstate;
	struct tsocket_context *sock;

	sock = talloc_zero(mem_ctx, struct tsocket_context);
	if (!sock) {
		return NULL;
	}
	sock->ops = ops;
	sock->location = location;
	sock->private_data = talloc_size(sock, psize);
	if (!sock->private_data) {
		talloc_free(sock);
		return NULL;
	}
	talloc_set_name_const(sock->private_data, type);

	talloc_set_destructor(sock, tsocket_context_destructor);

	*ppstate = sock->private_data;
	return sock;
}

int tsocket_set_event_context(struct tsocket_context *sock,
			      struct tevent_context *ev)
{
	return sock->ops->set_event_context(sock, ev);
}

int tsocket_set_readable_handler(struct tsocket_context *sock,
				 tsocket_event_handler_t handler,
				 void *private_data)
{
	return sock->ops->set_read_handler(sock, handler, private_data);
}

int tsocket_set_writeable_handler(struct tsocket_context *sock,
				  tsocket_event_handler_t handler,
				  void *private_data)
{
	return sock->ops->set_write_handler(sock, handler, private_data);
}

int tsocket_connect(struct tsocket_context *sock,
		    const struct tsocket_address *remote_addr)
{
	return sock->ops->connect_to(sock, remote_addr);
}

int tsocket_listen(struct tsocket_context *sock,
		   int queue_size)
{
	return sock->ops->listen_on(sock, queue_size);
}

int _tsocket_accept(struct tsocket_context *sock,
		    TALLOC_CTX *mem_ctx,
		    struct tsocket_context **new_sock,
		    const char *location)
{
	return sock->ops->accept_new(sock, mem_ctx, new_sock, location);
}

ssize_t tsocket_pending(struct tsocket_context *sock)
{
	return sock->ops->pending_data(sock);
}

int tsocket_readv(struct tsocket_context *sock,
		  const struct iovec *vector, size_t count)
{
	return sock->ops->readv_data(sock, vector, count);
}

int tsocket_writev(struct tsocket_context *sock,
		   const struct iovec *vector, size_t count)
{
	return sock->ops->writev_data(sock, vector, count);
}

ssize_t tsocket_recvfrom(struct tsocket_context *sock,
			 uint8_t *data, size_t len,
			 TALLOC_CTX *addr_ctx,
			 struct tsocket_address **src_addr)
{
	return sock->ops->recvfrom_data(sock, data, len, addr_ctx, src_addr);
}

ssize_t tsocket_sendto(struct tsocket_context *sock,
		       const uint8_t *data, size_t len,
		       const struct tsocket_address *dest_addr)
{
	return sock->ops->sendto_data(sock, data, len, dest_addr);
}

int tsocket_get_status(const struct tsocket_context *sock)
{
	return sock->ops->get_status(sock);
}

int _tsocket_get_local_address(const struct tsocket_context *sock,
			       TALLOC_CTX *mem_ctx,
			       struct tsocket_address **local_addr,
			       const char *location)
{
	return sock->ops->get_local_address(sock, mem_ctx,
					    local_addr, location);
}

int _tsocket_get_remote_address(const struct tsocket_context *sock,
				TALLOC_CTX *mem_ctx,
				struct tsocket_address **remote_addr,
				const char *location)
{
	return sock->ops->get_remote_address(sock, mem_ctx,
					     remote_addr, location);
}

int tsocket_get_option(const struct tsocket_context *sock,
		       const char *option,
		       TALLOC_CTX *mem_ctx,
		       char **value)
{
	return sock->ops->get_option(sock, option, mem_ctx, value);
}

int tsocket_set_option(const struct tsocket_context *sock,
		       const char *option,
		       bool force,
		       const char *value)
{
	return sock->ops->set_option(sock, option, force, value);
}

void tsocket_disconnect(struct tsocket_context *sock)
{
	sock->ops->disconnect(sock);
}

struct tsocket_address *_tsocket_address_create(TALLOC_CTX *mem_ctx,
						const struct tsocket_address_ops *ops,
						void *pstate,
						size_t psize,
						const char *type,
						const char *location)
{
	void **ppstate = (void **)pstate;
	struct tsocket_address *addr;

	addr = talloc_zero(mem_ctx, struct tsocket_address);
	if (!addr) {
		return NULL;
	}
	addr->ops = ops;
	addr->location = location;
	addr->private_data = talloc_size(addr, psize);
	if (!addr->private_data) {
		talloc_free(addr);
		return NULL;
	}
	talloc_set_name_const(addr->private_data, type);

	*ppstate = addr->private_data;
	return addr;
}

char *tsocket_address_string(const struct tsocket_address *addr,
			     TALLOC_CTX *mem_ctx)
{
	if (!addr) {
		return talloc_strdup(mem_ctx, "NULL");
	}
	return addr->ops->string(addr, mem_ctx);
}

struct tsocket_address *_tsocket_address_copy(const struct tsocket_address *addr,
					      TALLOC_CTX *mem_ctx,
					      const char *location)
{
	return addr->ops->copy(addr, mem_ctx, location);
}

int _tsocket_address_create_socket(const struct tsocket_address *addr,
				   enum tsocket_type type,
				   TALLOC_CTX *mem_ctx,
				   struct tsocket_context **sock,
				   const char *location)
{
	return addr->ops->create_socket(addr, type, mem_ctx, sock, location);
}

