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

#ifndef _TSOCKET_H
#define _TSOCKET_H

#include <talloc.h>
#include <tevent.h>

struct tsocket_context;
struct tsocket_address;
struct tdgram_context;
struct iovec;

enum tsocket_type {
	TSOCKET_TYPE_STREAM = 1,
	TSOCKET_TYPE_MESSAGE
};

typedef void (*tsocket_event_handler_t)(struct tsocket_context *, void *);
int tsocket_set_event_context(struct tsocket_context *sock,
			      struct tevent_context *ev);
int tsocket_set_readable_handler(struct tsocket_context *sock,
				 tsocket_event_handler_t handler,
				 void *private_data);
int tsocket_set_writeable_handler(struct tsocket_context *sock,
				  tsocket_event_handler_t handler,
				  void *private_data);

int tsocket_connect(struct tsocket_context *sock,
		    const struct tsocket_address *remote_addr);

int tsocket_listen(struct tsocket_context *sock,
		   int queue_size);

int _tsocket_accept(struct tsocket_context *sock,
		    TALLOC_CTX *mem_ctx,
		    struct tsocket_context **new_sock,
		    const char *location);
#define tsocket_accept(sock, mem_ctx, new_sock) \
	_tsocket_accept(sock, mem_ctx, new_sock, __location__)

ssize_t tsocket_pending(struct tsocket_context *sock);

int tsocket_readv(struct tsocket_context *sock,
		  const struct iovec *vector, size_t count);
int tsocket_writev(struct tsocket_context *sock,
		   const struct iovec *vector, size_t count);

int tsocket_get_status(const struct tsocket_context *sock);

int _tsocket_get_local_address(const struct tsocket_context *sock,
			       TALLOC_CTX *mem_ctx,
			       struct tsocket_address **local_addr,
			       const char *location);
#define tsocket_get_local_address(sock, mem_ctx, local_addr) \
	_tsocket_get_local_address(sock, mem_ctx, local_addr, __location__)
int _tsocket_get_remote_address(const struct tsocket_context *sock,
				TALLOC_CTX *mem_ctx,
				struct tsocket_address **remote_addr,
				const char *location);
#define tsocket_get_remote_address(sock, mem_ctx, remote_addr) \
	_tsocket_get_remote_address(sock, mem_ctx, remote_addr, __location__)

int tsocket_get_option(const struct tsocket_context *sock,
		       const char *option,
		       TALLOC_CTX *mem_ctx,
		       char **value);
int tsocket_set_option(const struct tsocket_context *sock,
		       const char *option,
		       bool force,
		       const char *value);

void tsocket_disconnect(struct tsocket_context *sock);

char *tsocket_address_string(const struct tsocket_address *addr,
			     TALLOC_CTX *mem_ctx);

struct tsocket_address *_tsocket_address_copy(const struct tsocket_address *addr,
					      TALLOC_CTX *mem_ctx,
					      const char *location);

#define tsocket_address_copy(addr, mem_ctx) \
	_tsocket_address_copy(addr, mem_ctx, __location__)

int _tsocket_address_create_socket(const struct tsocket_address *addr,
				   enum tsocket_type type,
				   TALLOC_CTX *mem_ctx,
				   struct tsocket_context **sock,
				   const char *location);
#define tsocket_address_create_socket(addr, type, mem_ctx, sock) \
	_tsocket_address_create_socket(addr, type, mem_ctx, sock,\
				       __location__)

/*
 * tdgram_context related functions
 */
struct tevent_req *tdgram_recvfrom_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tdgram_context *dgram);
ssize_t tdgram_recvfrom_recv(struct tevent_req *req,
			     int *perrno,
			     TALLOC_CTX *mem_ctx,
			     uint8_t **buf,
			     struct tsocket_address **src);

struct tevent_req *tdgram_sendto_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct tdgram_context *dgram,
				      const uint8_t *buf, size_t len,
				      const struct tsocket_address *dst);
ssize_t tdgram_sendto_recv(struct tevent_req *req,
			   int *perrno);

struct tevent_req *tdgram_disconnect_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct tdgram_context *dgram);
int tdgram_disconnect_recv(struct tevent_req *req,
			   int *perrno);

/*
 * BSD sockets: inet, inet6 and unix
 */

int _tsocket_address_inet_from_strings(TALLOC_CTX *mem_ctx,
				       const char *fam,
				       const char *addr,
				       uint16_t port,
				       struct tsocket_address **_addr,
				       const char *location);
#define tsocket_address_inet_from_strings(mem_ctx, fam, addr, port, _addr) \
	_tsocket_address_inet_from_strings(mem_ctx, fam, addr, port, _addr, \
					   __location__)

char *tsocket_address_inet_addr_string(const struct tsocket_address *addr,
				       TALLOC_CTX *mem_ctx);
uint16_t tsocket_address_inet_port(const struct tsocket_address *addr);
int tsocket_address_inet_set_port(struct tsocket_address *addr,
				  uint16_t port);
void tsocket_address_inet_set_broadcast(struct tsocket_address *addr,
					bool broadcast);

int _tsocket_address_unix_from_path(TALLOC_CTX *mem_ctx,
				    const char *path,
				    struct tsocket_address **_addr,
				    const char *location);
#define tsocket_address_unix_from_path(mem_ctx, path, _addr) \
	_tsocket_address_unix_from_path(mem_ctx, path, _addr, \
					__location__)
char *tsocket_address_unix_path(const struct tsocket_address *addr,
				TALLOC_CTX *mem_ctx);

int _tsocket_context_bsd_wrap_existing(TALLOC_CTX *mem_ctx,
				       int fd, bool close_on_disconnect,
				       struct tsocket_context **_sock,
				       const char *location);
#define tsocket_context_bsd_wrap_existing(mem_ctx, fd, cod, _sock) \
	_tsocket_context_bsd_wrap_existing(mem_ctx, fd, cod, _sock, \
					   __location__)

int _tdgram_inet_udp_socket(const struct tsocket_address *local,
			    const struct tsocket_address *remote,
			    TALLOC_CTX *mem_ctx,
			    struct tdgram_context **dgram,
			    const char *location);
#define tdgram_inet_udp_socket(local, remote, mem_ctx, dgram) \
	_tdgram_inet_udp_socket(local, remote, mem_ctx, dgram, __location__)

int _tdgram_unix_dgram_socket(const struct tsocket_address *local,
			      const struct tsocket_address *remote,
			      TALLOC_CTX *mem_ctx,
			      struct tdgram_context **dgram,
			      const char *location);
#define tdgram_unix_dgram_socket(local, remote, mem_ctx, dgram) \
	_tdgram_unix_dgram_socket(local, remote, mem_ctx, dgram, __location__)

/*
 * Async helpers
 */

struct tevent_req *tsocket_connect_send(struct tsocket_context *sock,
					TALLOC_CTX *mem_ctx,
					const struct tsocket_address *dst);
int tsocket_connect_recv(struct tevent_req *req, int *perrno);

struct tevent_req *tsocket_writev_send(struct tsocket_context *sock,
				       TALLOC_CTX *mem_ctx,
				       const struct iovec *vector,
				       size_t count);
int tsocket_writev_recv(struct tevent_req *req, int *perrno);

struct tevent_req *tsocket_writev_queue_send(TALLOC_CTX *mem_ctx,
					     struct tsocket_context *sock,
					     struct tevent_queue *queue,
					     const struct iovec *vector,
					     size_t count);
int tsocket_writev_queue_recv(struct tevent_req *req, int *perrno);

typedef int (*tsocket_readv_next_iovec_t)(struct tsocket_context *sock,
					  void *private_data,
					  TALLOC_CTX *mem_ctx,
					  struct iovec **vector,
					  size_t *count);
struct tevent_req *tsocket_readv_send(struct tsocket_context *sock,
				      TALLOC_CTX *mem_ctx,
				      tsocket_readv_next_iovec_t next_iovec_fn,
				      void *private_data);
int tsocket_readv_recv(struct tevent_req *req, int *perrno);

/*
 * Queue helpers
 */

struct tevent_req *tdgram_sendto_queue_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct tdgram_context *dgram,
					    struct tevent_queue *queue,
					    const uint8_t *buf,
					    size_t len,
					    struct tsocket_address *dst);
ssize_t tdgram_sendto_queue_recv(struct tevent_req *req, int *perrno);

#endif /* _TSOCKET_H */

