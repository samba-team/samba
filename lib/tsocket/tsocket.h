/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2009

     ** NOTE! The following LGPL license applies to the tsocket
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

struct tsocket_address;
struct tdgram_context;
struct tstream_context;
struct iovec;

/*
 * tsocket_address related functions
 */
char *tsocket_address_string(const struct tsocket_address *addr,
			     TALLOC_CTX *mem_ctx);

struct tsocket_address *_tsocket_address_copy(const struct tsocket_address *addr,
					      TALLOC_CTX *mem_ctx,
					      const char *location);

#define tsocket_address_copy(addr, mem_ctx) \
	_tsocket_address_copy(addr, mem_ctx, __location__)

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
 * tstream_context related functions
 */
ssize_t tstream_pending_bytes(struct tstream_context *stream);

struct tevent_req *tstream_readv_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct tstream_context *stream,
				      struct iovec *vector,
				      size_t count);
int tstream_readv_recv(struct tevent_req *req,
		       int *perrno);

struct tevent_req *tstream_writev_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct tstream_context *stream,
				       const struct iovec *vector,
				       size_t count);
int tstream_writev_recv(struct tevent_req *req,
			int *perrno);

struct tevent_req *tstream_disconnect_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct tstream_context *stream);
int tstream_disconnect_recv(struct tevent_req *req,
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

int _tsocket_address_unix_from_path(TALLOC_CTX *mem_ctx,
				    const char *path,
				    struct tsocket_address **_addr,
				    const char *location);
#define tsocket_address_unix_from_path(mem_ctx, path, _addr) \
	_tsocket_address_unix_from_path(mem_ctx, path, _addr, \
					__location__)
char *tsocket_address_unix_path(const struct tsocket_address *addr,
				TALLOC_CTX *mem_ctx);

int _tdgram_inet_udp_socket(const struct tsocket_address *local,
			    const struct tsocket_address *remote,
			    TALLOC_CTX *mem_ctx,
			    struct tdgram_context **dgram,
			    const char *location);
#define tdgram_inet_udp_socket(local, remote, mem_ctx, dgram) \
	_tdgram_inet_udp_socket(local, remote, mem_ctx, dgram, __location__)

int _tdgram_unix_socket(const struct tsocket_address *local,
			const struct tsocket_address *remote,
			TALLOC_CTX *mem_ctx,
			struct tdgram_context **dgram,
			const char *location);
#define tdgram_unix_socket(local, remote, mem_ctx, dgram) \
	_tdgram_unix_socket(local, remote, mem_ctx, dgram, __location__)

struct tevent_req * tstream_inet_tcp_connect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const struct tsocket_address *local,
					const struct tsocket_address *remote);
int _tstream_inet_tcp_connect_recv(struct tevent_req *req,
				   int *perrno,
				   TALLOC_CTX *mem_ctx,
				   struct tstream_context **stream,
				   const char *location);
#define tstream_inet_tcp_connect_recv(req, perrno, mem_ctx, stream) \
	_tstream_inet_tcp_connect_recv(req, perrno, mem_ctx, stream, \
				       __location__)

struct tevent_req * tstream_unix_connect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const struct tsocket_address *local,
					const struct tsocket_address *remote);
int _tstream_unix_connect_recv(struct tevent_req *req,
			       int *perrno,
			       TALLOC_CTX *mem_ctx,
			       struct tstream_context **stream,
			       const char *location);
#define tstream_unix_connect_recv(req, perrno, mem_ctx, stream) \
	_tstream_unix_connect_recv(req, perrno, mem_ctx, stream, \
					  __location__)

int _tstream_unix_socketpair(TALLOC_CTX *mem_ctx1,
			     struct tstream_context **_stream1,
			     TALLOC_CTX *mem_ctx2,
			     struct tstream_context **_stream2,
			     const char *location);
#define tstream_unix_socketpair(mem_ctx1, stream1, mem_ctx2, stream2) \
	_tstream_unix_socketpair(mem_ctx1, stream1, mem_ctx2, stream2, \
				 __location__)

struct sockaddr;

int _tsocket_address_bsd_from_sockaddr(TALLOC_CTX *mem_ctx,
				       struct sockaddr *sa,
				       size_t sa_socklen,
				       struct tsocket_address **_addr,
				       const char *location);
#define tsocket_address_bsd_from_sockaddr(mem_ctx, sa, sa_socklen, _addr) \
	_tsocket_address_bsd_from_sockaddr(mem_ctx, sa, sa_socklen, _addr, \
					   __location__)

ssize_t tsocket_address_bsd_sockaddr(const struct tsocket_address *addr,
				     struct sockaddr *sa,
				     size_t sa_socklen);

int _tstream_bsd_existing_socket(TALLOC_CTX *mem_ctx,
				 int fd,
				 struct tstream_context **_stream,
				 const char *location);
#define tstream_bsd_existing_socket(mem_ctx, fd, stream) \
	_tstream_bsd_existing_socket(mem_ctx, fd, stream, \
				     __location__)

/*
 * Queue and PDU helpers
 */

struct tevent_req *tdgram_sendto_queue_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct tdgram_context *dgram,
					    struct tevent_queue *queue,
					    const uint8_t *buf,
					    size_t len,
					    struct tsocket_address *dst);
ssize_t tdgram_sendto_queue_recv(struct tevent_req *req, int *perrno);

typedef int (*tstream_readv_pdu_next_vector_t)(struct tstream_context *stream,
					       void *private_data,
					       TALLOC_CTX *mem_ctx,
					       struct iovec **vector,
					       size_t *count);
struct tevent_req *tstream_readv_pdu_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct tstream_context *stream,
				tstream_readv_pdu_next_vector_t next_vector_fn,
				void *next_vector_private);
int tstream_readv_pdu_recv(struct tevent_req *req, int *perrno);

struct tevent_req *tstream_readv_pdu_queue_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct tstream_context *stream,
				struct tevent_queue *queue,
				tstream_readv_pdu_next_vector_t next_vector_fn,
				void *next_vector_private);
int tstream_readv_pdu_queue_recv(struct tevent_req *req, int *perrno);

struct tevent_req *tstream_writev_queue_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct tstream_context *stream,
					     struct tevent_queue *queue,
					     const struct iovec *vector,
					     size_t count);
int tstream_writev_queue_recv(struct tevent_req *req, int *perrno);

#endif /* _TSOCKET_H */

