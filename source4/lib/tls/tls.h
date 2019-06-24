/* 
   Unix SMB/CIFS implementation.

   transport layer security handling code

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _TLS_H_
#define _TLS_H_

#include "lib/socket/socket.h"

struct loadparm_context;

void tls_cert_generate(TALLOC_CTX *mem_ctx,
		       const char *hostname,
		       const char *keyfile, const char *certfile,
		       const char *cafile);

struct tstream_context;
struct tstream_tls_params;

enum tls_verify_peer_state {
	TLS_VERIFY_PEER_NO_CHECK = 0,
#define TLS_VERIFY_PEER_NO_CHECK_STRING "no_check"

	TLS_VERIFY_PEER_CA_ONLY = 10,
#define TLS_VERIFY_PEER_CA_ONLY_STRING "ca_only"

	TLS_VERIFY_PEER_CA_AND_NAME_IF_AVAILABLE = 20,
#define TLS_VERIFY_PEER_CA_AND_NAME_IF_AVAILABLE_STRING \
		"ca_and_name_if_available"

	TLS_VERIFY_PEER_CA_AND_NAME = 30,
#define TLS_VERIFY_PEER_CA_AND_NAME_STRING "ca_and_name"

	TLS_VERIFY_PEER_AS_STRICT_AS_POSSIBLE = 9999,
#define TLS_VERIFY_PEER_AS_STRICT_AS_POSSIBLE_STRING \
		"as_strict_as_possible"
};

const char *tls_verify_peer_string(enum tls_verify_peer_state verify_peer);

NTSTATUS tstream_tls_params_client(TALLOC_CTX *mem_ctx,
				   const char *ca_file,
				   const char *crl_file,
				   const char *tls_priority,
				   enum tls_verify_peer_state verify_peer,
				   const char *peer_name,
				   struct tstream_tls_params **_tlsp);

NTSTATUS tstream_tls_params_server(TALLOC_CTX *mem_ctx,
				   const char *dns_host_name,
				   bool enabled,
				   const char *key_file,
				   const char *cert_file,
				   const char *ca_file,
				   const char *crl_file,
				   const char *dhp_file,
				   const char *tls_priority,
				   struct tstream_tls_params **_params);

bool tstream_tls_params_enabled(struct tstream_tls_params *params);

struct tevent_req *_tstream_tls_connect_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct tstream_context *plain_stream,
					     struct tstream_tls_params *tls_params,
					     const char *location);
#define tstream_tls_connect_send(mem_ctx, ev, plain_stream, tls_params) \
	_tstream_tls_connect_send(mem_ctx, ev, plain_stream, tls_params, __location__)

int tstream_tls_connect_recv(struct tevent_req *req,
			     int *perrno,
			     TALLOC_CTX *mem_ctx,
			     struct tstream_context **tls_stream);

struct tevent_req *_tstream_tls_accept_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct tstream_context *plain_stream,
					    struct tstream_tls_params *tls_params,
					    const char *location);
#define tstream_tls_accept_send(mem_ctx, ev, plain_stream, tls_params) \
	_tstream_tls_accept_send(mem_ctx, ev, plain_stream, tls_params, __location__)

int tstream_tls_accept_recv(struct tevent_req *req,
			    int *perrno,
			    TALLOC_CTX *mem_ctx,
			    struct tstream_context **tls_stream);

#endif /* _TLS_H_ */
