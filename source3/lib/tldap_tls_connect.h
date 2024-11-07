/*
 * Unix SMB/CIFS implementation.
 * tls based tldap connect
 * Copyright (C) Stefan Metzmacher 2024
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __TLDAP_TLS_CONNECT_H__
#define __TLDAP_TLS_CONNECT_H__

struct tevent_context;
struct tldap_context;
struct loadparm_context;
struct tstream_tls_params;

struct tevent_req *tldap_tls_connect_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct tldap_context *ctx,
	struct tstream_tls_params *tls_params);
TLDAPRC tldap_tls_connect_recv(struct tevent_req *req);
TLDAPRC tldap_tls_connect(struct tldap_context *ctx,
			  struct tstream_tls_params *tls_params);

#endif
