/*
 * Unix SMB/CIFS implementation.
 * Gensec based tldap bind
 * Copyright (C) Volker Lendecke 2015
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

#ifndef __TLDAP_GENSEC_BIND_H__
#define __TLDAP_GENSEC_BIND_H__

struct tevent_context;
struct tldap_context;
struct cli_credentials;
struct loadparm_context;

struct tevent_req *tldap_gensec_bind_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct tldap_context *ctx, struct cli_credentials *creds,
	const char *target_service, const char *target_hostname,
	const char *target_principal, struct loadparm_context *lp_ctx,
	uint32_t gensec_features);
TLDAPRC tldap_gensec_bind_recv(struct tevent_req *req);
TLDAPRC tldap_gensec_bind(
	struct tldap_context *ctx, struct cli_credentials *creds,
	const char *target_service, const char *target_hostname,
	const char *target_principal, struct loadparm_context *lp_ctx,
	uint32_t gensec_features);

#endif
