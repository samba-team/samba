/*
 *  SPNEGO Encapsulation
 *  RPC Pipe client routines
 *  Copyright (C) Simo Sorce 2010.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _DCERPC_SPNEGO_H_
#define _DCERPC_SPENGO_H_

struct spnego_context;

NTSTATUS spnego_gssapi_init_client(TALLOC_CTX *mem_ctx,
				   enum dcerpc_AuthLevel auth_level,
				   const char *ccache_name,
				   const char *server,
				   const char *service,
				   const char *username,
				   const char *password,
				   uint32_t add_gss_c_flags,
				   struct spnego_context **spengo_ctx);

NTSTATUS spnego_get_client_auth_token(TALLOC_CTX *mem_ctx,
				      struct spnego_context *sp_ctx,
				      DATA_BLOB *spnego_in,
				      DATA_BLOB *spnego_out);

bool spnego_require_more_processing(struct spnego_context *sp_ctx);

NTSTATUS spnego_get_negotiated_mech(struct spnego_context *sp_ctx,
				    enum dcerpc_AuthType *auth_type,
				    void **auth_context);

#endif /* _DCERPC_SPENGO_H_ */
