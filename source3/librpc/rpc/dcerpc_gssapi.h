/*
 *  GSSAPI Security Extensions
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

#ifndef _CLI_PIPE_GSSAPI_H_
#define _CLI_PIPE_GSSAPI_H_

struct gse_context;

#ifndef GSS_C_DCE_STYLE
#define GSS_C_DCE_STYLE 0x1000
#endif

NTSTATUS gse_init_client(TALLOC_CTX *mem_ctx,
			  enum dcerpc_AuthType auth_type,
			  enum dcerpc_AuthLevel auth_level,
			  const char *ccache_name,
			  const char *server,
			  const char *service,
			  const char *username,
			  const char *password,
			  uint32_t add_gss_c_flags,
			  struct pipe_auth_data **_auth);

NTSTATUS gse_get_client_auth_token(TALLOC_CTX *mem_ctx,
				   struct gse_context *gse_ctx,
				   DATA_BLOB *token_in,
				   DATA_BLOB *token_out);

bool gse_require_more_processing(struct gse_context *gse_ctx);
DATA_BLOB gse_get_session_key(struct gse_context *gse_ctx);

size_t gse_get_signature_length(struct gse_context *gse_ctx,
				int seal, size_t payload_size);
NTSTATUS gse_seal(TALLOC_CTX *mem_ctx, struct gse_context *gse_ctx,
		  DATA_BLOB *data, DATA_BLOB *signature);
NTSTATUS gse_unseal(TALLOC_CTX *mem_ctx, struct gse_context *gse_ctx,
		    DATA_BLOB *data, DATA_BLOB *signature);
NTSTATUS gse_sign(TALLOC_CTX *mem_ctx, struct gse_context *gse_ctx,
		  DATA_BLOB *data, DATA_BLOB *signature);
NTSTATUS gse_sigcheck(TALLOC_CTX *mem_ctx, struct gse_context *gse_ctx,
		      DATA_BLOB *data, DATA_BLOB *signature);
#endif /* _CLI_PIPE_GSSAPI_H_ */
