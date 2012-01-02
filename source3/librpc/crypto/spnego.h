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

#ifndef _CLI_SPNEGO_H_
#define _CLI_SPENGO_H_

enum spnego_mech {
	SPNEGO_NONE = 0,
	SPNEGO_KRB5,
	SPNEGO_NTLMSSP
};

struct spnego_context {
	enum spnego_mech mech;

	union {
		struct gensec_security *gensec_security;
	} mech_ctx;

	char *oid_list[ASN1_MAX_OIDS];
	char *mech_oid;

	enum {
		SPNEGO_CONV_INIT = 0,
		SPNEGO_CONV_NEGO,
		SPNEGO_CONV_AUTH_MORE,
		SPNEGO_CONV_AUTH_CONFIRM,
		SPNEGO_CONV_AUTH_DONE
	} state;

	bool do_sign;
	bool do_seal;
	bool is_dcerpc;

	struct tsocket_address *remote_address;

	bool more_processing; /* Current mech state requires more processing */
};

NTSTATUS spnego_generic_init_client(TALLOC_CTX *mem_ctx,
				    const char *oid,
				    bool do_sign, bool do_seal,
				    bool is_dcerpc,
				    const char *server,
				    const char *target_service,
				    const char *domain,
				    const char *username,
				    const char *password,
				    struct spnego_context **spnego_ctx);

NTSTATUS spnego_get_client_auth_token(TALLOC_CTX *mem_ctx,
				      struct spnego_context *sp_ctx,
				      DATA_BLOB *spnego_in,
				      DATA_BLOB *spnego_out);

bool spnego_require_more_processing(struct spnego_context *sp_ctx);

NTSTATUS spnego_get_negotiated_mech(struct spnego_context *sp_ctx,
				    struct gensec_security **auth_context);

DATA_BLOB spnego_get_session_key(TALLOC_CTX *mem_ctx,
				 struct spnego_context *sp_ctx);

NTSTATUS spnego_sign(TALLOC_CTX *mem_ctx,
			struct spnego_context *sp_ctx,
			DATA_BLOB *data, DATA_BLOB *full_data,
			DATA_BLOB *signature);
NTSTATUS spnego_sigcheck(TALLOC_CTX *mem_ctx,
			 struct spnego_context *sp_ctx,
			 DATA_BLOB *data, DATA_BLOB *full_data,
			 DATA_BLOB *signature);
NTSTATUS spnego_seal(TALLOC_CTX *mem_ctx,
			struct spnego_context *sp_ctx,
			DATA_BLOB *data, DATA_BLOB *full_data,
			DATA_BLOB *signature);
NTSTATUS spnego_unseal(TALLOC_CTX *mem_ctx,
			struct spnego_context *sp_ctx,
			DATA_BLOB *data, DATA_BLOB *full_data,
			DATA_BLOB *signature);

#endif /* _CLI_SPENGO_H_ */
