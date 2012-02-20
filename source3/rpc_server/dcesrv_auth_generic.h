/*
 *  NTLMSSP Acceptor
 *  DCERPC Server functions
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

#ifndef _DCESRV_NTLMSSP_H_
#define _DCESRV_NTLMSSP_H_

struct gensec_security;

NTSTATUS auth_generic_server_authtype_start(TALLOC_CTX *mem_ctx,
					    uint8_t auth_type, uint8_t auth_level,
					    DATA_BLOB *token_in,
					    DATA_BLOB *token_out,
					    const struct tsocket_address *remote_address,
					    struct gensec_security **ctx);

NTSTATUS auth_generic_server_step(struct gensec_security *ctx,
			     TALLOC_CTX *mem_ctx,
			     DATA_BLOB *token_in,
			     DATA_BLOB *token_out);
NTSTATUS auth_generic_server_check_flags(struct gensec_security *ctx,
				    bool do_sign, bool do_seal);
NTSTATUS auth_generic_server_get_user_info(struct gensec_security *ctx,
				      TALLOC_CTX *mem_ctx,
				      struct auth_session_info **session_info);

#endif /* _DCESRV_NTLMSSP_H_ */
