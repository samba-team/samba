/* 
   Unix SMB/CIFS implementation.

   DCERPC client side interface structures

   Copyright (C) 2008 Jelmer Vernooij
   
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

/* This is a public header file that is installed as part of Samba. 
 * If you remove any functions or change their signature, update 
 * the so version number. */

#ifndef _S3_DCERPC_H__
#define _S3_DCERPC_H__

#include "librpc/gen_ndr/dcerpc.h"
#include "../librpc/ndr/libndr.h"
#include "../librpc/rpc/rpc_common.h"

struct NL_AUTH_MESSAGE;
struct gensec_security;
struct pipe_auth_data;

/* The following definitions come from librpc/rpc/dcerpc_helpers.c  */
NTSTATUS dcerpc_push_ncacn_packet(TALLOC_CTX *mem_ctx,
				  enum dcerpc_pkt_type ptype,
				  uint8_t pfc_flags,
				  uint16_t auth_length,
				  uint32_t call_id,
				  union dcerpc_payload *u,
				  DATA_BLOB *blob);
NTSTATUS dcerpc_push_dcerpc_auth(TALLOC_CTX *mem_ctx,
				 enum dcerpc_AuthType auth_type,
				 enum dcerpc_AuthLevel auth_level,
				 uint8_t auth_pad_length,
				 uint32_t auth_context_id,
				 const DATA_BLOB *credentials,
				 DATA_BLOB *blob);
NTSTATUS dcerpc_guess_sizes(struct pipe_auth_data *auth,
			    size_t header_len, size_t data_left,
			    size_t max_xmit_frag,
			    size_t *data_to_send, size_t *frag_len,
			    size_t *auth_len, size_t *pad_len);
NTSTATUS dcerpc_add_auth_footer(struct pipe_auth_data *auth,
				size_t pad_len, DATA_BLOB *rpc_out);
NTSTATUS dcerpc_check_auth(struct pipe_auth_data *auth,
			   struct ncacn_packet *pkt,
			   DATA_BLOB *pkt_trailer,
			   uint8_t header_size,
			   DATA_BLOB *raw_pkt);

#endif /* __S3_DCERPC_H__ */
