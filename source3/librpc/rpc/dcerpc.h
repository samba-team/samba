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

#include "../librpc/rpc/rpc_common.h"

#define SMB_RPC_INTERFACE_VERSION 1

/* The following definitions come from librpc/rpc/binding.c  */

struct epm_floor;
struct epm_tower;
const char *epm_floor_string(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor);
_PUBLIC_ char *dcerpc_binding_string(TALLOC_CTX *mem_ctx, const struct dcerpc_binding *b);
_PUBLIC_ NTSTATUS dcerpc_parse_binding(TALLOC_CTX *mem_ctx, const char *s, struct dcerpc_binding **b_out);
_PUBLIC_ NTSTATUS dcerpc_floor_get_lhs_data(const struct epm_floor *epm_floor,
					    struct ndr_syntax_id *syntax);
const char *dcerpc_floor_get_rhs_data(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor);
enum dcerpc_transport_t dcerpc_transport_by_endpoint_protocol(int prot);
_PUBLIC_ enum dcerpc_transport_t dcerpc_transport_by_tower(const struct epm_tower *tower);
_PUBLIC_ const char *derpc_transport_string_by_transport(enum dcerpc_transport_t t);
_PUBLIC_ NTSTATUS dcerpc_binding_from_tower(TALLOC_CTX *mem_ctx,
				   struct epm_tower *tower,
				   struct dcerpc_binding **b_out);
_PUBLIC_ NTSTATUS dcerpc_binding_build_tower(TALLOC_CTX *mem_ctx,
					     const struct dcerpc_binding *binding,
					     struct epm_tower *tower);

struct NL_AUTH_MESSAGE;
struct pipe_auth_data;

/* The following definitions come from librpc/rpc/dcerpc_helpers.c  */
NTSTATUS dcerpc_push_ncacn_packet(TALLOC_CTX *mem_ctx,
				  enum dcerpc_pkt_type ptype,
				  uint8_t pfc_flags,
				  uint16_t auth_length,
				  uint32_t call_id,
				  union dcerpc_payload *u,
				  DATA_BLOB *blob);
NTSTATUS dcerpc_pull_ncacn_packet(TALLOC_CTX *mem_ctx,
				  const DATA_BLOB *blob,
				  struct ncacn_packet *r,
				  bool bigendian);
NTSTATUS dcerpc_push_schannel_bind(TALLOC_CTX *mem_ctx,
				   struct NL_AUTH_MESSAGE *r,
				   DATA_BLOB *blob);
NTSTATUS dcerpc_push_dcerpc_auth(TALLOC_CTX *mem_ctx,
				 enum dcerpc_AuthType auth_type,
				 enum dcerpc_AuthLevel auth_level,
				 uint8_t auth_pad_length,
				 uint32_t auth_context_id,
				 const DATA_BLOB *credentials,
				 DATA_BLOB *blob);
NTSTATUS dcerpc_pull_dcerpc_auth(TALLOC_CTX *mem_ctx,
				 const DATA_BLOB *blob,
				 struct dcerpc_auth *r,
				 bool bigendian);
NTSTATUS dcerpc_guess_sizes(struct pipe_auth_data *auth,
			    size_t header_len, size_t data_left,
			    size_t max_xmit_frag, size_t pad_alignment,
			    size_t *data_to_send, size_t *frag_len,
			    size_t *auth_len, size_t *pad_len);
NTSTATUS dcerpc_add_auth_footer(struct pipe_auth_data *auth,
				size_t pad_len, DATA_BLOB *rpc_out);
NTSTATUS dcerpc_check_auth(struct pipe_auth_data *auth,
			   struct ncacn_packet *pkt,
			   DATA_BLOB *pkt_trailer,
			   size_t header_size,
			   DATA_BLOB *raw_pkt,
			   size_t *pad_len);

#endif /* __S3_DCERPC_H__ */
