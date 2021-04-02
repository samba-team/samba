/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2010-2011
   Copyright (C) Andrew Tridgell 2010-2011
   Copyright (C) Simo Sorce 2010

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

#ifndef __LIBRPC_RPC_DCERPC_UTIL_H__
#define __LIBRPC_RPC_DCERPC_UTIL_H__

#include "replace.h"
#include <talloc.h>
#include "lib/util/data_blob.h"
#include "librpc/rpc/rpc_common.h"
#include "librpc/gen_ndr/dcerpc.h"

void dcerpc_set_frag_length(DATA_BLOB *blob, uint16_t v);
uint16_t dcerpc_get_frag_length(const DATA_BLOB *blob);
void dcerpc_set_auth_length(DATA_BLOB *blob, uint16_t v);
uint16_t dcerpc_get_auth_length(const DATA_BLOB *blob);
uint8_t dcerpc_get_endian_flag(DATA_BLOB *blob);
uint8_t dcerpc_get_auth_type(const DATA_BLOB *blob);
uint8_t dcerpc_get_auth_level(const DATA_BLOB *blob);
uint32_t dcerpc_get_auth_context_id(const DATA_BLOB *blob);
const char *dcerpc_default_transport_endpoint(TALLOC_CTX *mem_ctx,
					      enum dcerpc_transport_t transport,
					      const struct ndr_interface_table *table);

NTSTATUS dcerpc_pull_ncacn_packet(TALLOC_CTX *mem_ctx,
				  const DATA_BLOB *blob,
				  struct ncacn_packet *r);

/**
* @brief	Pull a dcerpc_auth structure, taking account of any auth
*		padding in the blob. For request/response packets we pass
*		the whole data blob, so auth_data_only must be set to false
*		as the blob contains data+pad+auth and no just pad+auth.
*
* @param pkt		- The ncacn_packet strcuture
* @param mem_ctx	- The mem_ctx used to allocate dcerpc_auth elements
* @param pkt_trailer	- The packet trailer data, usually the trailing
*			  auth_info blob, but in the request/response case
*			  this is the stub_and_verifier blob.
* @param auth		- A preallocated dcerpc_auth *empty* structure
* @param auth_length	- The length of the auth trail, sum of auth header
*			  lenght and pkt->auth_length
* @param auth_data_only	- Whether the pkt_trailer includes only the auth_blob
*			  (+ padding) or also other data.
*
* @return		- A NTSTATUS error code.
*/
NTSTATUS dcerpc_pull_auth_trailer(const struct ncacn_packet *pkt,
				  TALLOC_CTX *mem_ctx,
				  const DATA_BLOB *pkt_trailer,
				  struct dcerpc_auth *auth,
				  uint32_t *auth_length,
				  bool auth_data_only);
NTSTATUS dcerpc_verify_ncacn_packet_header(const struct ncacn_packet *pkt,
					   enum dcerpc_pkt_type ptype,
					   size_t max_auth_info,
					   uint8_t required_flags,
					   uint8_t optional_flags);
struct tevent_req *dcerpc_read_ncacn_packet_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct tstream_context *stream);
NTSTATUS dcerpc_read_ncacn_packet_recv(struct tevent_req *req,
				       TALLOC_CTX *mem_ctx,
				       struct ncacn_packet **pkt,
				       DATA_BLOB *buffer);

#endif
