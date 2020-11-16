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

#ifndef __LIBRPC_RPC_DCERPC_PKT_AUTH_H__
#define __LIBRPC_RPC_DCERPC_PKT_AUTH_H__

#include "replace.h"
#include <talloc.h>
#include "lib/util/data_blob.h"
#include "libcli/util/ntstatus.h"
#include "librpc/rpc/rpc_common.h"
#include "librpc/gen_ndr/dcerpc.h"

NTSTATUS dcerpc_ncacn_pull_pkt_auth(const struct dcerpc_auth *auth_state,
				    struct gensec_security *gensec,
				    bool check_pkt_auth_fields,
				    TALLOC_CTX *mem_ctx,
				    enum dcerpc_pkt_type ptype,
				    uint8_t required_flags,
				    uint8_t optional_flags,
				    uint8_t payload_offset,
				    DATA_BLOB *payload_and_verifier,
				    DATA_BLOB *raw_packet,
				    const struct ncacn_packet *pkt);
NTSTATUS dcerpc_ncacn_push_pkt_auth(const struct dcerpc_auth *auth_state,
				    struct gensec_security *gensec,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *raw_packet,
				    size_t sig_size,
				    uint8_t payload_offset,
				    const DATA_BLOB *payload,
				    const struct ncacn_packet *pkt);
struct tevent_req *dcerpc_read_ncacn_packet_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct tstream_context *stream);
NTSTATUS dcerpc_read_ncacn_packet_recv(struct tevent_req *req,
				       TALLOC_CTX *mem_ctx,
				       struct ncacn_packet **pkt,
				       DATA_BLOB *buffer);

#endif
