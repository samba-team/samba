/*
   Unix SMB/CIFS implementation.

   Copyright (C) Ralph Boehme 2016

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

#ifndef _TSTREAM_BINDING_HANDLE_H_
#define _TSTREAM_BINDING_HANDLE_H_

#include <talloc.h>
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "librpc/rpc/rpc_common.h"
#include "libcli/util/tstream.h"

struct dcerpc_binding_handle *tstream_binding_handle_create(
	TALLOC_CTX *mem_ctx,
	const struct ndr_interface_table *table,
	struct tstream_context **stream,
	size_t call_initial_read_size,
	tstream_read_pdu_blob_full_fn_t *complete_pdu_fn,
	void *complete_pdu_fn_private,
	uint32_t max_data);

#endif /* _TSTREAM_BINDING_HANDLE_H_ */
