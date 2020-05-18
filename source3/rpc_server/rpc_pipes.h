/*
   Unix SMB/Netbios implementation.
   RPC Server Headers
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   Copyright (C) Jeremy Allison 2000-2004
   Copyright (C) Simo Sorce 2010-2011

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

#ifndef _RPC_PIPES_H_
#define _RPC_PIPES_H_

#include "librpc/rpc/dcerpc.h"

struct dcesrv_ep_entry_list;
struct tsocket_address;
struct pipes_struct;
struct dcesrv_context;

/*
 * DCE/RPC-specific samba-internal-specific handling of data on
 * NamedPipes.
 */
struct pipes_struct {
	struct pipes_struct *next, *prev;

	const struct tsocket_address *local_address;
	const struct tsocket_address *remote_address;

	enum dcerpc_transport_t transport;

	struct auth_session_info *session_info;
	struct messaging_context *msg_ctx;

	struct dcesrv_ep_entry_list *ep_entries;

	struct pipe_auth_data auth;

	/*
	 * Set to true when an RPC bind has been done on this pipe.
	 */
	bool pipe_bound;

	/*
	 * Set the DCERPC_FAULT to return.
	 */
	int fault_state;

	/* This context is used for PDU data and is freed between each pdu.
		Don't use for pipe state storage. */
	TALLOC_CTX *mem_ctx;

	/* handle database to use on this pipe. */
	struct dcesrv_call_state *dce_call;

	/* call id retrieved from the pdu header */
	uint32_t call_id;

	/* operation number retrieved from the rpc header */
	uint16_t opnum;

	/* private data for the interface implementation */
	void *private_data;

};

int make_base_pipes_struct(TALLOC_CTX *mem_ctx,
			   struct messaging_context *msg_ctx,
			   const char *pipe_name,
			   enum dcerpc_transport_t transport,
			   const struct tsocket_address *remote_address,
			   const struct tsocket_address *local_address,
			   struct pipes_struct **_p);

bool check_open_pipes(void);
size_t num_pipe_handles(void);

bool create_policy_hnd(struct pipes_struct *p,
			struct policy_handle *hnd,
			uint8_t handle_type,
			void *data_ptr);

void *_find_policy_by_hnd(struct pipes_struct *p,
			  const struct policy_handle *hnd,
			  uint8_t handle_type,
			  NTSTATUS *pstatus);
#define find_policy_by_hnd(_p, _hnd, _hnd_type, _type, _pstatus) \
	(_type *)_find_policy_by_hnd((_p), (_hnd), (_hnd_type), (_pstatus));

bool close_policy_hnd(struct pipes_struct *p, struct policy_handle *hnd);
void close_policy_by_pipe(struct pipes_struct *p);
bool pipe_access_check(struct pipes_struct *p);

#endif /* _RPC_PIPES_H_ */
