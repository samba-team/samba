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

#include "source3/librpc/rpc/dcerpc.h"

struct tsocket_address;
struct pipes_struct;
struct dcesrv_context;

/*
 * DCE/RPC-specific samba-internal-specific handling of data on
 * NamedPipes.
 */
struct pipes_struct {
	enum dcerpc_transport_t transport;

	struct messaging_context *msg_ctx;

	/*
	 * Set the DCERPC_FAULT to return.
	 */
	int fault_state;

	/* This context is used for PDU data and is freed between each pdu.
		Don't use for pipe state storage. */
	TALLOC_CTX *mem_ctx;

	/* handle database to use on this pipe. */
	struct dcesrv_call_state *dce_call;
};

bool check_open_pipes(void);
size_t num_pipe_handles(void);

void *create_policy_hnd(struct pipes_struct *p,
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
bool pipe_access_check(struct pipes_struct *p);

#define DCESRV_COMPAT_NOT_USED_ON_WIRE(__opname) \
void _## __opname(struct pipes_struct *p, struct __opname *r) \
{ \
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR; \
}

#endif /* _RPC_PIPES_H_ */
