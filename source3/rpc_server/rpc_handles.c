/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Jeremy Allison			   2001.
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

#include "includes.h"
#include "system/passwd.h" /* uid_wrapper */
#include "../librpc/gen_ndr/ndr_lsa.h"
#include "../librpc/gen_ndr/ndr_samr.h"
#include "auth.h"
#include "rpc_server/rpc_pipes.h"
#include "../libcli/security/security.h"
#include "lib/tsocket/tsocket.h"
#include "librpc/ndr/ndr_table.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static struct pipes_struct *InternalPipes;

/* TODO
 * the following prototypes are declared here to avoid
 * code being moved about too much for a patch to be
 * disrupted / less obvious.
 *
 * these functions, and associated functions that they
 * call, should be moved behind a .so module-loading
 * system _anyway_.  so that's the next step...
 */

int make_base_pipes_struct(TALLOC_CTX *mem_ctx,
			   struct messaging_context *msg_ctx,
			   const char *pipe_name,
			   enum dcerpc_transport_t transport,
			   bool endian,
			   const struct tsocket_address *remote_address,
			   const struct tsocket_address *local_address,
			   struct pipes_struct **_p)
{
	struct pipes_struct *p;

	p = talloc_zero(mem_ctx, struct pipes_struct);
	if (!p) {
		return ENOMEM;
	}

	p->mem_ctx = talloc_named(p, 0, "pipe %s %p", pipe_name, p);
	if (!p->mem_ctx) {
		talloc_free(p);
		return ENOMEM;
	}

	p->msg_ctx = msg_ctx;
	p->transport = transport;
	p->endian = endian;

	p->remote_address = tsocket_address_copy(remote_address, p);
	if (p->remote_address == NULL) {
		talloc_free(p);
		return ENOMEM;
	}

	if (local_address) {
		p->local_address = tsocket_address_copy(local_address, p);
		if (p->local_address == NULL) {
			talloc_free(p);
			return ENOMEM;
		}
	}

	DLIST_ADD(InternalPipes, p);
	talloc_set_destructor(p, close_internal_rpc_pipe_hnd);

	*_p = p;
	return 0;
}


bool check_open_pipes(void)
{
	struct pipes_struct *p;

	for (p = InternalPipes; p != NULL; p = p->next) {
		if (num_pipe_handles(p) != 0) {
			return true;
		}
	}
	return false;
}

/****************************************************************************
 Close an rpc pipe.
****************************************************************************/

int close_internal_rpc_pipe_hnd(struct pipes_struct *p)
{
	if (!p) {
		DEBUG(0,("Invalid pipe in close_internal_rpc_pipe_hnd\n"));
		return False;
	}

	/* Free the handles database. */
	close_policy_by_pipe(p);

	DLIST_REMOVE(InternalPipes, p);

	return 0;
}

/*
 * Handle database - stored per pipe.
 */

struct dcesrv_handle {
	struct dcesrv_handle *prev, *next;
	struct policy_handle wire_handle;
	uint32_t access_granted;
	void *data;
};

struct handle_list {
	struct dcesrv_handle *handles;	/* List of pipe handles. */
	size_t count;			/* Current number of handles. */
	size_t pipe_ref_count;		/* Number of pipe handles referring
					 * to this tree. */
};

/* This is the max handles across all instances of a pipe name. */
#ifndef MAX_OPEN_POLS
#define MAX_OPEN_POLS 2048
#endif

/****************************************************************************
 Hack as handles need to be persisant over lsa pipe closes so long as a samr
 pipe is open. JRA.
****************************************************************************/

static bool is_samr_lsa_pipe(const struct ndr_syntax_id *syntax)
{
	return (ndr_syntax_id_equal(syntax, &ndr_table_samr.syntax_id)
		|| ndr_syntax_id_equal(syntax, &ndr_table_lsarpc.syntax_id));
}

size_t num_pipe_handles(struct pipes_struct *p)
{
	if (p->pipe_handles == NULL) {
		return 0;
	}
	return p->pipe_handles->count;
}

/****************************************************************************
 Initialise a policy handle list on a pipe. Handle list is shared between all
 pipes of the same name.
****************************************************************************/

bool init_pipe_handles(struct pipes_struct *p, const struct ndr_syntax_id *syntax)
{
	struct pipes_struct *plist;
	struct handle_list *hl;

	for (plist = InternalPipes; plist; plist = plist->next) {
		struct pipe_rpc_fns *p_ctx;
		bool stop = false;

		for (p_ctx = plist->contexts;
		     p_ctx != NULL;
		     p_ctx = p_ctx->next) {
			if (ndr_syntax_id_equal(syntax, &p_ctx->syntax)) {
				stop = true;
				break;
			}
			if (is_samr_lsa_pipe(&p_ctx->syntax)
			    && is_samr_lsa_pipe(syntax)) {
				/*
				 * samr and lsa share a handle space (same process
				 * under Windows?)
				 */
				stop = true;
				break;
			}
		}

		if (stop) {
			break;
		}
	}

	if (plist != NULL) {
		hl = plist->pipe_handles;
		if (hl == NULL) {
			return false;
		}
	} else {
		/*
		 * First open, we have to create the handle list
		 */
		hl = talloc_zero(NULL, struct handle_list);
		if (hl == NULL) {
			return false;
		}

		DEBUG(10,("init_pipe_handle_list: created handle list for "
			  "pipe %s\n",
			  ndr_interface_name(&syntax->uuid,
					     syntax->if_version)));
	}

	/*
	 * One more pipe is using this list.
	 */

	hl->pipe_ref_count++;

	/*
	 * Point this pipe at this list.
	 */

	p->pipe_handles = hl;

	DEBUG(10,("init_pipe_handle_list: pipe_handles ref count = %lu for "
		  "pipe %s\n", (unsigned long)p->pipe_handles->pipe_ref_count,
		  ndr_interface_name(&syntax->uuid, syntax->if_version)));

	return True;
}

/****************************************************************************
  find first available policy slot.  creates a policy handle for you.

  If "data_ptr" is given, this must be a talloc'ed object, create_policy_hnd
  talloc_moves this into the handle. If the policy_hnd is closed,
  data_ptr is TALLOC_FREE()'ed
****************************************************************************/

static struct dcesrv_handle *create_rpc_handle_internal(struct pipes_struct *p,
				struct policy_handle *hnd, void *data_ptr)
{
	struct dcesrv_handle *rpc_hnd;
	static uint32 pol_hnd_low  = 0;
	static uint32 pol_hnd_high = 0;
	time_t t = time(NULL);

	if (p->pipe_handles->count > MAX_OPEN_POLS) {
		DEBUG(0,("create_policy_hnd: ERROR: too many handles (%d) on this pipe.\n",
				(int)p->pipe_handles->count));
		return NULL;
	}

	rpc_hnd = talloc_zero(p->pipe_handles, struct dcesrv_handle);
	if (!rpc_hnd) {
		DEBUG(0,("create_policy_hnd: ERROR: out of memory!\n"));
		return NULL;
	}

	if (data_ptr != NULL) {
		rpc_hnd->data = talloc_move(rpc_hnd, &data_ptr);
	}

	pol_hnd_low++;
	if (pol_hnd_low == 0) {
		pol_hnd_high++;
	}

	/* first bit must be null */
	SIVAL(&rpc_hnd->wire_handle.handle_type, 0 , 0);

	/* second bit is incrementing */
	SIVAL(&rpc_hnd->wire_handle.uuid.time_low, 0 , pol_hnd_low);
	SSVAL(&rpc_hnd->wire_handle.uuid.time_mid, 0 , pol_hnd_high);
	SSVAL(&rpc_hnd->wire_handle.uuid.time_hi_and_version, 0, (pol_hnd_high >> 16));

	/* split the current time into two 16 bit values */

	/* something random */
	SSVAL(rpc_hnd->wire_handle.uuid.clock_seq, 0, (t >> 16));
	/* something random */
	SSVAL(rpc_hnd->wire_handle.uuid.node, 0, t);
	/* something more random */
	SIVAL(rpc_hnd->wire_handle.uuid.node, 2, getpid());

	DLIST_ADD(p->pipe_handles->handles, rpc_hnd);
	p->pipe_handles->count++;

	*hnd = rpc_hnd->wire_handle;

	DEBUG(6, ("Opened policy hnd[%d] ", (int)p->pipe_handles->count));
	dump_data(6, (uint8_t *)hnd, sizeof(*hnd));

	return rpc_hnd;
}

bool create_policy_hnd(struct pipes_struct *p, struct policy_handle *hnd,
		       void *data_ptr)
{
	struct dcesrv_handle *rpc_hnd;

	rpc_hnd = create_rpc_handle_internal(p, hnd, data_ptr);
	if (rpc_hnd == NULL) {
		return false;
	}
	return true;
}

/****************************************************************************
  find policy by handle - internal version.
****************************************************************************/

static struct dcesrv_handle *find_policy_by_hnd_internal(struct pipes_struct *p,
				const struct policy_handle *hnd, void **data_p)
{
	struct dcesrv_handle *h;
	unsigned int count;

	if (data_p) {
		*data_p = NULL;
	}

	count = 0;
	for (h = p->pipe_handles->handles; h != NULL; h = h->next) {
		if (memcmp(&h->wire_handle, hnd, sizeof(*hnd)) == 0) {
			DEBUG(6,("Found policy hnd[%u] ", count));
			dump_data(6, (const uint8 *)hnd, sizeof(*hnd));
			if (data_p) {
				*data_p = h->data;
			}
			return h;
		}
		count++;
	}

	DEBUG(4,("Policy not found: "));
	dump_data(4, (const uint8_t *)hnd, sizeof(*hnd));

	p->fault_state = DCERPC_FAULT_CONTEXT_MISMATCH;

	return NULL;
}

/****************************************************************************
  find policy by handle
****************************************************************************/

bool find_policy_by_hnd(struct pipes_struct *p, const struct policy_handle *hnd,
			void **data_p)
{
	struct dcesrv_handle *rpc_hnd;

	rpc_hnd = find_policy_by_hnd_internal(p, hnd, data_p);
	if (rpc_hnd == NULL) {
		return false;
	}
	return true;
}

/****************************************************************************
  Close a policy.
****************************************************************************/

bool close_policy_hnd(struct pipes_struct *p, struct policy_handle *hnd)
{
	struct dcesrv_handle *rpc_hnd;

	rpc_hnd = find_policy_by_hnd_internal(p, hnd, NULL);

	if (rpc_hnd == NULL) {
		DEBUG(3, ("Error closing policy (policy not found)\n"));
		return false;
	}

	DEBUG(6,("Closed policy\n"));

	p->pipe_handles->count--;

	DLIST_REMOVE(p->pipe_handles->handles, rpc_hnd);
	TALLOC_FREE(rpc_hnd);

	return true;
}

/****************************************************************************
 Close a pipe - free the handle set if it was the last pipe reference.
****************************************************************************/

void close_policy_by_pipe(struct pipes_struct *p)
{
	if (p->pipe_handles == NULL) {
		return;
	}

	p->pipe_handles->pipe_ref_count--;

	if (p->pipe_handles->pipe_ref_count == 0) {
		/*
		 * Last pipe open on this list - free the list.
		 */
		TALLOC_FREE(p->pipe_handles);

		DEBUG(10,("Deleted handle list for RPC connection %s\n",
			  ndr_interface_name(&p->contexts->syntax.uuid,
					     p->contexts->syntax.if_version)));
	}
}

/*******************************************************************
Shall we allow access to this rpc?  Currently this function
implements the 'restrict anonymous' setting by denying access to
anonymous users if the restrict anonymous level is > 0.  Further work
will be checking a security descriptor to determine whether a user
token has enough access to access the pipe.
********************************************************************/

bool pipe_access_check(struct pipes_struct *p)
{
	/* Don't let anonymous users access this RPC if restrict
	   anonymous > 0 */

	if (lp_restrict_anonymous() > 0) {

		/* schannel, so we must be ok */
		if (p->pipe_bound &&
		    (p->auth.auth_type == DCERPC_AUTH_TYPE_SCHANNEL)) {
			return True;
		}

		if (security_session_user_level(p->session_info, NULL) < SECURITY_USER) {
			return False;
		}
	}

	return True;
}

void *_policy_handle_create(struct pipes_struct *p, struct policy_handle *hnd,
			    uint32_t access_granted, size_t data_size,
			    const char *type, NTSTATUS *pstatus)
{
	struct dcesrv_handle *rpc_hnd;
	void *data;

	if (p->pipe_handles->count > MAX_OPEN_POLS) {
		DEBUG(0, ("ERROR: Too many handles (%d) for RPC connection %s\n",
			  (int) p->pipe_handles->count,
			  ndr_interface_name(&p->contexts->syntax.uuid,
					     p->contexts->syntax.if_version)));

		*pstatus = NT_STATUS_INSUFFICIENT_RESOURCES;
		return NULL;
	}

	data = talloc_size(talloc_tos(), data_size);
	if (data == NULL) {
		*pstatus = NT_STATUS_NO_MEMORY;
		return NULL;
	}
	talloc_set_name_const(data, type);

	rpc_hnd = create_rpc_handle_internal(p, hnd, data);
	if (rpc_hnd == NULL) {
		TALLOC_FREE(data);
		*pstatus = NT_STATUS_NO_MEMORY;
		return NULL;
	}
	rpc_hnd->access_granted = access_granted;
	*pstatus = NT_STATUS_OK;
	return data;
}

void *_policy_handle_find(struct pipes_struct *p,
			  const struct policy_handle *hnd,
			  uint32_t access_required,
			  uint32_t *paccess_granted,
			  const char *name, const char *location,
			  NTSTATUS *pstatus)
{
	struct dcesrv_handle *rpc_hnd;
	void *data;

	rpc_hnd = find_policy_by_hnd_internal(p, hnd, &data);
	if (rpc_hnd == NULL) {
		*pstatus = NT_STATUS_INVALID_HANDLE;
		return NULL;
	}
	if (strcmp(name, talloc_get_name(data)) != 0) {
		DEBUG(10, ("expected %s, got %s\n", name,
			   talloc_get_name(data)));
		*pstatus = NT_STATUS_INVALID_HANDLE;
		return NULL;
	}
	if ((access_required & rpc_hnd->access_granted) != access_required) {
		if (root_mode()) {
			DEBUG(4, ("%s: ACCESS should be DENIED (granted: "
				  "%#010x; required: %#010x)\n", location,
				  rpc_hnd->access_granted, access_required));
			DEBUGADD(4,("but overwritten by euid == 0\n"));
			goto okay;
		}
		DEBUG(2,("%s: ACCESS DENIED (granted: %#010x; required: "
			 "%#010x)\n", location, rpc_hnd->access_granted,
			 access_required));
		*pstatus = NT_STATUS_ACCESS_DENIED;
		return NULL;
	}

 okay:
	DEBUG(10, ("found handle of type %s\n", talloc_get_name(data)));
	if (paccess_granted != NULL) {
		*paccess_granted = rpc_hnd->access_granted;
	}
	*pstatus = NT_STATUS_OK;
	return data;
}
