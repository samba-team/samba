/* 
   Unix SMB/CIFS implementation.
   NTVFS base code

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
/*
  this implements the core code for all NTVFS modules. Backends register themselves here.
*/

#include "includes.h"
#include "lib/util/dlinklist.h"
#include "build.h"
#include "ntvfs/ntvfs.h"

/* the list of currently registered NTVFS backends, note that there
 * can be more than one backend with the same name, as long as they
 * have different typesx */
static struct ntvfs_backend {
	const struct ntvfs_ops *ops;
} *backends = NULL;
static int num_backends;

/*
  register a NTVFS backend. 

  The 'name' can be later used by other backends to find the operations
  structure for this backend.  

  The 'type' is used to specify whether this is for a disk, printer or IPC$ share
*/
_PUBLIC_ NTSTATUS ntvfs_register(const struct ntvfs_ops *ops,
				 const struct ntvfs_critical_sizes *const sizes)
{
	struct ntvfs_ops *new_ops;

	if (ntvfs_interface_differs(sizes)) {
		DEBUG(0, ("NTVFS backend '%s' for type %d "
			  "failed version check\n",
			  ops->name, (int)ops->type));
		return NT_STATUS_BAD_FUNCTION_TABLE;
	}

	if (ntvfs_backend_byname(ops->name, ops->type) != NULL) {
		/* its already registered! */
		DEBUG(0,("NTVFS backend '%s' for type %d already registered\n", 
			 ops->name, (int)ops->type));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	backends = realloc_p(backends, struct ntvfs_backend, num_backends+1);
	if (!backends) {
		smb_panic("out of memory in ntvfs_register");
	}

	new_ops = smb_xmemdup(ops, sizeof(*ops));
	new_ops->name = smb_xstrdup(ops->name);

	backends[num_backends].ops = new_ops;

	num_backends++;

	DEBUG(3,("NTVFS backend '%s' for type %d registered\n", 
		 ops->name,ops->type));

	return NT_STATUS_OK;
}


/*
  return the operations structure for a named backend of the specified type
*/
_PUBLIC_ const struct ntvfs_ops *ntvfs_backend_byname(const char *name, enum ntvfs_type type)
{
	int i;

	for (i=0;i<num_backends;i++) {
		if (backends[i].ops->type == type && 
		    strcmp(backends[i].ops->name, name) == 0) {
			return backends[i].ops;
		}
	}

	return NULL;
}


/*
  return the NTVFS interface version, and the size of some critical types
  This can be used by backends to either detect compilation errors, or provide
  multiple implementations for different smbd compilation options in one module
*/

static const NTVFS_CURRENT_CRITICAL_SIZES(critical_sizes);

_PUBLIC_ const struct ntvfs_critical_sizes *ntvfs_interface_version(void)
{
	return &critical_sizes;
}

_PUBLIC_ BOOL ntvfs_interface_differs(const struct ntvfs_critical_sizes *const iface)
{
	/* The comparison would be easier with memcmp, but compiler-interset
	 * alignment padding is not guaranteed to be zeroed.
	 */

#define FIELD_DIFFERS(field) (iface->field != critical_sizes.field)

	if (FIELD_DIFFERS(interface_version))
		return True;

	if (FIELD_DIFFERS(sizeof_ntvfs_critical_sizes))
		return True;

	if (FIELD_DIFFERS(sizeof_ntvfs_context))
		return True;

	if (FIELD_DIFFERS(sizeof_ntvfs_module_context))
		return True;

	if (FIELD_DIFFERS(sizeof_ntvfs_ops))
		return True;

	if (FIELD_DIFFERS(sizeof_ntvfs_async_state))
		return True;

	if (FIELD_DIFFERS(sizeof_ntvfs_request))
		return True;

	/* Versions match. */
	return False;

#undef FIELD_DIFFERS
}

/*
  initialise a connection structure to point at a NTVFS backend
*/
NTSTATUS ntvfs_init_connection(TALLOC_CTX *mem_ctx, struct share_config *scfg, enum ntvfs_type type,
			       enum protocol_types protocol,
			       struct event_context *ev, struct messaging_context *msg,
			       struct server_id server_id, struct ntvfs_context **_ctx)
{
	const char **handlers = share_string_list_option(mem_ctx, scfg, SHARE_NTVFS_HANDLER);
	int i;
	struct ntvfs_context *ctx;

	if (!handlers) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	ctx = talloc_zero(mem_ctx, struct ntvfs_context);
	NT_STATUS_HAVE_NO_MEMORY(ctx);
	ctx->protocol		= protocol;
	ctx->type		= type;
	ctx->config		= talloc_steal(ctx, scfg);
	ctx->event_ctx		= ev;
	ctx->msg_ctx		= msg;
	ctx->server_id		= server_id;

	for (i=0; handlers[i]; i++) {
		struct ntvfs_module_context *ntvfs;

		ntvfs = talloc_zero(ctx, struct ntvfs_module_context);
		NT_STATUS_HAVE_NO_MEMORY(ntvfs);
		ntvfs->ctx = ctx;
		ntvfs->ops = ntvfs_backend_byname(handlers[i], ctx->type);
		if (!ntvfs->ops) {
			DEBUG(1,("ntvfs_init_connection: failed to find backend=%s, type=%d\n",
				handlers[i], ctx->type));
			return NT_STATUS_INTERNAL_ERROR;
		}
		ntvfs->depth = i;
		DLIST_ADD_END(ctx->modules, ntvfs, struct ntvfs_module_context *);
	}

	if (!ctx->modules) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	*_ctx = ctx;
	return NT_STATUS_OK;
}

NTSTATUS ntvfs_init(void)
{
	init_module_fn static_init[] = STATIC_ntvfs_MODULES;
	init_module_fn *shared_init = load_samba_modules(NULL, "ntvfs");

	run_init_functions(static_init);
	run_init_functions(shared_init);

	talloc_free(shared_init);
	
	return NT_STATUS_OK;
}
