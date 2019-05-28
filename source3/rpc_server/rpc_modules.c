/*
 *  Unix SMB/CIFS implementation.
 *
 *  SMBD RPC modules
 *
 *  Copyright (c) 2015 Ralph Boehme <slow@samba.org>
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
#include "rpc_server/rpc_modules.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static struct rpc_module *rpc_modules;

struct rpc_module {
	struct rpc_module *prev, *next;
	char *name;
	struct rpc_module_fns *fns;
};

static struct rpc_module *find_rpc_module(const char *name)
{
	struct rpc_module *module = NULL;

	for (module = rpc_modules; module != NULL; module = module->next) {
		if (strequal(module->name, name)) {
			return module;
		}
	}

	return NULL;
}

NTSTATUS register_rpc_module(struct rpc_module_fns *fns,
			     const char *name)
{
	struct rpc_module *module = find_rpc_module(name);

	if (module != NULL) {
		DBG_ERR("RPC module %s already loaded!\n", name);
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	module = SMB_XMALLOC_P(struct rpc_module);
	module->name = smb_xstrdup(name);
	module->fns = fns;

	DLIST_ADD(rpc_modules, module);
	DBG_NOTICE("Successfully added RPC module '%s'\n", name);

	return NT_STATUS_OK;
}

bool setup_rpc_module(struct tevent_context *ev_ctx,
		      struct messaging_context *msg_ctx,
		      const char *name)
{
	bool ok;
	struct rpc_module *module = find_rpc_module(name);

	if (module == NULL) {
		return false;
	}

	ok = module->fns->setup(ev_ctx, msg_ctx);
	if (!ok) {
		DBG_ERR("calling setup for %s failed\n", name);
	}

	return true;
}

bool setup_rpc_modules(struct tevent_context *ev_ctx,
		       struct messaging_context *msg_ctx)
{
	bool ok;
	struct rpc_module *module = rpc_modules;

	for (module = rpc_modules; module; module = module->next) {
		ok = module->fns->setup(ev_ctx, msg_ctx);
		if (!ok) {
			DBG_ERR("calling setup for %s failed\n", module->name);
		}
	}

	return true;
}
