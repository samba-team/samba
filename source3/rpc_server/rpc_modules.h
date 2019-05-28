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

#ifndef _RPC_MODULES_H
#define _RPC_MODULES_H

struct rpc_module_fns {
	bool (*setup)(struct tevent_context *ev_ctx,
		      struct messaging_context *msg_ctx);
};

NTSTATUS register_rpc_module(struct rpc_module_fns *fns,
			     const char *name);

bool setup_rpc_modules(struct tevent_context *ev_ctx,
		       struct messaging_context *msg_ctx);

bool setup_rpc_module(struct tevent_context *ev_ctx,
		      struct messaging_context *msg_ctx,
		      const char *name);
#endif
