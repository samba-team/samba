/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Almost completely rewritten by (C) Jeremy Allison 2005 - 2010
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
#include "ntdomain.h"

#include "rpc_contexts.h"

struct pipe_rpc_fns *find_pipe_fns_by_context(struct pipe_rpc_fns *list,
					      uint32_t context_id)
{
	struct pipe_rpc_fns *fns = NULL;

	if ( !list ) {
		DEBUG(0,("find_pipe_fns_by_context: ERROR!  No context list for pipe!\n"));
		return NULL;
	}

	for (fns=list; fns; fns=fns->next ) {
		if ( fns->context_id == context_id )
			return fns;
	}
	return NULL;
}
