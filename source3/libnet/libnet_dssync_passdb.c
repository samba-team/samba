/*
   Unix SMB/CIFS implementation.

   Copyright (C) Guenther Deschner <gd@samba.org> 2008

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

#include "includes.h"
#include "libnet/libnet_dssync.h"

/****************************************************************
****************************************************************/

static NTSTATUS passdb_startup(struct dssync_context *ctx, TALLOC_CTX *mem_ctx,
			       struct replUpToDateVectorBlob **pold_utdv)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

static NTSTATUS passdb_finish(struct dssync_context *ctx, TALLOC_CTX *mem_ctx,
			      struct replUpToDateVectorBlob *new_utdv)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

static NTSTATUS passdb_process_objects(struct dssync_context *ctx,
				       TALLOC_CTX *mem_ctx,
				       struct drsuapi_DsReplicaObjectListItemEx *cur,
				       struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

const struct dssync_ops libnet_dssync_passdb_ops = {
	.startup		= passdb_startup,
	.process_objects	= passdb_process_objects,
	.finish			= passdb_finish,
};
