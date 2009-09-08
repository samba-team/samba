/* 
   Unix SMB/CIFS implementation.

   useful utilities for the DRS server

   Copyright (C) Andrew Tridgell 2009
   
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
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "rpc_server/drsuapi/dcesrv_drsuapi.h"
#include "dsdb/samdb/samdb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "param/param.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "libcli/security/dom_sid.h"

/*
  format a drsuapi_DsReplicaObjectIdentifier naming context as a string
 */
char *drs_ObjectIdentifier_to_string(TALLOC_CTX *mem_ctx,
				     struct drsuapi_DsReplicaObjectIdentifier *nc)
{
	char *guid, *sid, *ret;
	guid = GUID_string(mem_ctx, &nc->guid);
	sid  = dom_sid_string(mem_ctx, &nc->sid);
	ret = talloc_asprintf(mem_ctx, "<GUID=%s>;<SID=%s>;%s",
			      guid, sid, nc->dn);
	talloc_free(guid);
	talloc_free(sid);
	return ret;
}
