/* 
   Unix SMB/CIFS implementation.

   Running objects database

   Copyright (C) Jelmer Vernooij 2004
   
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

#include "includes.h"
#include "rpc_server/dcerpc_server.h"
#include "librpc/gen_ndr/ndr_rot.h"
#include "rpc_server/common/common.h"

struct tdb_wrap *openrodb(TALLOC_CTX *mem_ctx)
{
	struct tdb_wrap *wrap;
	char *rodb_name = NULL;
	
	asprintf(&rodb_name, "%s/rot.tdb", lp_lockdir());
	wrap = tdb_wrap_open(mem_ctx, rodb_name, 0, 0, O_RDWR|O_CREAT, 0600);
	SAFE_FREE(rodb_name);

	return wrap;
}

