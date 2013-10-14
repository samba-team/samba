/* 
   Unix SMB/CIFS implementation.
   Parameter loading functions
   Copyright (C) Andrew Bartlett 2011

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
#include "lib/param/s3_param.h"

static struct loadparm_service *lp_service_for_s4_ctx(const char *servicename)
{
	TALLOC_CTX *mem_ctx;
	struct loadparm_service *service;

	mem_ctx = talloc_stackframe();
	service = lp_service(servicename);
	talloc_free(mem_ctx);

	return service;
}

static struct loadparm_service *lp_servicebynum_for_s4_ctx(int servicenum)
{
	TALLOC_CTX *mem_ctx;
	struct loadparm_service *service;

	mem_ctx = talloc_stackframe();
	service = lp_servicebynum(servicenum);
	talloc_free(mem_ctx);

	return service;
}

static bool lp_load_for_s4_ctx(const char *filename)
{
	TALLOC_CTX *mem_ctx;
	bool status;

	mem_ctx = talloc_stackframe();
	status =  lp_load(filename, false, false, false, false);
	talloc_free(mem_ctx);

	return status;
}

#include "loadparm_ctx_table.c"

const struct loadparm_s3_helpers *loadparm_s3_helpers(void)
{
	return &s3_fns;
}
