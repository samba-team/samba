/*
   Unix SMB/CIFS implementation.
   DCERPC server info param function
   Moved into rpc_server/common to break dependencies to rpc_server from param
   Copyright (C) Karl Auer 1993-1998

   Largely re-written by Andrew Tridgell, September 1994

   Copyright (C) Simo Sorce 2001
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) Stefan (metze) Metzmacher 2002
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007

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
#include "lib/param/param.h"
#include "rpc_server/common/common.h"

_PUBLIC_ struct dcerpc_server_info *lpcfg_dcerpc_server_info(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	struct dcerpc_server_info *ret = talloc_zero(mem_ctx, struct dcerpc_server_info);

	ret->domain_name = talloc_reference(mem_ctx, lpcfg_workgroup(lp_ctx));
	ret->version_major = lpcfg_parm_int(lp_ctx, NULL, "server_info", "version_major", 5);
	ret->version_minor = lpcfg_parm_int(lp_ctx, NULL, "server_info", "version_minor", 2);
	ret->version_build = lpcfg_parm_int(lp_ctx, NULL, "server_info", "version_build", 3790);

	return ret;
}

