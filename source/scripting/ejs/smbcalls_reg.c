/* 
   Unix SMB/CIFS implementation.

   provide hooks into smbd C calls from ejs scripts

   Copyright (C) Jelmer Vernooij 2007
   
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
#include "scripting/ejs/smbcalls.h"
#include "lib/appweb/ejs/ejs.h"
#include "db_wrap.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/ndr/libndr.h"
#include "lib/registry/registry.h"

/*
  get the connected db
 */
static struct registry_context *ejs_get_reg_context(int eid)
{
	struct registry_context *rctx = mprGetThisPtr(eid, "registry");
	if (rctx == NULL) {
		ejsSetErrorMsg(eid, "unable to find registry");
	}
	return rctx;
}

static int ejs_apply_patchfile(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct registry_context *rctx;
	WERROR error;

	/* validate arguments */
	if (argc != 1) {
		ejsSetErrorMsg(eid, "reg.apply_patchfile invalid number of arguments");
		return -1;
	}

	rctx = ejs_get_reg_context(eid);
	if (rctx == NULL) {
		return -1;
	}
	
	error = reg_diff_apply(mprToString(argv[0]), rctx);

	mpr_Return(eid, mprWERROR(error));

	return 0;
}

/*
  initialise registry ejs subsystem
*/
static int ejs_reg_open(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *reg = mprInitObject(eid, "registry", argc, argv);
	struct registry_context *rctx;
	WERROR error;

	error = reg_open_samba(mprMemCtx(), &rctx, NULL, NULL);
	SMB_ASSERT(W_ERROR_IS_OK(error));

	mprSetPtrChild(reg, "registry", rctx);
	mprSetCFunction(reg, "apply_patchfile", ejs_apply_patchfile);

	return 0;
}


/*
  setup C functions that be called from ejs
*/
NTSTATUS smb_setup_ejs_reg(void)
{
	ejsDefineCFunction(-1, "reg_open", ejs_reg_open, NULL, MPR_VAR_SCRIPT_HANDLE);
	return NT_STATUS_OK;
}
