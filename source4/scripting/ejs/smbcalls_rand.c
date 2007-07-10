/* 
   Unix SMB/CIFS implementation.

   provide access to randomisation functions

   Copyright (C) Andrew Tridgell 2005
   
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
#include "system/passwd.h"
#include "librpc/gen_ndr/ndr_misc.h"

/*
  usage:
      var i = random();
*/
static int ejs_random(MprVarHandle eid, int argc, struct MprVar **argv)
{
	mpr_Return(eid, mprCreateIntegerVar(generate_random()));
	return 0;
}

/*
  usage:
      var s = randpass(len);
*/
static int ejs_randpass(MprVarHandle eid, int argc, struct MprVar **argv)
{
	char *s;
	if (argc != 1 || !mprVarIsNumber(argv[0]->type)) {
		ejsSetErrorMsg(eid, "randpass invalid arguments");
		return -1;
	}
	s = generate_random_str(mprMemCtx(), mprToInt(argv[0]));
	mpr_Return(eid, mprString(s));
	talloc_free(s);
	return 0;
}

/*
  usage:
      var guid = randguid();
*/
static int ejs_randguid(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct GUID guid = GUID_random();
	char *s = GUID_string(mprMemCtx(), &guid);
	mpr_Return(eid, mprString(s));
	talloc_free(s);
	return 0;
}

/*
  usage:
      var sid = randsid();
*/
static int ejs_randsid(MprVarHandle eid, int argc, struct MprVar **argv)
{
	char *s = talloc_asprintf(mprMemCtx(), "S-1-5-21-%8u-%8u-%8u", 
				  (unsigned)generate_random(), 
				  (unsigned)generate_random(), 
				  (unsigned)generate_random());
	mpr_Return(eid, mprString(s));
	talloc_free(s);
	return 0;
}

/*
  initialise random ejs subsystem
*/
static int ejs_random_init(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *obj = mprInitObject(eid, "random", argc, argv);

	mprSetCFunction(obj, "random", ejs_random);
	mprSetCFunction(obj, "randpass", ejs_randpass);
	mprSetCFunction(obj, "randguid", ejs_randguid);
	mprSetCFunction(obj, "randsid", ejs_randsid);
	return 0;
}

/*
  setup C functions that be called from ejs
*/
NTSTATUS smb_setup_ejs_random(void)
{
	ejsDefineCFunction(-1, "random_init", ejs_random_init, NULL, MPR_VAR_SCRIPT_HANDLE);
	return NT_STATUS_OK;
}
