/* 
   Unix SMB/CIFS implementation.

   provide access to string functions

   Copyright (C) Andrew Tridgell 2005
   
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
#include "scripting/ejs/smbcalls.h"
#include "lib/ejs/ejs.h"
#include "system/passwd.h"

/*
  usage:
      var s = strlower("UPPER");
*/
static int ejs_strlower(MprVarHandle eid, int argc, char **argv)
{
	char *s;
	if (argc != 1) {
		ejsSetErrorMsg(eid, "strlower invalid arguments");
		return -1;
	}
	s = strlower_talloc(mprMemCtx(), argv[0]);
	mpr_Return(eid, mprString(s));
	talloc_free(s);
	return 0;
}

/*
  usage:
      var s = strupper("lower");
*/
static int ejs_strupper(MprVarHandle eid, int argc, char **argv)
{
	char *s;
	if (argc != 1) {
		ejsSetErrorMsg(eid, "strupper invalid arguments");
		return -1;
	}
	s = strupper_talloc(mprMemCtx(), argv[0]);
	mpr_Return(eid, mprString(s));
	talloc_free(s);
	return 0;
}


/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_string(void)
{
	ejsDefineStringCFunction(-1, "strlower", ejs_strlower, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "strupper", ejs_strupper, NULL, MPR_VAR_SCRIPT_HANDLE);
}
