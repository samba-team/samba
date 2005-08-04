/* 
   Unix SMB/CIFS implementation.

   provide hooks credentials calls

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
#include "lib/appweb/ejs/ejs.h"

/*
  helper function to get the local objects credentials ptr
*/
static struct cli_credentials *ejs_creds_get_credentials(int eid)
{
	struct cli_credentials *creds = mprGetThisPtr(eid, "creds");
	if (creds == NULL) {
		ejsSetErrorMsg(eid, "NULL ejs credentials");
	}
	return creds;
}

/*
  get a domain
*/
static int ejs_creds_get_domain(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct cli_credentials *creds = ejs_creds_get_credentials(eid);

	mpr_Return(eid, mprString(cli_credentials_get_domain(creds)));
	return 0;
}


static int ejs_creds_get_username(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct cli_credentials *creds = ejs_creds_get_credentials(eid);

	mpr_Return(eid, mprString(cli_credentials_get_username(creds)));
	return 0;
}

static int ejs_creds_set_username(MprVarHandle eid, int argc, char **argv)
{
	struct cli_credentials *creds = ejs_creds_get_credentials(eid);
	if (argc != 1) {
		ejsSetErrorMsg(eid, "bad arguments to set_username");
		return -1;
	}

	cli_credentials_set_username(creds, argv[0], CRED_SPECIFIED);
	mpr_Return(eid, mprCreateBoolVar(True));
	return 0;
}


/*
  initialise credentials ejs object
*/
static int ejs_credentials_init(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *obj = mprInitObject(eid, "credentials", argc, argv);
	struct cli_credentials *creds;

	creds = cli_credentials_init(mprMemCtx());
	if (creds == NULL) {
		return -1;
	}

	cli_credentials_guess(creds);
	cli_credentials_set_username(creds, "", CRED_GUESSED);
	cli_credentials_set_password(creds, "", CRED_GUESSED);

	mprSetPtrChild(obj, "creds", creds);

	/* setup our object methods */
	mprSetCFunction(obj, "get_domain", ejs_creds_get_domain);
	mprSetCFunction(obj, "get_username", ejs_creds_get_username);
	mprSetStringCFunction(obj, "set_username", ejs_creds_set_username);

	return 0;
}


/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_credentials(void)
{
	ejsDefineCFunction(-1, "credentials_init", ejs_credentials_init, NULL, MPR_VAR_SCRIPT_HANDLE);
}
