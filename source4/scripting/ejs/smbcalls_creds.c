/* 
   Unix SMB/CIFS implementation.

   provide hooks credentials calls

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
#include "lib/cmdline/popt_common.h"
#include "auth/credentials/credentials.h"

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


/*
  set a domain
*/
static int ejs_creds_set_domain(MprVarHandle eid, int argc, char **argv)
{
	struct cli_credentials *creds = ejs_creds_get_credentials(eid);
	if (argc != 1) {
		ejsSetErrorMsg(eid, "bad arguments to set_domain");
		return -1;
	}

	cli_credentials_set_domain(creds, argv[0], CRED_SPECIFIED);
	mpr_Return(eid, mprCreateBoolVar(True));
	return 0;
}


/*
  get a username
*/
static int ejs_creds_get_username(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct cli_credentials *creds = ejs_creds_get_credentials(eid);

	mpr_Return(eid, mprString(cli_credentials_get_username(creds)));
	return 0;
}


/*
  set a username
*/
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
  get user password
*/
static int ejs_creds_get_password(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct cli_credentials *creds = ejs_creds_get_credentials(eid);
	
	mpr_Return(eid, mprString(cli_credentials_get_password(creds)));
	return 0;
}


/*
  set user password
*/
static int ejs_creds_set_password(MprVarHandle eid, int argc, char **argv)
{
	struct cli_credentials *creds = ejs_creds_get_credentials(eid);
	if (argc != 1) {
		ejsSetErrorMsg(eid, "bad arguments to set_password");
		return -1;
	}

	cli_credentials_set_password(creds, argv[0], CRED_SPECIFIED);
	mpr_Return(eid, mprCreateBoolVar(True));
	return 0;
}


/*
  set realm
*/
static int ejs_creds_set_realm(MprVarHandle eid, int argc, char **argv)
{
	struct cli_credentials *creds = ejs_creds_get_credentials(eid);
	if (argc != 1) {
		ejsSetErrorMsg(eid, "bad arguments to set_realm");
		return -1;
	}

	cli_credentials_set_realm(creds, argv[0], CRED_SPECIFIED);
	mpr_Return(eid, mprCreateBoolVar(True));
	return 0;
}


/*
  get realm
*/
static int ejs_creds_get_realm(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct cli_credentials *creds = ejs_creds_get_credentials(eid);
	
	mpr_Return(eid, mprString(cli_credentials_get_realm(creds)));
	return 0;
}


/*
  set workstation
*/
static int ejs_creds_set_workstation(MprVarHandle eid, int argc, char **argv)
{
	struct cli_credentials *creds = ejs_creds_get_credentials(eid);
	if (argc != 1) {
		ejsSetErrorMsg(eid, "bad arguments to set_workstation");
		return -1;
	}
	
	cli_credentials_set_workstation(creds, argv[0], CRED_SPECIFIED);
	mpr_Return(eid, mprCreateBoolVar(True));
	return 0;
}


/*
  get workstation
*/
static int ejs_creds_get_workstation(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct cli_credentials *creds = ejs_creds_get_credentials(eid);
	
	mpr_Return(eid, mprString(cli_credentials_get_workstation(creds)));
	return 0;
}

/*
  set machine account 
*/
static int ejs_creds_set_machine_account(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct cli_credentials *creds = ejs_creds_get_credentials(eid);
	if (argc != 0) {
		ejsSetErrorMsg(eid, "bad arguments to set_machine_account");
		return -1;
	}
	
	if (NT_STATUS_IS_OK(cli_credentials_set_machine_account(creds))) {
		mpr_Return(eid, mprCreateBoolVar(True));
	} else {
		mpr_Return(eid, mprCreateBoolVar(False));
	}
	return 0;
}


/*
  initialise credentials ejs object
*/
static int ejs_credentials_obj(struct MprVar *obj, struct cli_credentials *creds)
{
	mprSetPtrChild(obj, "creds", creds);

	/* setup our object methods */
	mprSetCFunction(obj, "get_domain", ejs_creds_get_domain);
	mprSetStringCFunction(obj, "set_domain", ejs_creds_set_domain);
	mprSetCFunction(obj, "get_username", ejs_creds_get_username);
	mprSetStringCFunction(obj, "set_username", ejs_creds_set_username);
	mprSetCFunction(obj, "get_password", ejs_creds_get_password);
	mprSetStringCFunction(obj, "set_password", ejs_creds_set_password);
	mprSetCFunction(obj, "get_realm", ejs_creds_get_realm);
	mprSetStringCFunction(obj, "set_realm", ejs_creds_set_realm);
	mprSetCFunction(obj, "get_workstation", ejs_creds_get_workstation);
	mprSetStringCFunction(obj, "set_workstation", ejs_creds_set_workstation);
	mprSetCFunction(obj, "set_machine_account", ejs_creds_set_machine_account);

	return 0;
}


struct MprVar mprCredentials(struct cli_credentials *creds)
{
	struct MprVar mpv = mprObject("credentials");

	ejs_credentials_obj(&mpv, creds);
	
	return mpv;
}


/*
  initialise credentials ejs object
*/
static int ejs_credentials_init(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct cli_credentials *creds;
	struct MprVar *obj = mprInitObject(eid, "credentials", argc, argv);

	creds = cli_credentials_init(mprMemCtx());
	if (creds == NULL) {
		return -1;
	}

	cli_credentials_set_conf(creds);

	return ejs_credentials_obj(obj, creds);
}

/*
  initialise cmdline credentials ejs object
*/
int ejs_credentials_cmdline(int eid, int argc, struct MprVar **argv)
{
	struct MprVar *obj = mprInitObject(eid, "credentials", argc, argv);
	if (talloc_reference(mprMemCtx(), cmdline_credentials) == NULL) {
		return -1;
	}
	return ejs_credentials_obj(obj, cmdline_credentials);
}

/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_credentials(void)
{
	ejsDefineCFunction(-1, "credentials_init", ejs_credentials_init, NULL, MPR_VAR_SCRIPT_HANDLE);
}

