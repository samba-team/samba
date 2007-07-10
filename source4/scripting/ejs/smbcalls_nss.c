/* 
   Unix SMB/CIFS implementation.

   provide access to getpwnam() and related calls

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


/*
  return a struct passwd as an object
*/
static struct MprVar mpr_passwd(struct passwd *pwd)
{
	struct MprVar ret;
	if (pwd == NULL) {
		return mprCreateUndefinedVar();
	}
	ret = mprObject("passwd");

	mprSetVar(&ret, "pw_name",   mprString(pwd->pw_name));
	mprSetVar(&ret, "pw_passwd", mprString(pwd->pw_passwd));
	mprSetVar(&ret, "pw_uid",    mprCreateIntegerVar(pwd->pw_uid));
	mprSetVar(&ret, "pw_gid",    mprCreateIntegerVar(pwd->pw_gid));
	mprSetVar(&ret, "pw_gecos",  mprString(pwd->pw_gecos));
	mprSetVar(&ret, "pw_dir",    mprString(pwd->pw_dir));
	mprSetVar(&ret, "pw_shell",  mprString(pwd->pw_shell));
	return ret;
}

/*
  return a struct passwd as an object
*/
static struct MprVar mpr_group(struct group *grp)
{
	struct MprVar ret;
	if (grp == NULL) {
		return mprCreateUndefinedVar();
	}
	ret = mprObject("group");

	mprSetVar(&ret, "gr_name",   mprString(grp->gr_name));
	mprSetVar(&ret, "gr_passwd", mprString(grp->gr_passwd));
	mprSetVar(&ret, "gr_gid",    mprCreateIntegerVar(grp->gr_gid));
	mprSetVar(&ret, "gr_mem",    mprList("gr_mem", (const char **)grp->gr_mem));
	return ret;
}


/*
  usage:
      var pw = nss.getpwnam("root");

  returns an object containing struct passwd entries
*/
static int ejs_getpwnam(MprVarHandle eid, int argc, struct MprVar **argv)
{
	/* validate arguments */
	if (argc != 1 || argv[0]->type != MPR_TYPE_STRING) {
		ejsSetErrorMsg(eid, "getpwnam invalid arguments");
		return -1;
	}

	mpr_Return(eid, mpr_passwd(getpwnam(mprToString(argv[0]))));
	return 0;
}

/*
  usage:
      var pw = nss.getpwuid(0);

  returns an object containing struct passwd entries
*/
static int ejs_getpwuid(MprVarHandle eid, int argc, struct MprVar **argv)
{
	/* validate arguments */
	if (argc != 1 || !mprVarIsNumber(argv[0]->type)) {
		ejsSetErrorMsg(eid, "getpwuid invalid arguments");
		return -1;
	}
	mpr_Return(eid, mpr_passwd(getpwuid(mprToInt(argv[0]))));
	return 0;
}

/*
  usage:
      var pw = nss.getgrnam("users");

  returns an object containing struct group entries
*/
static int ejs_getgrnam(MprVarHandle eid, int argc, struct MprVar **argv)
{
	/* validate arguments */
	if (argc != 1 || argv[0]->type != MPR_TYPE_STRING) {
		ejsSetErrorMsg(eid, "getgrnam invalid arguments");
		return -1;
	}
	mpr_Return(eid, mpr_group(getgrnam(mprToString(argv[0]))));
	return 0;
}

/*
  usage:
      var pw = nss.getgrgid(0);

  returns an object containing struct group entries
*/
static int ejs_getgrgid(MprVarHandle eid, int argc, struct MprVar **argv)
{
	/* validate arguments */
	if (argc != 1 || argv[0]->type != MPR_TYPE_STRING) {
		ejsSetErrorMsg(eid, "getgrgid invalid arguments");
		return -1;
	}
	mpr_Return(eid, mpr_group(getgrgid(mprToInt(argv[0]))));
	return 0;
}


/*
  initialise nss ejs subsystem
*/
static int ejs_nss_init(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *nss = mprInitObject(eid, "nss", argc, argv);

	mprSetCFunction(nss, "getpwnam", ejs_getpwnam);
	mprSetCFunction(nss, "getpwuid", ejs_getpwuid);
	mprSetCFunction(nss, "getgrnam", ejs_getgrnam);
	mprSetCFunction(nss, "getgrgid", ejs_getgrgid);

	return 0;
}

/*
  setup C functions that be called from ejs
*/
NTSTATUS smb_setup_ejs_nss(void)
{
	ejsDefineCFunction(-1, "nss_init", ejs_nss_init, NULL, MPR_VAR_SCRIPT_HANDLE);
	return NT_STATUS_OK;
}
