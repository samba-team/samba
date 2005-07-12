/* 
   Unix SMB/CIFS implementation.

   provide access to system functions

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

/*
  return the list of configured network interfaces
*/
static int ejs_sys_interfaces(MprVarHandle eid, int argc, struct MprVar **argv)
{
	int i, count = iface_count();
	struct MprVar ret = mprObject("interfaces");
	for (i=0;i<count;i++) {
		mprAddArray(&ret, i, mprString(iface_n_ip(i)));
	}
	mpr_Return(eid, ret);
	return 0;	
}

/*
  return the hostname from gethostname()
*/
static int ejs_sys_hostname(MprVarHandle eid, int argc, struct MprVar **argv)
{
	char name[200];
	if (gethostname(name, sizeof(name)-1) == -1) {
		ejsSetErrorMsg(eid, "gethostname failed - %s", strerror(errno));
		return -1;
	}
	mpr_Return(eid, mprString(name));
	return 0;	
}


/*
  return current time as a 64 bit nttime value
*/
static int ejs_sys_nttime(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct timeval tv = timeval_current();
	struct MprVar v = mprCreateNumberVar(timeval_to_nttime(&tv));
	mpr_Return(eid, v);
	return 0;
}

/*
  return a ldap time string from a nttime
*/
static int ejs_sys_ldaptime(MprVarHandle eid, int argc, struct MprVar **argv)
{
	char *s;
	time_t t;
	if (argc != 1 || !mprVarIsNumber(argv[0]->type)) {
		ejsSetErrorMsg(eid, "sys_ldaptime invalid arguments");
		return -1;
	}
	t = nt_time_to_unix(mprVarToNumber(argv[0]));
	s = ldap_timestring(mprMemCtx(), t);
	mpr_Return(eid, mprString(s));
	talloc_free(s);
	return 0;
}


/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_system(void)
{
	ejsDefineCFunction(-1, "sys_interfaces", ejs_sys_interfaces, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "sys_hostname", ejs_sys_hostname, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "sys_nttime", ejs_sys_nttime, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "sys_ldaptime", ejs_sys_ldaptime, NULL, MPR_VAR_SCRIPT_HANDLE);
}
