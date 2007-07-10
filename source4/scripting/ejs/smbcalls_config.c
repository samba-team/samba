/* 
   Unix SMB/CIFS implementation.

   provide hooks into smbd C calls from ejs scripts

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
#include "param/loadparm.h"
#include "system/network.h"
#include "lib/socket/netif.h"

/*
  return a list of defined services
*/
static int ejs_lpServices(MprVarHandle eid, int argc, char **argv)
{
	int i;
	const char **list = NULL;
	if (argc != 0) return -1;
	
	for (i=0;i<lp_numservices();i++) {
		list = str_list_add(list, lp_servicename(i));
	}
	talloc_steal(mprMemCtx(), list);
	mpr_Return(eid, mprList("services", list));
	return 0;
}


/*
  return a list of parameter categories
*/
static int ejs_lpCategories(MprVarHandle eid, int argc, char **argv)
{
	struct parm_struct *parm_table = lp_parm_table();
	int i;
	const char **list = NULL;
	if (argc != 0) return -1;
	
	for (i=0;parm_table[i].label;i++) {
		if (parm_table[i].class == P_SEPARATOR) {
			list = str_list_add(list, parm_table[i].label);
		}
	}
	talloc_steal(mprMemCtx(), list);
	mpr_Return(eid, mprList("categories", list));
	return 0;
}


/*
  allow access to loadparm variables from inside ejs scripts in web apps
  
  can be called in 4 ways:

    v = lp.get("type:parm");             gets a parametric variable
    v = lp.get("share", "type:parm");    gets a parametric variable on a share
    v = lp.get("parm");                  gets a global variable
    v = lp.get("share", "parm");         gets a share variable

  the returned variable is a ejs object. It is an array object for lists.  
*/
static int ejs_lpGet(MprVarHandle eid, int argc, char **argv)
{
	struct parm_struct *parm = NULL;
	void *parm_ptr = NULL;
	int i;

	if (argc < 1) return -1;

	if (argc == 2) {
		/* its a share parameter */
		int snum = lp_servicenumber(argv[0]);
		if (snum == -1) {
			return -1;
		}
		if (strchr(argv[1], ':')) {
			/* its a parametric option on a share */
			const char *type = talloc_strndup(mprMemCtx(), 
							  argv[1], 
							  strcspn(argv[1], ":"));
			const char *option = strchr(argv[1], ':') + 1;
			const char *value;
			if (type == NULL || option == NULL) return -1;
			value = lp_get_parametric(snum, type, option);
			if (value == NULL) return -1;
			mpr_ReturnString(eid, value);
			return 0;
		}

		parm = lp_parm_struct(argv[1]);
		if (parm == NULL || parm->class == P_GLOBAL) {
			return -1;
		}
		parm_ptr = lp_parm_ptr(snum, parm);
	} else if (strchr(argv[0], ':')) {
		/* its a global parametric option */
		const char *type = talloc_strndup(mprMemCtx(), 
						  argv[0], strcspn(argv[0], ":"));
		const char *option = strchr(argv[0], ':') + 1;
		const char *value;
		if (type == NULL || option == NULL) return -1;
		value = lp_get_parametric(-1, type, option);
		if (value == NULL) return -1;
		mpr_ReturnString(eid, value);
		return 0;
	} else {
		/* its a global parameter */
		parm = lp_parm_struct(argv[0]);
		if (parm == NULL) return -1;
		parm_ptr = lp_parm_ptr(-1, parm);
	}

	if (parm == NULL || parm_ptr == NULL) {
		return -1;
	}

	/* construct and return the right type of ejs object */
	switch (parm->type) {
	case P_STRING:
	case P_USTRING:
		mpr_ReturnString(eid, *(char **)parm_ptr);
		break;
	case P_BOOL:
		mpr_Return(eid, mprCreateBoolVar(*(BOOL *)parm_ptr));
		break;
	case P_INTEGER:
	case P_BYTES:
		mpr_Return(eid, mprCreateIntegerVar(*(int *)parm_ptr));
		break;
	case P_ENUM:
		for (i=0; parm->enum_list[i].name; i++) {
			if (*(int *)parm_ptr == parm->enum_list[i].value) {
				mpr_ReturnString(eid, parm->enum_list[i].name);
				return 0;
			}
		}
		return -1;	
	case P_LIST: 
		mpr_Return(eid, mprList(parm->label, *(const char ***)parm_ptr));
		break;
	case P_SEP:
		return -1;
	}
	return 0;
}


/*
  set a smb.conf parameter. Only sets in memory, not permanent
  
  can be called in 4 ways:

    ok = lp.set("parm", "value");
*/
static int ejs_lpSet(MprVarHandle eid, int argc, char **argv)
{
	if (argc != 2) {
		ejsSetErrorMsg(eid, "lp.set invalid arguments");
		return -1;
	}

	mpr_Return(eid, mprCreateBoolVar(lp_set_cmdline(argv[0], argv[1])));
	return 0;
}

/*
  reload smb.conf
  
    ok = lp.reload();
*/
static int ejs_lpReload(MprVarHandle eid, int argc, char **argv)
{
	BOOL ret = lp_load();
	if (ret) {
		unload_interfaces();
	}
	mpr_Return(eid, mprCreateBoolVar(ret));
	return 0;
}

/*
  initialise loadparm ejs subsystem
*/
static int ejs_loadparm_init(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *obj = mprInitObject(eid, "loadparm", argc, argv);

	mprSetStringCFunction(obj, "get", ejs_lpGet);
	mprSetStringCFunction(obj, "set", ejs_lpSet);
	mprSetStringCFunction(obj, "reload", ejs_lpReload);
	mprSetStringCFunction(obj, "services", ejs_lpServices);
	mprSetStringCFunction(obj, "categories", ejs_lpCategories);
	return 0;
}

/*
  setup C functions that be called from ejs
*/
NTSTATUS smb_setup_ejs_config(void)
{
	ejsDefineCFunction(-1, "loadparm_init", ejs_loadparm_init, NULL, MPR_VAR_SCRIPT_HANDLE);
	return NT_STATUS_OK;
}
