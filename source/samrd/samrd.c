/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Main SMB server routines
   Copyright (C) Andrew Tridgell 1992-1998
   
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

fstring pipe_name;

pstring servicesf = CONFIGFILE;
extern pstring debugf;
extern BOOL append_log;
extern int DEBUGLEVEL;

/*****************************************************************************
 initialise srv_auth_fns array
 *****************************************************************************/
void msrpc_auth_init(rpcsrv_struct *l)
{
	extern srv_auth_fns ntlmssp_fns;
	add_srv_auth_fn(l, &ntlmssp_fns);
}

/*************************************************************************
 initialise an msrpc service
 *************************************************************************/
void msrpc_service_init(char* service_name)
{
	DEBUG(10,("msrpc_service_init\n"));

	add_msrpc_command_processor( pipe_name, service_name, api_samr_rpc );

	if (!pwdb_initialise(True) || !initialise_password_db())
	{
		exit(-1);
	}

	if(!initialise_sam_password_db())
	{
		exit(-1);
	}

	if(!initialise_passgrp_db())
	{
		exit(-1);
	}

	if(!initialise_group_db())
	{
		exit(-1);
	}

	if(!initialise_alias_db())
	{
		exit(-1);
	}

	if(!initialise_builtin_db())
	{
		exit(-1);
	}
}

/****************************************************************************
  reload the services file
  **************************************************************************/
BOOL reload_services(BOOL test)
{
	BOOL ret;

	if (lp_loaded()) {
		pstring fname;
		pstrcpy(fname,lp_configfile());
		if (file_exist(fname,NULL) && !strcsequal(fname,servicesf)) {
			pstrcpy(servicesf,fname);
			test = False;
		}
	}

	reopen_logs();

	if (test && !lp_file_list_changed())
		return(True);

	lp_killunused(NULL);

	ret = lp_load(servicesf,False,False,True);

	/* perhaps the config filename is now set */
	if (!test)
		reload_services(True);

	reopen_logs();

	load_interfaces();

	return(ret);
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
#ifdef HAVE_SET_AUTH_PARAMETERS
	set_auth_parameters(argc,argv);
#endif

#ifdef HAVE_SETLUID
	/* needed for SecureWare on SCO */
	setluid(0);
#endif

	append_log = True;

	TimeInit();

	setup_logging(argv[0],False);
	fstrcpy(pipe_name, "samr");
	slprintf(debugf, sizeof(debugf), "%s/log.%s", LOGFILEBASE, pipe_name);

	return msrpc_main(argc, argv);
}
