/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Main SMB server routines
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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
#include "nterr.h"

fstring pipe_name;

pstring servicesf = CONFIGFILE;
extern pstring debugf;
extern BOOL append_log;
extern int DEBUGLEVEL;

/*****************************************************************************
 initialise srv_auth_fns array
 *****************************************************************************/
static void auth_init(rpcsrv_struct * l)
{
}

static void service_init(char *service_name)
{
	add_msrpc_command_processor(pipe_name, service_name, api_ntlsa_rpc);

	if (!pwdb_initialise(True))
	{
		exit(-1);
	}

	if (!secret_init_db())
	{
		exit(-1);
	}
}

/****************************************************************************
  reload the services file
  **************************************************************************/
static void update_trust_account(void)
{
	BOOL trust_pwd_needs_changing = False;
	uint8 old_trust[16];
	NTTIME ntlct;
	BOOL res = True;
	BOOL res1;
	BOOL res2;

	POLICY_HND pol_sec;
	POLICY_HND lsa_pol;
	STRING2 secret;
	UNISTR2 uni_sec_name;
	char *name = "$MACHINE.ACC";
	extern fstring global_myworkgroup;

	make_unistr2(&uni_sec_name, name, strlen(name));

	res =
		res ? _lsa_open_policy2(NULL, &lsa_pol, NULL,
					0x02000000) : False;

	res1 = res ? _lsa_open_secret(&lsa_pol,
				      &uni_sec_name, 0x02000000,
				      &pol_sec) : False;

	res2 =
		res1 ? _lsa_query_secret(&pol_sec, &secret, &ntlct, NULL,
					 NULL) : False;

	res2 = res2 ? secret_get_data(&secret, old_trust, 16) : False;

	if (res2 && time(NULL) >
	    nt_time_to_unix(&ntlct) + lp_machine_password_timeout())
	{
		trust_pwd_needs_changing = True;
	}

	if (trust_pwd_needs_changing)
	{
		unsigned char trust_passwd_hash[16];
		fstring srv_name;

		res2 = res2 ? get_any_dc_name(global_myworkgroup,
					      srv_name) : False;

		generate_random_buffer(trust_passwd_hash, 16, True);
		secret_store_data(&secret, trust_passwd_hash, 16);

		res2 = res2 ? modify_trust_password(global_myworkgroup,
						    srv_name, old_trust,
						    trust_passwd_hash,
						    SEC_CHAN_WKSTA) : False;

		res2 = res2 ? (_lsa_set_secret(&pol_sec, &secret, 0x0) ==
			       NT_STATUS_NOPROBLEMO) : False;
	}

	res1 = res1 ? _lsa_close(&pol_sec) : False;

	res = res ? _lsa_close(&lsa_pol) : False;
}

/****************************************************************************
  reload the services file
  **************************************************************************/
static BOOL reload_msrpc(BOOL test)
{
	BOOL ret;

	update_trust_account();

	if (lp_loaded())
	{
		pstring fname;
		pstrcpy(fname, lp_configfile());
		if (file_exist(fname, NULL) && !strcsequal(fname, servicesf))
		{
			pstrcpy(servicesf, fname);
			test = False;
		}
	}

	reopen_logs();

	if (test && !lp_file_list_changed())
		return (True);

	lp_killunused(NULL);

	ret = lp_load(servicesf, False, False, True);

	/* perhaps the config filename is now set */
	if (!test)
		reload_msrpc(True);

	reopen_logs();

	load_interfaces();

	return (ret);
}

/****************************************************************************
  main program
****************************************************************************/
static int main_init(int argc, char *argv[])
{
#ifdef HAVE_SET_AUTH_PARAMETERS
	set_auth_parameters(argc, argv);
#endif

#ifdef HAVE_SETLUID
	/* needed for SecureWare on SCO */
	setluid(0);
#endif

	append_log = True;

	TimeInit();

	fstrcpy(pipe_name, "lsarpc");
	setup_logging(argv[0], False);
	slprintf(debugf, sizeof(debugf), "%s/log.%s", LOGFILEBASE, pipe_name);

	return 0;
}

static msrpc_service_fns fn_table = {
	auth_init,
	service_init,
	reload_msrpc,
	main_init
};

msrpc_service_fns *get_service_fns(void)
{
	return &fn_table;
}
