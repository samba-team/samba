/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   PAM for NT Domains
   Copyright (C) Andrew Tridgell              1994-2000
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
#include "rpc_validate.h"
#include "nterr.h"

extern int DEBUGLEVEL;

static BOOL initialised = False;

extern pstring global_myname;

FILE *out_hnd;


/****************************************************************************
  main program
****************************************************************************/
BOOL rpc_initialise(void)
{
	extern pstring debugf;
	extern BOOL append_log;

	pstring servicesf = CONFIGFILE;
	mode_t myumask = 0755;

	if (initialised)
	{
		return True;
	}

	DEBUGLEVEL = 100;

	out_hnd = stdout;

	append_log = True;
	slprintf(debugf, sizeof(debugf) - 1, "%s/log.pam_ntdom", LOGFILEBASE);

	TimeInit();
	charset_initialise();
	init_connections();

	myumask = umask(0);
	umask(myumask);

	if (!get_myname(global_myname, NULL))
	{
		fprintf(stderr, "Failed to get my hostname.\n");
		return False;
	}

	codepage_initialise(lp_client_code_page());

	setup_logging(debugf, False);
	reopen_logs();

	if (!lp_load(servicesf, True, False, False))
	{
		fprintf(stderr,
			"Can't load %s - run testparm to debug it\n",
			servicesf);
		return False;
	}

	load_interfaces();

	if (!pwdb_initialise(False))
	{
		return False;
	}

	initialised = True;

	return True;
}

/****************************************************************************
 validates a user.
 ****************************************************************************/
int Valid_User(char *username, char *plaintext_pwd, char *domainname)
{
	NET_USER_INFO_3 info3;
	uchar ntpw[16];
	uchar lmpw[16];

	uint32 status;

	ZERO_STRUCT(info3);

	DEBUG(3, ("%s pam_ntdom (version %s) login.  user:%s domain:%s\n",
		  timestring(False), VERSION, username, domainname));

	nt_lm_owf_gen(plaintext_pwd, ntpw, lmpw),
		status = domain_client_validate("\\\\.", username, domainname,
						global_myname, SEC_CHAN_WKSTA,
						NULL,
						lmpw, sizeof(lmpw),
						ntpw, sizeof(ntpw), &info3);

	if (status != NT_STATUS_NOPROBLEMO)
	{
		fprintf(stderr, "login of %s to domain %s rejected.\n",
			username, domainname);
		return NTV_LOGON_ERROR;
	}

	return NTV_NO_ERROR;
}
