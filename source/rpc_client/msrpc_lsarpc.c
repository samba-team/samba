/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

/****************************************************************************
nt lsa query secret
****************************************************************************/
BOOL msrpc_lsa_query_secret(struct cli_state *cli,
				const char* secret_name,
				STRING2 *secret,
				NTTIME *last_update)
{
	uint16 nt_pipe_fnum;
	fstring srv_name;
	BOOL res = True;
	BOOL res1;
	BOOL res2;

	POLICY_HND pol_sec;
	POLICY_HND lsa_pol;
	STRING2 enc_secret;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, cli->desthost);
	strupper(srv_name);

	/* open LSARPC session. */
	res = res ? cli_nt_session_open(cli, PIPE_LSARPC, &nt_pipe_fnum) : False;

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy2(cli, nt_pipe_fnum,
				srv_name,
				&lsa_pol, False) : False;

	/* lookup domain controller; receive a policy handle */
	res1 = res ? lsa_open_secret(cli, nt_pipe_fnum,
				&lsa_pol,
				secret_name, 0x02000000, &pol_sec) : False;

	res2 = res1 ? lsa_query_secret(cli, nt_pipe_fnum,
			       &pol_sec, &enc_secret, last_update) : False;

	res1 = res1 ? lsa_close(cli, nt_pipe_fnum, &pol_sec) : False;

	res = res ? lsa_close(cli, nt_pipe_fnum, &lsa_pol) : False;

	/* close the session */
	cli_nt_session_close(cli, nt_pipe_fnum);

	res2 = res2 ? nt_decrypt_string2(secret, &enc_secret, (char*)(cli->pwd.smb_nt_pwd)) : False;

	return res2;
}
