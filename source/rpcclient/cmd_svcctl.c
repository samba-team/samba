/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   
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

extern struct cli_state *smb_cli;
extern int smb_tidx;

extern FILE* out_hnd;

/****************************************************************************
nt svcistry enum
****************************************************************************/
void cmd_svc_enum(struct client_info *info)
{
	uint16 fnum;
	BOOL res = True;
	BOOL res1 = True;
	int i;
	uint32 resume_hnd = 0;
	ENUM_SRVC_STATUS *svcs = NULL;

	POLICY_HND sc_man_pol;
	fstring full_keyname;
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->myhostname);
	strupper(srv_name);

	DEBUG(4,("cmd_svc_enum: server:%s\n", srv_name));

	/* open SVCCTL session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SVCCTL, &fnum) : False;

	/* open service control manager receive a policy handle */
	res = res ? do_svc_open_sc_man(smb_cli, fnum,
	                        srv_name, NULL, 0x80000004,
				&sc_man_pol) : False;

	do
	{
		/* enumerate services */
		res1 = res ? do_svc_enum_svcs(smb_cli, fnum,
		                        &sc_man_pol,
		                        0x00000030, 0x00000003,
		                        0x00000080, &resume_hnd, &svcs) : False;

	} while (resume_hnd != 0);

	if (svcs != NULL)
	{
		free(svcs);
	}

#if 0
	if (res1 && num_subkeys > 0)
	{
		fprintf(out_hnd,"Subkeys\n");
		fprintf(out_hnd,"-------\n");
	}

	for (i = 0; i < num_subkeys; i++)
	{
		BOOL res2 = True;
		/*
		 * enumerate key
		 */

		/* enum key */
		res2 = res2 ? do_svc_enum_key(smb_cli, fnum, &key_pol,
					i, enum_name,
					&enum_unk1, &enum_unk2,
					&key_mod_time) : False;
		
		if (res2)
		{
			display_svc_key_info(out_hnd, ACTION_HEADER   , enum_name, key_mod_time);
			display_svc_key_info(out_hnd, ACTION_ENUMERATE, enum_name, key_mod_time);
			display_svc_key_info(out_hnd, ACTION_FOOTER   , enum_name, key_mod_time);
		}

	}

	}
#endif
	res  = res  ? do_svc_close(smb_cli, fnum, &sc_man_pol) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res && res1)
	{
		DEBUG(5,("cmd_svc_enum: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_svc_enum: query failed\n"));
	}
}

