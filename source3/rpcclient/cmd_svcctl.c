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
	uint32 buf_size = 0;
	uint32 dos_error = 0;
	ENUM_SRVC_STATUS *svcs = NULL;
	uint32 num_svcs = 0;

	POLICY_HND sc_man_pol;
	
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
		buf_size += 0x800;

		/* enumerate services */
		res1 = res ? do_svc_enum_svcs(smb_cli, fnum,
		                        &sc_man_pol,
		                        0x00000030, 0x00000003,
		                        &buf_size, &resume_hnd, &dos_error,
		                        &svcs, &num_svcs) : False;

	} while (dos_error == ERRmoredata);

	if (res1 && dos_error == 0x0 && num_svcs > 0 && svcs != NULL)
	{
		fprintf(out_hnd,"Services\n");
		fprintf(out_hnd,"--------\n");
	}

	for (i = 0; i < num_svcs && svcs != NULL; i++)
	{
		if (res1)
		{
			display_svc_info(out_hnd, ACTION_HEADER   , &svcs[i]);
			display_svc_info(out_hnd, ACTION_ENUMERATE, &svcs[i]);
			display_svc_info(out_hnd, ACTION_FOOTER   , &svcs[i]);
		}
	}

	if (svcs != NULL)
	{
		free(svcs);
	}

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

