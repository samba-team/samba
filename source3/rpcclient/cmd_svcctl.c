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

void svc_display_query_svc_cfg(QUERY_SERVICE_CONFIG *cfg)
{
	display_query_svc_cfg(out_hnd, ACTION_HEADER   , cfg);
	display_query_svc_cfg(out_hnd, ACTION_ENUMERATE, cfg);
	display_query_svc_cfg(out_hnd, ACTION_FOOTER   , cfg);
}

BOOL svc_query_service(struct cli_state *cli, uint16 fnum,
				POLICY_HND *pol_scm,
				const char *svc_name,
				SVC_QUERY_FN(svc_query_fn))
{
	BOOL res2 = True;
	BOOL res3;
	POLICY_HND pol_svc;
	QUERY_SERVICE_CONFIG cfg;
	uint32 svc_buf_size = 0x8000;

	res2 = res2 ? svc_open_service(cli, fnum,
				       pol_scm,
				       svc_name, 0x80000001,
				       &pol_svc) : False;
	res3 = res2 ? svc_query_svc_cfg(cli, fnum,
				       &pol_svc, &cfg,
				       &svc_buf_size) : False;

	if (res3 && svc_query_fn != NULL)
	{
		svc_query_fn(&cfg);
	}

	res2 = res2 ? svc_close(cli, fnum, &pol_svc) : False;

	return res3;
}

/****************************************************************************
nt service info
****************************************************************************/
void cmd_svc_info(struct client_info *info)
{
	uint16 fnum;
	BOOL res = True;
	BOOL res1 = True;
	fstring svc_name;

	POLICY_HND pol_scm;
	
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->myhostname);
	strupper(srv_name);

	DEBUG(4,("cmd_svc_info: server:%s\n", srv_name));

	if (!next_token(NULL, svc_name, NULL, sizeof(svc_name)))
	{
		report(out_hnd,"svcinfo <service name>\n");
		return;
	}

	/* open SVCCTL session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SVCCTL, &fnum) : False;

	/* open service control manager receive a policy handle */
	res = res ? svc_open_sc_man(smb_cli, fnum,
	                        srv_name, NULL, 0x80000004,
				&pol_scm) : False;

	res1 = svc_query_service(smb_cli, fnum, &pol_scm, svc_name,
				svc_display_query_svc_cfg);

	res = res ? svc_close(smb_cli, fnum, &pol_scm) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res && res1)
	{
		DEBUG(5,("cmd_svc_info: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_svc_info: query failed\n"));
	}
}

static void svc_display_svc_info(ENUM_SRVC_STATUS *svc)
{
	display_svc_info(out_hnd, ACTION_HEADER   , svc);
	display_svc_info(out_hnd, ACTION_ENUMERATE, svc);
	display_svc_info(out_hnd, ACTION_FOOTER   , svc);
}

/****************************************************************************
nt service enum
****************************************************************************/
BOOL msrpc_svc_enum(struct client_info *info,
				ENUM_SRVC_STATUS **svcs,
				uint32 *num_svcs,
				SVC_INFO_FN(info_fn),
				SVC_QUERY_FN(query_fn))
{
	uint16 fnum;
	BOOL res = True;
	BOOL res1 = False;
	int i;
	uint32 resume_hnd = 0;
	uint32 buf_size = 0;
	uint32 dos_error = 0;

	POLICY_HND pol_scm;
	
	fstring srv_name;

	(*svcs) = NULL;
	(*num_svcs) = 0;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->myhostname);
	strupper(srv_name);

	/* open SVCCTL session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SVCCTL, &fnum) : False;

	/* open service control manager receive a policy handle */
	res = res ? svc_open_sc_man(smb_cli, fnum,
	                        srv_name, NULL, 0x80000004,
				&pol_scm) : False;

	do
	{
		if ((*svcs) != NULL)
		{
			free(*svcs);
			(*svcs) = NULL;
			(*num_svcs) = 0;
		}

		buf_size += 0x800;

		/* enumerate services */
		res1 = res ? svc_enum_svcs(smb_cli, fnum,
		                        &pol_scm,
		                        0x00000030, 0x00000003,
		                        &buf_size, &resume_hnd, &dos_error,
		                        svcs, num_svcs) : False;

	} while (res1 && dos_error == ERRmoredata);

	if (res1 && dos_error == 0x0 && (*num_svcs) > 0 && (*svcs) != NULL)
	{
		report(out_hnd,"Services\n");
		report(out_hnd,"--------\n");
	}

	for (i = 0; i < (*num_svcs) && (*svcs) != NULL && res1; i++)
	{
		fstring svc_name;

		unistr_to_ascii(svc_name, (*svcs)[i].uni_srvc_name.buffer,
				sizeof(svc_name)-1);

		if (query_fn != NULL)
		{
			res1 = svc_query_service(smb_cli, fnum, &pol_scm,
			                         svc_name, query_fn);
		}
		else if (info_fn != NULL)
		{
			info_fn(&(*svcs)[i]);
		}
	}

	res = res ? svc_close(smb_cli, fnum, &pol_scm) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	return res1;
}

/****************************************************************************
nt service enum
****************************************************************************/
void cmd_svc_enum(struct client_info *info)
{
	ENUM_SRVC_STATUS *svcs = NULL;
	uint32 num_svcs = 0;
	fstring tmp;
	BOOL request_info = False;

	if (next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		request_info = strequal(tmp, "-i");
	}

	msrpc_svc_enum(info, &svcs, &num_svcs,
	               request_info ? NULL : svc_display_svc_info,
	               request_info ? svc_display_query_svc_cfg : NULL);

	if (svcs != NULL)
	{
		free(svcs);
	}
}

