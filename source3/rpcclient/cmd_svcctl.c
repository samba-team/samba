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

void svc_display_query_svc_cfg(const QUERY_SERVICE_CONFIG *cfg)
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
void cmd_svc_info(struct client_info *info, int argc, char *argv[])
{
	uint16 fnum;
	BOOL res = True;
	BOOL res1 = True;
	char *svc_name;

	POLICY_HND pol_scm;
	
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->myhostname);
	strupper(srv_name);

	DEBUG(4,("cmd_svc_info: server:%s\n", srv_name));

	if (argc < 2)
	{
		report(out_hnd,"svcinfo <service name>\n");
		return;
	}

	svc_name = argv[1];

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

static void svc_display_svc_info(const ENUM_SRVC_STATUS *svc)
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
void cmd_svc_enum(struct client_info *info, int argc, char *argv[])
{
	ENUM_SRVC_STATUS *svcs = NULL;
	uint32 num_svcs = 0;
	BOOL request_info = False;
	int opt;

	argc--;
	argv++;

	while ((opt = getopt(argc, argv,"i")) != EOF)
	{
		switch (opt)
		{
			case 'i':
			{
				request_info = True;
				break;
			}
		}
	}

	report(out_hnd,"Services\n");
	report(out_hnd,"--------\n");

	msrpc_svc_enum(info, &svcs, &num_svcs,
	               request_info ? NULL : svc_display_svc_info,
	               request_info ? svc_display_query_svc_cfg : NULL);

	if (svcs != NULL)
	{
		free(svcs);
	}
}

/****************************************************************************
nt stop service 
****************************************************************************/
void cmd_svc_stop(struct client_info *info, int argc, char *argv[])
{
	uint16 fnum;
	BOOL res = True;
	BOOL res1 = True;
	char *svc_name;
	BOOL res2 = True;
	POLICY_HND pol_svc;
	POLICY_HND pol_scm;
	
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->myhostname);
	strupper(srv_name);

	DEBUG(4,("cmd_svc_stop: server:%s\n", srv_name));

	if (argc < 2)
	{
		report(out_hnd,"svcstop <service name>\n");
		return;
	}

	svc_name = argv[1];

	/* open SVCCTL session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SVCCTL, &fnum) : False;

	/* open service control manager receive a policy handle */
	res = res ? svc_open_sc_man(smb_cli, fnum,
	                        srv_name, NULL, 0x80000000,
				&pol_scm) : False;

	res1 = res ? svc_open_service(smb_cli, fnum,
				       &pol_scm,
				       svc_name, 0x00000020,
				       &pol_svc) : False;
	res2 = res1 ? svc_stop_service(smb_cli, fnum, &pol_svc, 0x1) : False;

	res1 = res1 ? svc_close(smb_cli, fnum, &pol_svc) : False;
	res  = res  ? svc_close(smb_cli, fnum, &pol_scm) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res2)
	{
		report(out_hnd,"Stopped Service %s\n", svc_name);
		DEBUG(5,("cmd_svc_stop: succeeded\n"));
	}
	else
		report(out_hnd,"Failed Service Stopped (%s)\n", svc_name);
	{
		DEBUG(5,("cmd_svc_stop: failed\n"));
	}
}

/****************************************************************************
nt start service 
****************************************************************************/
void cmd_svc_start(struct client_info *info, int argc, char *argv[])
{
	uint16 fnum;
	BOOL res = True;
	BOOL res1 = True;
	char *svc_name;
	BOOL res2 = True;
	POLICY_HND pol_svc;
	POLICY_HND pol_scm;
	
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->myhostname);
	strupper(srv_name);

	DEBUG(4,("cmd_svc_start: server:%s\n", srv_name));

	if (argc < 2)
	{
		report(out_hnd,"svcstart <service name> [arg 0] [arg 1]...]\n");
		return;
	}

	argc++;
	argc--;

	svc_name = argv[0];

	argc++;
	argc--;

	/* open SVCCTL session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SVCCTL, &fnum) : False;

	/* open service control manager receive a policy handle */
	res = res ? svc_open_sc_man(smb_cli, fnum,
	                        srv_name, NULL, 0x80000000,
				&pol_scm) : False;

	res1 = res ? svc_open_service(smb_cli, fnum,
				       &pol_scm,
				       svc_name, 0x80000010,
				       &pol_svc) : False;
	res2 = res1 ? svc_start_service(smb_cli, fnum,
				       &pol_svc, argc, argv) : False;

	res1 = res1 ? svc_close(smb_cli, fnum, &pol_svc) : False;
	res  = res  ? svc_close(smb_cli, fnum, &pol_scm) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res2)
	{
		report(out_hnd,"Started Service %s\n", svc_name);
		DEBUG(5,("cmd_svc_start: succeeded\n"));
	}
	else
		report(out_hnd,"Failed Service Startup (%s)\n", svc_name);
	{
		DEBUG(5,("cmd_svc_start: failed\n"));
	}
}

