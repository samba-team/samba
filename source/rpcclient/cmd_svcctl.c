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

#include "includes.h"
#include "rpc_client.h"
#include "rpcclient.h"
#include "nterr.h"

extern int DEBUGLEVEL;

extern FILE* out_hnd;

void svc_display_query_svc_cfg(const QUERY_SERVICE_CONFIG *cfg)
{
	display_query_svc_cfg(out_hnd, ACTION_HEADER   , cfg);
	display_query_svc_cfg(out_hnd, ACTION_ENUMERATE, cfg);
	display_query_svc_cfg(out_hnd, ACTION_FOOTER   , cfg);
}

BOOL svc_query_service( POLICY_HND *pol_scm,
				const char *svc_name,
				SVC_QUERY_FN(svc_query_fn))
{
	BOOL res2 = True;
	BOOL res3;
	POLICY_HND pol_svc;
	QUERY_SERVICE_CONFIG cfg;
	uint32 svc_buf_size = 0x8000;

	res2 = res2 ? svc_open_service( pol_scm,
				       svc_name, 0x80000001,
				       &pol_svc) : False;
	res3 = res2 ? svc_query_svc_cfg( &pol_svc, &cfg,
				       &svc_buf_size) : False;

	if (res3 && svc_query_fn != NULL)
	{
		svc_query_fn(&cfg);
	}

	res2 = res2 ? svc_close(&pol_svc) : False;

	return res3;
}

/****************************************************************************
nt service info
****************************************************************************/
void cmd_svc_info(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;
	BOOL res1 = True;
	char *svc_name;

	POLICY_HND pol_scm;
	
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	DEBUG(4,("cmd_svc_info: server:%s\n", srv_name));

	if (argc < 2)
	{
		report(out_hnd,"svcinfo <service name>\n");
		return;
	}

	svc_name = argv[1];

	/* open service control manager receive a policy handle */
	res = res ? svc_open_sc_man( srv_name, NULL, 0x80000004,
				&pol_scm) : False;

	res1 = svc_query_service(&pol_scm, svc_name,
				svc_display_query_svc_cfg);

	res = res ? svc_close(&pol_scm) : False;

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
BOOL msrpc_svc_enum(const char* srv_name,
				ENUM_SRVC_STATUS **svcs,
				uint32 *num_svcs,
				SVC_INFO_FN(info_fn),
				SVC_QUERY_FN(query_fn))
{
	BOOL res = True;
	BOOL res1 = False;
	int i;
	uint32 resume_hnd = 0;
	uint32 buf_size = 0;
	uint32 dos_error = 0;

	POLICY_HND pol_scm;
	
	(*svcs) = NULL;
	(*num_svcs) = 0;

	/* open service control manager receive a policy handle */
	res = res ? svc_open_sc_man( srv_name, NULL, 0x80000004,
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
		res1 = res ? svc_enum_svcs( &pol_scm,
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
			res1 = svc_query_service(&pol_scm,
			                         svc_name, query_fn);
		}
		else if (info_fn != NULL)
		{
			info_fn(&(*svcs)[i]);
		}
	}

	res = res ? svc_close(&pol_scm) : False;

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
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

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

	msrpc_svc_enum(srv_name, &svcs, &num_svcs,
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
	BOOL res = True;
	BOOL res1 = True;
	char *svc_name;
	BOOL res2 = True;
	POLICY_HND pol_svc;
	POLICY_HND pol_scm;
	
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	DEBUG(4,("cmd_svc_stop: server:%s\n", srv_name));

	if (argc < 2)
	{
		report(out_hnd,"svcstop <service name>\n");
		return;
	}

	svc_name = argv[1];

	/* open service control manager receive a policy handle */
	res = res ? svc_open_sc_man( srv_name, NULL, 0x80000000,
				&pol_scm) : False;

	res1 = res ? svc_open_service( &pol_scm,
				       svc_name, 0x00000020,
				       &pol_svc) : False;
	res2 = res1 ? svc_stop_service(&pol_svc, 0x1) : False;

	res1 = res1 ? svc_close(&pol_svc) : False;
	res  = res  ? svc_close(&pol_scm) : False;

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
	BOOL res = True;
	BOOL res1 = True;
	char *svc_name;
	BOOL res2 = True;
	POLICY_HND pol_svc;
	POLICY_HND pol_scm;
	
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	DEBUG(4,("cmd_svc_start: server:%s\n", srv_name));

	if (argc < 2)
	{
		report(out_hnd,"svcstart <service name> [arg 0] [arg 1]...]\n");
		return;
	}

	argv++;
	argc--;

	svc_name = argv[0];

	argv++;
	argc--;

	/* open service control manager receive a policy handle */
	res = res ? svc_open_sc_man( srv_name, NULL, 0x80000000,
				&pol_scm) : False;

	res1 = res ? svc_open_service( &pol_scm,
				       svc_name, 0x80000010,
				       &pol_svc) : False;
	res2 = res1 ? svc_start_service( &pol_svc, argc, argv) : False;

	res1 = res1 ? svc_close(&pol_svc) : False;
	res  = res  ? svc_close(&pol_scm) : False;

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

/****************************************************************************
nt service set
****************************************************************************/
void cmd_svc_set(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;
	BOOL res2 = True;
	BOOL res3;
	POLICY_HND pol_svc;
	QUERY_SERVICE_CONFIG cfg;
	uint32 svc_buf_size = 0x8000;

	char *svc_name;

	POLICY_HND pol_scm;
	
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	DEBUG(4,("cmd_svc_set: server:%s\n", srv_name));

	if (argc < 2)
	{
		report(out_hnd,"svcset <service name>\n");
		return;
	}

	svc_name = argv[1];

	/* open service control manager receive a policy handle */
	res = res ? svc_open_sc_man( srv_name, NULL, 0x80000004,
				&pol_scm) : False;

	res2 = res ? svc_open_service( &pol_scm,
				       svc_name, 0x80000001,
				       &pol_svc) : False;
	res3 = res2 ? svc_query_svc_cfg( &pol_svc, &cfg,
				       &svc_buf_size) : False;

	if (res3)
	{
		res3 = svc_change_svc_cfg(&pol_svc,
		                   cfg.service_type,
		                   cfg.start_type,
		                   0xffffffff,
		                   0,
		                   NULL, NULL,
		                   cfg.tag_id,
		                   NULL, "administrator", NULL, NULL);
			
	}

	res2 = res2 ? svc_close(&pol_svc) : False;

	res = res ? svc_close(&pol_scm) : False;

	if (res3)
	{
		DEBUG(5,("cmd_svc_set: change succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_svc_set: change failed\n"));
	}
}

/****************************************************************************
nt stop service 
****************************************************************************/
void cmd_svc_unk3(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;
	BOOL res1 = True;
	POLICY_HND pol_scm;
	POLICY_HND unkhnd;
	
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	DEBUG(4,("cmd_svc_unk3: server:%s\n", srv_name));

	/* open service control manager receive a policy handle */
	res = res ? svc_open_sc_man(srv_name, NULL, 0x000f0009,
				    &pol_scm) : False;

	res1 = res ? svc_unknown_3(&pol_scm, &unkhnd) : False;
	if (res1) svc_close(&unkhnd);

	res  = res ? svc_close(&pol_scm) : False;

	if (res1)
	{
		DEBUG(5,("cmd_svc_unk3: succeeded\n"));
	}
}
