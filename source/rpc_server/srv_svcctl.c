
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;

/****************************************************************************
  get svc name 
****************************************************************************/
static BOOL get_policy_svc_name(struct policy_cache *cache, POLICY_HND *hnd,
				fstring name)
{
	char *dev;
	dev = (char *)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		fstrcpy(name, dev);
		DEBUG(5,("getting policy svc name=%s\n", name));
		return True;
	}

	DEBUG(3,("Error getting policy svc name\n"));
	return False;
}

/****************************************************************************
  set svc name 
****************************************************************************/
static BOOL set_policy_svc_name(struct policy_cache *cache, POLICY_HND *hnd,
				fstring name)
{
	char *dev = strdup(name);
	if (dev != NULL)
	{
		if (set_policy_state(cache, hnd, NULL, (void*)dev))
		{
			DEBUG(3,("Service setting policy name=%s\n", name));
			return True;
		}
		free(dev);
		return True;
	}

	DEBUG(3,("Error setting policy name=%s\n", name));
	return False;
}

/*******************************************************************
 svc_reply_unknown_1
 ********************************************************************/
static void svc_reply_close(SVC_Q_CLOSE *q_r,
				prs_struct *rdata)
{
	SVC_R_CLOSE r_u;

	/* set up the REG unknown_1 response */
	bzero(r_u.pol.data, POL_HND_SIZE);

	/* close the policy handle */
	if (close_policy_hnd(get_global_hnd_cache(), &(q_r->pol)))
	{
		r_u.status = NT_STATUS_NOPROBLEMO;
	}
	else
	{
		r_u.status = NT_STATUS_OBJECT_NAME_INVALID;
	}

	DEBUG(5,("svc_unknown_1: %d\n", __LINE__));

	/* store the response in the SMB stream */
	svc_io_r_close("", &r_u, rdata, 0);

	DEBUG(5,("svc_unknown_1: %d\n", __LINE__));
}

/*******************************************************************
 api_svc_close
 ********************************************************************/
static void api_svc_close( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	SVC_Q_CLOSE q_r;
	svc_io_q_close("", &q_r, data, 0);
	svc_reply_close(&q_r, rdata);
}


/*******************************************************************
 svc_reply_open_service
 ********************************************************************/
static void svc_reply_open_service(SVC_Q_OPEN_SERVICE *q_u,
				prs_struct *rdata)
{
	uint32 status     = NT_STATUS_NOPROBLEMO;
	POLICY_HND pol;
	SVC_R_OPEN_SERVICE r_u;
	fstring name;

	DEBUG(5,("svc_open_service: %d\n", __LINE__));

	if (status == NT_STATUS_NOPROBLEMO && find_policy_by_hnd(get_global_hnd_cache(), &q_u->scman_pol) == -1)
	{
		status = NT_STATUS_INVALID_HANDLE;
	}

	if (status == NT_STATUS_NOPROBLEMO && !open_policy_hnd(get_global_hnd_cache(), &pol,
	                                      q_u->des_access))
	{
		status = NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	unistr2_to_ascii(name, &q_u->uni_svc_name, sizeof(name)-1);

	if (status == NT_STATUS_NOPROBLEMO)
	{
		DEBUG(5,("svc_open_service: %s\n", name));
		/* lkcl XXXX do a check on the name, here */
	}

	if (status == NT_STATUS_NOPROBLEMO && !set_policy_svc_name(get_global_hnd_cache(), &pol, name))
	{
		status = NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	make_svc_r_open_service(&r_u, &pol, status);

	/* store the response in the SMB stream */
	svc_io_r_open_service("", &r_u, rdata, 0);

	DEBUG(5,("svc_open_service: %d\n", __LINE__));
}

/*******************************************************************
 api_svc_open_service
 ********************************************************************/
static void api_svc_open_service( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	SVC_Q_OPEN_SERVICE q_u;
	svc_io_q_open_service("", &q_u, data, 0);
	svc_reply_open_service(&q_u, rdata);
}

/*******************************************************************
 svc_reply_stop_service
 ********************************************************************/
static void svc_reply_stop_service(SVC_Q_STOP_SERVICE *q_s,
				prs_struct *rdata)
{
	fstring svc_name;
	fstring script;

	SVC_R_STOP_SERVICE r_s;

	DEBUG(5,("svc_stop_service: %d\n", __LINE__));

	r_s.status = NT_STATUS_NOPROBLEMO;

	if (find_policy_by_hnd(get_global_hnd_cache(), &q_s->pol) == -1 ||
		!get_policy_svc_name(get_global_hnd_cache(), &q_s->pol, svc_name))
	{
		r_s.status = NT_STATUS_INVALID_HANDLE;
	}

	slprintf(script, sizeof(script)-1, "%s/rc.service stop %s/%s.pid %s/%s",
			SBINDIR, LOCKDIR, svc_name, BINDIR, svc_name);
	
	DEBUG(10,("start_service: %s\n", script));

	/* start the service here */
	if (smbrun(script, "/tmp/foo", False) == 0)
	{
		r_s.status = NT_STATUS_ACCESS_DENIED;
	}

	/* store the response in the SMB stream */
	svc_io_r_stop_service("", &r_s, rdata, 0);

	DEBUG(5,("svc_stop_service: %d\n", __LINE__));
}

/*******************************************************************
 api_svc_stop_service
 ********************************************************************/
static void api_svc_stop_service( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	SVC_Q_STOP_SERVICE q_u;
	svc_io_q_stop_service("", &q_u, data, 0);
	svc_reply_stop_service(&q_u, rdata);
}

/*******************************************************************
 svc_reply_start_service
 ********************************************************************/
static void svc_reply_start_service(SVC_Q_START_SERVICE *q_s,
				prs_struct *rdata)
{
	fstring svc_name;
	pstring script;

	SVC_R_START_SERVICE r_s;

	DEBUG(5,("svc_start_service: %d\n", __LINE__));

	r_s.status = NT_STATUS_NOPROBLEMO;

	if (find_policy_by_hnd(get_global_hnd_cache(), &q_s->pol) == -1 ||
		!get_policy_svc_name(get_global_hnd_cache(), &q_s->pol, svc_name))
	{
		r_s.status = NT_STATUS_INVALID_HANDLE;
	}

	slprintf(script, sizeof(script)-1, "%s/rc.service start %s/%s.pid %s/%s",
			SBINDIR, LOCKDIR, svc_name, BINDIR, svc_name);
	
	DEBUG(10,("svc_start_service: %s\n", script));

	/* start the service here */
	if (smbrun(script, "/tmp/foo", False) == 0)
	{
		r_s.status = NT_STATUS_ACCESS_DENIED;
	}

	/* store the response in the SMB stream */
	svc_io_r_start_service("", &r_s, rdata, 0);

	DEBUG(5,("svc_start_service: %d\n", __LINE__));
}

/*******************************************************************
 api_svc_start_service
 ********************************************************************/
static void api_svc_start_service( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	SVC_Q_START_SERVICE q_u;
	svc_io_q_start_service("", &q_u, data, 0);
	svc_reply_start_service(&q_u, rdata);
}

/*******************************************************************
 svc_reply_open_sc_man
 ********************************************************************/
static void svc_reply_open_sc_man(SVC_Q_OPEN_SC_MAN *q_u,
				prs_struct *rdata)
{
	uint32 status     = NT_STATUS_NOPROBLEMO;
	POLICY_HND pol;
	SVC_R_OPEN_SC_MAN r_u;
	fstring name;

	DEBUG(5,("svc_open_sc_man: %d\n", __LINE__));

	if (status == NT_STATUS_NOPROBLEMO && !open_policy_hnd(get_global_hnd_cache(), &pol,		                                      q_u->des_access))
	{
		status = NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	unistr2_to_ascii(name, &q_u->uni_srv_name, sizeof(name)-1);

	if (status == NT_STATUS_NOPROBLEMO)
	{
		DEBUG(5,("svc_open_sc_man: %s\n", name));
		/* lkcl XXXX do a check on the name, here */
	}

	if (status == NT_STATUS_NOPROBLEMO && !set_policy_svc_name(get_global_hnd_cache(), &pol, name))
	{
		status = NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	make_svc_r_open_sc_man(&r_u, &pol, status);

	/* store the response in the SMB stream */
	svc_io_r_open_sc_man("", &r_u, rdata, 0);

	DEBUG(5,("svc_open_sc_man: %d\n", __LINE__));
}

/*******************************************************************
 api_svc_open_sc_man
 ********************************************************************/
static void api_svc_open_sc_man( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	SVC_Q_OPEN_SC_MAN q_u;
	svc_io_q_open_sc_man("", &q_u, data, 0);
	svc_reply_open_sc_man(&q_u, rdata);
}

/*******************************************************************
 svc_reply_enum_svcs_status
 ********************************************************************/
static void svc_reply_enum_svcs_status(SVC_Q_ENUM_SVCS_STATUS *q_u,
				prs_struct *rdata)
{
	uint32 dos_status = 0;
	SVC_R_ENUM_SVCS_STATUS r_u;
	ENUM_SRVC_STATUS *svcs = NULL;
	int num_svcs = 0;
	int buf_size = 0;
	int i = get_enum_hnd(&q_u->resume_hnd);
	uint32 resume_hnd = 0;
	int max_buf_size = 0x10000;
	uint32 num_entries = 10;
	char *services[] =
	{
		"lsarpcd",
		"srvsvcd",
		"wkssvcd",
		"smbd",
		"nmbd",
		"svcctld",
		"samrd",
		"spoolssd",
		"browserd",
		"winregd"
	};

	ZERO_STRUCT(r_u);

	DEBUG(5,("svc_enum_svcs_status: %d\n", __LINE__));

	if (dos_status == NT_STATUS_NOPROBLEMO && find_policy_by_hnd(get_global_hnd_cache(), &q_u->pol) == -1)
	{
		dos_status = NT_STATUS_INVALID_HANDLE;
	}

#if 0
	if (dos_status == NT_STATUS_NOPROBLEMO)
	{
		DEBUG(5,("svc_enum_svcs_status:\n"));

		if (!get_file_match(LOCKDIR, "*.pid", &num_entries, &services))
		{
			dos_status = ERRnoaccess;
		}
	}
#endif
	for (i = 0; i < num_entries; i++)
	{
		ENUM_SRVC_STATUS *svc = NULL;
		fstring svc_name;
		int len;

		fstrcpy(svc_name, services[i]);
		len = strlen(services[i]);
#if 0
		svc_name[len-4] = 0;
		len -= 4;
#endif

		buf_size += (len+1) * 2;
		buf_size += 9 * sizeof(uint32);

		DEBUG(10,("buf_size: %d q_u->buf_size: %d\n",
			   buf_size, q_u->buf_size));

		if (buf_size >= max_buf_size)
		{
			resume_hnd = i;
			break;
		}

		if (buf_size > q_u->buf_size)
		{
			dos_status = ERRmoredata;
			break;
		}

		num_svcs++;
		svcs = Realloc(svcs, num_svcs * sizeof(ENUM_SRVC_STATUS));
		if (svcs == NULL)
		{
			dos_status = ERRnomem;
			num_svcs = 0;
			break;
		}

		svc = &svcs[num_svcs-1];
		ZERO_STRUCTP(svc);

		make_unistr(&svc->uni_srvc_name, svc_name);
		make_unistr(&svc->uni_disp_name, svc_name);

		DEBUG(10,("show service: %s\n", svc_name));
	}

	/*
	 * check for finished condition: no resume handle and last buffer fits
	 */

	if (resume_hnd == 0 && buf_size <= q_u->buf_size)
	{
		/* this indicates, along with resume_hnd of 0, an end. */
		max_buf_size = 0;
	}

	make_svc_r_enum_svcs_status(&r_u, svcs, max_buf_size, num_svcs, resume_hnd, dos_status);

	/* store the response in the SMB stream */
	svc_io_r_enum_svcs_status("", &r_u, rdata, 0);

	if (svcs != NULL)
	{
		free(svcs);
	}

#if 0
	free_char_array(num_entries, services);
#endif

	DEBUG(5,("svc_enum_svcs_status: %d\n", __LINE__));
}

/*******************************************************************
 api_svc_enum_svcs_status
 ********************************************************************/
static void api_svc_enum_svcs_status( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	SVC_Q_ENUM_SVCS_STATUS q_u;
	svc_io_q_enum_svcs_status("", &q_u, data, 0);
	svc_reply_enum_svcs_status(&q_u, rdata);
}

/*******************************************************************
 svc_reply_query_disp_name
 ********************************************************************/
static void svc_reply_query_disp_name(SVC_Q_QUERY_DISP_NAME *q_u,
				prs_struct *rdata)
{
	SVC_R_QUERY_DISP_NAME r_u;
	fstring svc_name;
	uint32 status = NT_STATUS_NOPROBLEMO;

	DEBUG(5,("svc_query_disp_name: %d\n", __LINE__));

	if (find_policy_by_hnd(get_global_hnd_cache(), &q_u->scman_pol) == -1)
	{
		status = NT_STATUS_INVALID_HANDLE;
	}

	/* for now display name = service name */
	unistr2_to_ascii(svc_name, &q_u->uni_svc_name, sizeof(svc_name)-1);
	make_svc_r_query_disp_name(&r_u, svc_name, status);

	/* store the response in the SMB stream */
	svc_io_r_query_disp_name("", &r_u, rdata, 0);

	DEBUG(5,("svc_query_disp_name: %d\n", __LINE__));
}

/*******************************************************************
 api_svc_query_disp_name
 ********************************************************************/
static void api_svc_query_disp_name( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	SVC_Q_QUERY_DISP_NAME q_u;
	svc_io_q_query_disp_name("", &q_u, data, 0);
	svc_reply_query_disp_name(&q_u, rdata);
}

/*******************************************************************
 array of \PIPE\svcctl operations
 ********************************************************************/
static struct api_struct api_svc_cmds[] =
{
	{ "SVC_CLOSE"           , SVC_CLOSE           , api_svc_close            },
	{ "SVC_OPEN_SC_MAN"     , SVC_OPEN_SC_MAN     , api_svc_open_sc_man      },
	{ "SVC_OPEN_SERVICE"    , SVC_OPEN_SERVICE    , api_svc_open_service     },
	{ "SVC_ENUM_SVCS_STATUS", SVC_ENUM_SVCS_STATUS, api_svc_enum_svcs_status },
	{ "SVC_QUERY_DISP_NAME" , SVC_QUERY_DISP_NAME , api_svc_query_disp_name  },
	{ "SVC_START_SERVICE"   , SVC_START_SERVICE   , api_svc_start_service    },
	{ "SVC_STOP_SERVICE"    , SVC_STOP_SERVICE    , api_svc_stop_service     },
	{ NULL                  , 0                   , NULL                     }
};

/*******************************************************************
 receives a svcctl pipe and responds.
 ********************************************************************/
BOOL api_svcctl_rpc(rpcsrv_struct *p)
{
	return api_rpcTNP(p, "api_svc_rpc", api_svc_cmds);
}

