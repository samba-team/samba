
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
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
#include "nterr.h"

extern int DEBUGLEVEL;


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
	if (close_policy_hnd(&(q_r->pol)))
	{
		r_u.status = 0;
	}
	else
	{
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_INVALID;
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
	uint32 status     = 0;
	POLICY_HND pol;
	SVC_R_OPEN_SERVICE r_u;
	fstring name;

	DEBUG(5,("svc_open_service: %d\n", __LINE__));

	if (status == 0x0 && find_policy_by_hnd(&q_u->scman_pol) == -1)
	{
		status = 0xC000000 | NT_STATUS_INVALID_HANDLE;
	}

	if (status == 0x0 && !open_policy_hnd(&pol))
	{
		status = 0xC000000 | NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	unistr2_to_ascii(name, &q_u->uni_svc_name, sizeof(name)-1);

	if (status == 0x0)
	{
		DEBUG(5,("svc_open_service: %s\n", name));
		/* lkcl XXXX do a check on the name, here */
	}

	if (status == 0x0 && !set_policy_reg_name(&pol, name))
	{
		status = 0xC000000 | NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
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
 svc_reply_start_service
 ********************************************************************/
static void svc_reply_start_service(SVC_Q_START_SERVICE *q_s,
				prs_struct *rdata)
{
	SVC_R_START_SERVICE r_s;

	DEBUG(5,("svc_start_service: %d\n", __LINE__));

	r_s.status = 0x0;

	if (find_policy_by_hnd(&q_s->pol) == -1)
	{
		r_s.status = 0xC000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* start the service here */

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
	uint32 status     = 0;
	POLICY_HND pol;
	SVC_R_OPEN_SC_MAN r_u;
	fstring name;

	DEBUG(5,("svc_open_sc_man: %d\n", __LINE__));

	if (status == 0x0 && !open_policy_hnd(&pol))
	{
		status = 0xC000000 | NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	unistr2_to_ascii(name, &q_u->uni_srv_name, sizeof(name)-1);

	if (status == 0x0)
	{
		DEBUG(5,("svc_open_sc_man: %s\n", name));
		/* lkcl XXXX do a check on the name, here */
	}

	if (status == 0x0 && !set_policy_reg_name(&pol, name))
	{
		status = 0xC000000 | NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
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

static char *dummy_services[] =
{
	"imapd",
	"popd",
	"smbd",
	"nmbd",
	"httpd",
	"inetd",
	"syslogd",
	NULL
};

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

	ZERO_STRUCT(r_u);

	DEBUG(5,("svc_enum_svcs_status: %d\n", __LINE__));

	if (dos_status == 0x0 && find_policy_by_hnd(&q_u->pol) == -1)
	{
		dos_status = 0xC000000 | NT_STATUS_INVALID_HANDLE;
	}

	if (dos_status == 0x0)
	{
		DEBUG(5,("svc_enum_svcs_status:\n"));
		while (dummy_services[i] != NULL)
		{
			ENUM_SRVC_STATUS *svc = NULL;

			buf_size += strlen(dummy_services[i] + 1) * 2;
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

			make_unistr(&svc->uni_srvc_name, dummy_services[i]);
			make_unistr(&svc->uni_disp_name, dummy_services[i]);

			DEBUG(10,("show service: %s\n", dummy_services[i]));
			i++;
		}
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
	uint32 status = 0;

	DEBUG(5,("svc_query_disp_name: %d\n", __LINE__));

	if (find_policy_by_hnd(&q_u->scman_pol) == -1)
	{
		status = 0xC000000 | NT_STATUS_INVALID_HANDLE;
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
	{ NULL                  , 0                   , NULL                     }
};

/*******************************************************************
 receives a svcctl pipe and responds.
 ********************************************************************/
BOOL api_svcctl_rpc(rpcsrv_struct *p, prs_struct *data)
{
	return api_rpcTNP(p, "api_svc_rpc", api_svc_cmds, data);
}

