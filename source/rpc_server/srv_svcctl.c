
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

/*******************************************************************
 api_svc_close
 ********************************************************************/
static BOOL api_svc_close(prs_struct *data,
			  prs_struct *rdata)
{
	SVC_Q_CLOSE q_r;
	SVC_R_CLOSE r_u;

	ZERO_STRUCT(q_r);
	ZERO_STRUCT(r_u);

	if (!svc_io_q_close("", &q_r, data, 0))
	{
		return False;
	}

	r_u.pol = q_r.pol;
	r_u.status = _svc_close(&r_u.pol);

	/* store the response in the SMB stream */
	return svc_io_r_close("", &r_u, rdata, 0);
}

/*******************************************************************
 api_svc_open_service
 ********************************************************************/
static BOOL api_svc_open_service(prs_struct *data,
				 prs_struct *rdata)
{
	SVC_Q_OPEN_SERVICE q_u;
	SVC_R_OPEN_SERVICE r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!svc_io_q_open_service("", &q_u, data, 0))
	{
		return False;
	}

	r_u.status = _svc_open_service(&q_u.scman_pol,
				       &q_u.uni_svc_name,
				       q_u.des_access, &r_u.pol);

	/* store the response in the SMB stream */
	return svc_io_r_open_service("", &r_u, rdata, 0);
}

/*******************************************************************
 api_svc_stop_service
 ********************************************************************/
static BOOL api_svc_stop_service(prs_struct *data,
				 prs_struct *rdata)
{
	SVC_Q_STOP_SERVICE q_u;
	SVC_R_STOP_SERVICE r_s;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_s);

	if (!svc_io_q_stop_service("", &q_u, data, 0))
	{
		return False;
	}

	r_s.status = _svc_stop_service(&q_u.pol,
				       q_u.unknown,
				       &r_s.unknown0,
				       &r_s.unknown1,
				       &r_s.unknown2,
				       &r_s.unknown3,
				       &r_s.unknown4,
				       &r_s.unknown5, &r_s.unknown6);

	/* store the response in the SMB stream */
	return svc_io_r_stop_service("", &r_s, rdata, 0);
}

/*******************************************************************
 api_svc_start_service
 ********************************************************************/
static BOOL api_svc_start_service(prs_struct *data,
				  prs_struct *rdata)
{
	SVC_Q_START_SERVICE q_u;
	SVC_R_START_SERVICE r_s;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_s);

	if (!svc_io_q_start_service("", &q_u, data, 0))
	{
		return False;
	}

	r_s.status = _svc_start_service(&q_u.pol,
					q_u.argc, q_u.argc2, q_u.argv);

	/* store the response in the SMB stream */
	return svc_io_r_start_service("", &r_s, rdata, 0);
}

/*******************************************************************
 api_svc_open_sc_man
 ********************************************************************/
static BOOL api_svc_open_sc_man(prs_struct *data,
				prs_struct *rdata)
{
	SVC_Q_OPEN_SC_MAN q_u;
	SVC_R_OPEN_SC_MAN r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!svc_io_q_open_sc_man("", &q_u, data, 0))
	{
		return False;
	}

	r_u.status = _svc_open_sc_man(&q_u.uni_srv_name,
				      &q_u.uni_db_name,
				      q_u.des_access, &r_u.pol);

	/* store the response in the SMB stream */
	return svc_io_r_open_sc_man("", &r_u, rdata, 0);
}

/*******************************************************************
 api_svc_enum_svcs_status
 ********************************************************************/
static BOOL api_svc_enum_svcs_status(prs_struct *data,
				     prs_struct *rdata)
{
	SVC_Q_ENUM_SVCS_STATUS q_u;
	SVC_R_ENUM_SVCS_STATUS r_u;
	uint32 buf_size;
	ENUM_SRVC_STATUS svcs[MAX_SERVICES];
	uint32 more_buf_size;
	uint32 num_svcs;
	ENUM_HND resume_hnd;
	uint32 status;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!svc_io_q_enum_svcs_status("", &q_u, data, 0))
	{
		return False;
	}

	buf_size = q_u.buf_size;
	resume_hnd = q_u.resume_hnd;
	status = _svc_enum_svcs_status(&q_u.pol,
				       q_u.service_type,
				       q_u.service_state,
				       &buf_size,
				       &resume_hnd,
				       svcs, &more_buf_size, &num_svcs);
	make_svc_r_enum_svcs_status(&r_u, svcs, more_buf_size, num_svcs,
				    &resume_hnd, status);

	/* store the response in the SMB stream */
	return svc_io_r_enum_svcs_status("", &r_u, rdata, 0);
}

/*******************************************************************
 api_svc_query_disp_name
 ********************************************************************/
static BOOL api_svc_query_disp_name(prs_struct *data,
				    prs_struct *rdata)
{
	SVC_Q_QUERY_DISP_NAME q_u;
	SVC_R_QUERY_DISP_NAME r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!svc_io_q_query_disp_name("", &q_u, data, 0))
	{
		return False;
	}

	r_u.status = _svc_query_disp_name(&q_u.scman_pol,
					  &q_u.uni_svc_name,
					  q_u.buf_size,
					  &r_u.uni_disp_name, &r_u.buf_size);

	/* store the response in the SMB stream */
	return svc_io_r_query_disp_name("", &r_u, rdata, 0);
}

/*******************************************************************
 api_svc_unknown_3
 ********************************************************************/
static BOOL api_svc_unknown_3(prs_struct *data,
			      prs_struct *rdata)
{
	SVC_Q_UNKNOWN_3 q_u;
	SVC_R_UNKNOWN_3 r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!svc_io_q_unknown_3("", &q_u, data, 0))
	{
		return False;
	}

	r_u.status = _svc_unknown_3(&q_u.scman_hnd, &r_u.hnd);

	/* store the response in the SMB stream */
	return svc_io_r_unknown_3("", &r_u, rdata, 0);
}

/*******************************************************************
 array of \PIPE\svcctl operations
 ********************************************************************/
static const struct api_struct api_svc_cmds[] = {
	{"SVC_CLOSE", SVC_CLOSE, api_svc_close},
	{"SVC_OPEN_SC_MAN", SVC_OPEN_SC_MAN, api_svc_open_sc_man},
	{"SVC_OPEN_SERVICE", SVC_OPEN_SERVICE, api_svc_open_service},

	{"SVC_ENUM_SVCS_STATUS", SVC_ENUM_SVCS_STATUS,
	 api_svc_enum_svcs_status},
	{"SVC_QUERY_DISP_NAME", SVC_QUERY_DISP_NAME, api_svc_query_disp_name},
	{"SVC_START_SERVICE", SVC_START_SERVICE, api_svc_start_service},
	{"SVC_STOP_SERVICE", SVC_STOP_SERVICE, api_svc_stop_service},
	{"SVC_UNKNOWN_3", SVC_UNKNOWN_3, api_svc_unknown_3},
	{NULL, 0, NULL}
};

/*******************************************************************
 receives a svcctl pipe and responds.
 ********************************************************************/
BOOL api_svcctl_rpc(rpcsrv_struct * p)
{
	return api_rpcTNP(p, "api_svc_rpc", api_svc_cmds);
}
