
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                  1997-1998.
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

extern int DEBUGLEVEL;

/****************************************************************************
do a SVC Open Policy
****************************************************************************/
BOOL svc_open_sc_man( const char *srv_name, char *db_name,
				uint32 des_access,
				POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	SVC_Q_OPEN_SC_MAN q_o;
	BOOL valid_pol = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_init(srv_name, PIPE_SVCCTL, &con))
	{
		return False;
	}

	if (hnd == NULL) return False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api SVC_OPEN_SC_MAN */

	DEBUG(4,("SVC Open SC_MAN\n"));

	make_svc_q_open_sc_man(&q_o, srv_name, db_name, des_access);

	/* turn parameters into data stream */
	svc_io_q_open_sc_man("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SVC_OPEN_SC_MAN, &buf, &rbuf))
	{
		SVC_R_OPEN_SC_MAN r_o;
		BOOL p;

		ZERO_STRUCT(r_o);

		svc_io_r_open_sc_man("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(1,("SVC_OPEN_SC_MAN: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the policy handle */
			memcpy(hnd, r_o.pol.data, sizeof(hnd->data));
			valid_pol = True;
			valid_pol = register_policy_hnd(hnd) &&
			            set_policy_con(hnd, con, 
			                                 cli_connection_unlink);
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_pol;
}


/****************************************************************************
do a SVC Open Service
****************************************************************************/
BOOL svc_open_service( POLICY_HND *scm_hnd,
				const char *srv_name,
				uint32 des_access,
				POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	SVC_Q_OPEN_SERVICE q_o;
	BOOL valid_pol = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_get(scm_hnd, &con))
	{
		return False;
	}

	if (hnd == NULL || scm_hnd == NULL) return False;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api SVC_OPEN_SERVICE */

	DEBUG(4,("SVC Open Service\n"));

	make_svc_q_open_service(&q_o, scm_hnd, srv_name, des_access);

	/* turn parameters into data stream */
	svc_io_q_open_service("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SVC_OPEN_SERVICE, &buf, &rbuf))
	{
		SVC_R_OPEN_SERVICE r_o;
		BOOL p;

		ZERO_STRUCT(r_o);

		svc_io_r_open_service("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(1,("SVC_OPEN_SC_MAN: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the policy handle */
			memcpy(hnd, r_o.pol.data, sizeof(hnd->data));
			valid_pol = register_policy_hnd(hnd) &&
			            set_policy_con(hnd, con, NULL);
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_pol;
}


/****************************************************************************
do a SVC Enumerate Services
****************************************************************************/
BOOL svc_enum_svcs( POLICY_HND *hnd,
				uint32 services_type, uint32 services_state,
				uint32 *buf_size, uint32 *resume_hnd,
				uint32 *dos_error,
				ENUM_SRVC_STATUS **svcs, uint32 *num_svcs)
{
	prs_struct rbuf;
	prs_struct buf; 
	SVC_Q_ENUM_SVCS_STATUS q_o;
	BOOL valid_pol = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_get(hnd, &con))
	{
		return False;
	}

	if (hnd == NULL || buf_size == NULL || dos_error == NULL || num_svcs == NULL)
	{
		return False;
	}

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api SVC_ENUM_SVCS_STATUS */

	DEBUG(4,("SVC Enum Services Status\n"));

	make_svc_q_enum_svcs_status(&q_o, hnd,
	                            services_type, services_state,
	                            *buf_size, *resume_hnd);

	/* turn parameters into data stream */
	svc_io_q_enum_svcs_status("", &q_o, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SVC_ENUM_SVCS_STATUS, &buf, &rbuf))
	{
		SVC_R_ENUM_SVCS_STATUS r_o;
		BOOL p;

		ZERO_STRUCT(r_o);

		svc_io_r_enum_svcs_status("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.dos_status != 0)
		{
			fstring errmsg;

			if (r_o.dos_status != ERRmoredata)
			{
				smb_safe_err_msg(ERRDOS, r_o.dos_status,
				                 errmsg, sizeof(errmsg));
				/* report error code */
				DEBUG(1,("SVC_ENUM_SVCS_STATUS: %s\n", errmsg));
			}
			p = r_o.dos_status == ERRmoredata;
		}

		if (p)
		{
			(*svcs) = r_o.svcs;
			(*num_svcs) = r_o.num_svcs;
			(*resume_hnd) = get_enum_hnd(&r_o.resume_hnd);
			(*buf_size) = r_o.more_buf_size;
			(*dos_error) = r_o.dos_status;
			valid_pol = True;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_pol;
}


/****************************************************************************
do a SVC Stop Service 
****************************************************************************/
BOOL svc_stop_service( POLICY_HND *hnd,
				uint32 unknown)
{
	prs_struct rbuf;
	prs_struct buf; 
	SVC_Q_STOP_SERVICE q_c;
	BOOL valid_cfg = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_get(hnd, &con))
	{
		return False;
	}

	if (hnd == NULL) return False;

	/* create and send a MSRPC command with api SVC_STOP_SERVICE */

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SVC Stop Service\n"));

	/* store the parameters */
	make_svc_q_stop_service(&q_c, hnd, unknown);

	/* turn parameters into data stream */
	svc_io_q_stop_service("", &q_c, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SVC_STOP_SERVICE, &buf, &rbuf))
	{
		SVC_R_STOP_SERVICE r_c;
		BOOL p;

		ZERO_STRUCT (r_c);

		svc_io_r_stop_service("", &r_c, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(1,("SVC_START_SERVICE: %s\n", get_nt_error_msg(r_c.status)));
			p = False;
		}

		if (p)
		{
			valid_cfg = True;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_cfg;
}


/****************************************************************************
do a SVC Start Service 
****************************************************************************/
BOOL svc_start_service( POLICY_HND *hnd,
				uint32 argc,
				char **argv)
{
	prs_struct rbuf;
	prs_struct buf; 
	SVC_Q_START_SERVICE q_c;
	BOOL valid_cfg = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_get(hnd, &con))
	{
		return False;
	}

	if (hnd == NULL) return False;

	/* create and send a MSRPC command with api SVC_START_SERVICE */

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SVC Start Service\n"));

	/* store the parameters */
	make_svc_q_start_service(&q_c, hnd, argc, argv);

	/* turn parameters into data stream */
	svc_io_q_start_service("", &q_c, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SVC_START_SERVICE, &buf, &rbuf))
	{
		SVC_R_START_SERVICE r_c;
		BOOL p;

		ZERO_STRUCT (r_c);

		svc_io_r_start_service("", &r_c, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(1,("SVC_START_SERVICE: %s\n", get_nt_error_msg(r_c.status)));
			p = False;
		}

		if (p)
		{
			valid_cfg = True;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_cfg;
}


/****************************************************************************
do a SVC Query Service Config
****************************************************************************/
BOOL svc_query_svc_cfg( POLICY_HND *hnd,
				QUERY_SERVICE_CONFIG *cfg,
				uint32 *buf_size)
{
	prs_struct rbuf;
	prs_struct buf; 
	SVC_Q_QUERY_SVC_CONFIG q_c;
	BOOL valid_cfg = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_get(hnd, &con))
	{
		return False;
	}

	if (hnd == NULL || buf_size == NULL) return False;

	/* create and send a MSRPC command with api SVC_QUERY_SVC_CONFIG */

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SVC Query Service Config\n"));

	/* store the parameters */
	make_svc_q_query_svc_config(&q_c, hnd, *buf_size);

	/* turn parameters into data stream */
	svc_io_q_query_svc_config("", &q_c, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SVC_QUERY_SVC_CONFIG, &buf, &rbuf))
	{
		SVC_R_QUERY_SVC_CONFIG r_c;
		BOOL p;

		ZERO_STRUCT (r_c);
		ZERO_STRUCTP(cfg);

		r_c.cfg = cfg;

		svc_io_r_query_svc_config("", &r_c, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(1,("SVC_QUERY_SVC_CONFIG: %s\n", get_nt_error_msg(r_c.status)));
			p = False;
		}

		if (p)
		{
			valid_cfg = r_c.buf_size != 0;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_cfg;
}


/****************************************************************************
do a SVC Close
****************************************************************************/
BOOL svc_close(POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	SVC_Q_CLOSE q_c;
	BOOL valid_close = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_get(hnd, &con))
	{
		return False;
	}

	if (hnd == NULL) return False;

	/* create and send a MSRPC command with api SVC_CLOSE */

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SVC Close\n"));

	/* store the parameters */
	make_svc_q_close(&q_c, hnd);

	/* turn parameters into data stream */
	svc_io_q_close("", &q_c, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SVC_CLOSE, &buf, &rbuf))
	{
		SVC_R_CLOSE r_c;
		BOOL p;

		ZERO_STRUCT(r_c);

		svc_io_r_close("", &r_c, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(1,("SVC_CLOSE: %s\n", get_nt_error_msg(r_c.status)));
			p = False;
		}

		if (p)
		{
			/* check that the returned policy handle is all zeros */
			uint32 i;
			valid_close = True;

			for (i = 0; i < sizeof(r_c.pol.data); i++)
			{
				if (r_c.pol.data[i] != 0)
				{
					valid_close = False;
					break;
				}
			}	
			if (!valid_close)
			{
				DEBUG(1,("SVC_CLOSE: non-zero handle returned\n"));
			}
		}
	}

	close_policy_hnd(hnd);

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_close;
}

/****************************************************************************
do a SVC Change Service Config
****************************************************************************/
BOOL svc_change_svc_cfg( POLICY_HND *hnd,
				uint32 service_type, uint32 start_type,
				uint32 unknown_0,
				uint32 error_control,
				char* bin_path_name, char* load_order_grp, 
				uint32 tag_id,
				char* dependencies, char* service_start_name,
				char* password,
				char* disp_name)
{
	prs_struct rbuf;
	prs_struct buf; 
	SVC_Q_CHANGE_SVC_CONFIG q_c;
	BOOL valid_cfg = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_get(hnd, &con))
	{
		return False;
	}

	if (hnd == NULL) return False;

	/* create and send a MSRPC command with api SVC_CHANGE_SVC_CONFIG */

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SVC Change Service Config\n"));

	/* store the parameters */
	make_svc_q_change_svc_config(&q_c, hnd, 
				service_type, start_type,
	                        unknown_0, error_control,
				bin_path_name, load_order_grp, 
				tag_id,
				dependencies, service_start_name,
				password, disp_name);

	/* turn parameters into data stream */
	svc_io_q_change_svc_config("", &q_c, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SVC_CHANGE_SVC_CONFIG, &buf, &rbuf))
	{
		SVC_R_CHANGE_SVC_CONFIG r_c;
		BOOL p;

		ZERO_STRUCT (r_c);

		svc_io_r_change_svc_config("", &r_c, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(1,("SVC_CHANGE_SVC_CONFIG: %s\n", get_nt_error_msg(r_c.status)));
			p = False;
		}

		if (p)
		{
			valid_cfg = True;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return valid_cfg;
}
