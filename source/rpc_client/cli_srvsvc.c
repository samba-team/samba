
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

extern int DEBUGLEVEL;

/****************************************************************************
do a server net tprt enum
****************************************************************************/
BOOL srv_net_srv_tprt_enum(
			const char *srv_name, 
			uint32 switch_value, SRV_TPRT_INFO_CTR *ctr,
			uint32 preferred_len,
			ENUM_HND *hnd)
{
	prs_struct data; 
	prs_struct rdata;
	SRV_Q_NET_TPRT_ENUM q_o;
	BOOL valid_enum = False;
	struct cli_connection *con = NULL;

	if (ctr == NULL || preferred_len == 0) return False;

	if (!cli_connection_init(srv_name, PIPE_SRVSVC, &con))
	{
		return False;
	}

	prs_init(&data , 1024, 4, False);
	prs_init(&rdata, 0   , 4, True );

	/* create and send a MSRPC command with api SRV_NETTPRTENUM */

	DEBUG(4,("SRV Net Server Transport Enum, level %d, enum:%8x\n",
				switch_value, get_enum_hnd(hnd)));
				
	ctr->switch_value = switch_value;
	ctr->ptr_tprt_ctr = 1;
	ctr->tprt.info0.num_entries_read = 0;
	ctr->tprt.info0.ptr_tprt_info    = 1;

	/* store the parameters */
	make_srv_q_net_tprt_enum(&q_o, srv_name,
	                         switch_value, ctr,
	                         preferred_len,
	                         hnd);

	/* turn parameters into data stream */
	srv_io_q_net_tprt_enum("", &q_o, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SRV_NETTRANSPORTENUM, &data, &rdata))
	{
		SRV_R_NET_TPRT_ENUM r_o;
		BOOL p;

		r_o.ctr = ctr;

		srv_io_r_net_tprt_enum("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SRV_R_NET_SRV_GET_INFO: %s\n", get_nt_error_msg(r_o.status)));
			p = 0;
		}

		if (p && r_o.ctr->switch_value != switch_value)
		{
			/* different switch levels.  oops. */
			DEBUG(0,("SRV_R_NET_SRV_TPRT_ENUM: info class %d does not match request %d\n",
				r_o.ctr->switch_value, switch_value));
			p = 0;
		}

		if (p)
		{
			/* ok, at last: we're happy. */
			valid_enum = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );
	
	cli_connection_unlink(con);

	return valid_enum;
}

/****************************************************************************
do a server net conn enum
****************************************************************************/
BOOL srv_net_srv_conn_enum( char *srv_name, char *qual_name,
			uint32 switch_value, SRV_CONN_INFO_CTR *ctr,
			uint32 preferred_len,
			ENUM_HND *hnd)
{
	prs_struct data; 
	prs_struct rdata;
	SRV_Q_NET_CONN_ENUM q_o;
	BOOL valid_enum = False;
	struct cli_connection *con = NULL;

	if (ctr == NULL || preferred_len == 0) return False;

	if (!cli_connection_init(srv_name, PIPE_SRVSVC, &con))
	{
		return False;
	}

	prs_init(&data , 1024, 4, False);
	prs_init(&rdata, 0   , 4, True );

	/* create and send a MSRPC command with api SRV_NETCONNENUM */

	DEBUG(4,("SRV Net Server Connection Enum %s), level %d, enum:%8x\n",
				qual_name, switch_value, get_enum_hnd(hnd)));
				
	ctr->switch_value = switch_value;
	ctr->ptr_conn_ctr = 1;
	ctr->conn.info0.num_entries_read = 0;
	ctr->conn.info0.ptr_conn_info    = 1;

	/* store the parameters */
	make_srv_q_net_conn_enum(&q_o, srv_name, qual_name,
	                         switch_value, ctr,
	                         preferred_len,
	                         hnd);

	/* turn parameters into data stream */
	srv_io_q_net_conn_enum("", &q_o, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SRV_NETCONNENUM, &data, &rdata))
	{
		SRV_R_NET_CONN_ENUM r_o;
		BOOL p;

		r_o.ctr = ctr;

		srv_io_r_net_conn_enum("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SRV_R_NET_SRV_GET_INFO: %s\n", get_nt_error_msg(r_o.status)));
			p = 0;
		}

		if (p && r_o.ctr->switch_value != switch_value)
		{
			/* different switch levels.  oops. */
			DEBUG(0,("SRV_R_NET_SRV_CONN_ENUM: info class %d does not match request %d\n",
				r_o.ctr->switch_value, switch_value));
			p = 0;
		}

		if (p)
		{
			/* ok, at last: we're happy. */
			valid_enum = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );
	
	cli_connection_unlink(con);

	return valid_enum;
}

/****************************************************************************
do a server net sess enum
****************************************************************************/
BOOL srv_net_srv_sess_enum( char *srv_name, char *qual_name, char *user_name,
			uint32 switch_value, SRV_SESS_INFO_CTR *ctr,
			uint32 preferred_len,
			ENUM_HND *hnd)
{
	prs_struct data; 
	prs_struct rdata;
	SRV_Q_NET_SESS_ENUM q_o;
	BOOL valid_enum = False;
	struct cli_connection *con = NULL;

	if (ctr == NULL || preferred_len == 0) return False;

	if (!cli_connection_init(srv_name, PIPE_SRVSVC, &con))
	{
		return False;
	}

	prs_init(&data , 1024, 4, False);
	prs_init(&rdata, 0   , 4, True );

	/* create and send a MSRPC command with api SRV_NETSESSENUM */

	DEBUG(4,("SRV Net Session Enum, level %d, enum:%8x\n",
				switch_value, get_enum_hnd(hnd)));
				
	ctr->switch_value = switch_value;
	ctr->ptr_sess_ctr = 1;
	ctr->sess.info0.num_entries_read = 0;
	ctr->sess.info0.ptr_sess_info    = 1;

	/* store the parameters */
	make_srv_q_net_sess_enum(&q_o, srv_name, qual_name, user_name,
	                         switch_value, ctr,
	                         preferred_len,
	                         hnd);

	/* turn parameters into data stream */
	srv_io_q_net_sess_enum("", &q_o, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SRV_NETSESSENUM, &data, &rdata))
	{
		SRV_R_NET_SESS_ENUM r_o;
		BOOL p;

		r_o.ctr = ctr;

		srv_io_r_net_sess_enum("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SRV_R_NET_SRV_SESS_ENUM: %s\n", get_nt_error_msg(r_o.status)));
			p = 0;
		}

		if (p && r_o.ctr->switch_value != switch_value)
		{
			/* different switch levels.  oops. */
			DEBUG(0,("SRV_R_NET_SRV_SESS_ENUM: info class %d does not match request %d\n",
				r_o.ctr->switch_value, switch_value));
			p = 0;
		}

		if (p)
		{
			/* ok, at last: we're happy. */
			valid_enum = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );
	
	cli_connection_unlink(con);

	return valid_enum;
}

/****************************************************************************
do a server net share enum
****************************************************************************/
BOOL srv_net_srv_share_enum( char *srv_name, 
			uint32 switch_value, SRV_SHARE_INFO_CTR *ctr,
			uint32 preferred_len,
			ENUM_HND *hnd)
{
	prs_struct data; 
	prs_struct rdata;
	SRV_Q_NET_SHARE_ENUM q_o;
	BOOL valid_enum = False;
	struct cli_connection *con = NULL;

	if (ctr == NULL || preferred_len == 0) return False;

	if (!cli_connection_init(srv_name, PIPE_SRVSVC, &con))
	{
		return False;
	}

	prs_init(&data , 1024, 4, False);
	prs_init(&rdata, 0   , 4, True );

	/* create and send a MSRPC command with api SRV_NETSHAREENUM */

	DEBUG(4,("SRV Get Share Info, level %d, enum:%8x\n",
				switch_value, get_enum_hnd(hnd)));
				
	q_o.share_level = switch_value;

	ctr->switch_value = switch_value;
	ctr->ptr_share_ctr = 1;
	ctr->share.info1.num_entries_read = 0;
	ctr->share.info1.ptr_share_info    = 1;

	/* store the parameters */
	make_srv_q_net_share_enum(&q_o, srv_name, 
	                         switch_value, ctr,
	                         preferred_len,
	                         hnd);

	/* turn parameters into data stream */
	srv_io_q_net_share_enum("", &q_o, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SRV_NETSHAREENUM, &data, &rdata))
	{
		SRV_R_NET_SHARE_ENUM r_o;
		BOOL p;

		r_o.ctr = ctr;

		srv_io_r_net_share_enum("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SRV_R_NET_SRV_GET_INFO: %s\n", get_nt_error_msg(r_o.status)));
			p = 0;
		}

		if (p && r_o.ctr->switch_value != switch_value)
		{
			/* different switch levels.  oops. */
			DEBUG(0,("SRV_R_NET_SRV_SHARE_ENUM: info class %d does not match request %d\n",
				r_o.ctr->switch_value, switch_value));
			p = 0;
		}

		if (p)
		{
			/* ok, at last: we're happy. */
			valid_enum = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );
	
	cli_connection_unlink(con);

	return valid_enum;
}

/****************************************************************************
do a server net file enum
****************************************************************************/
BOOL srv_net_srv_file_enum( char *srv_name, char *qual_name, uint32 file_id,
			uint32 switch_value, SRV_FILE_INFO_CTR *ctr,
			uint32 preferred_len,
			ENUM_HND *hnd)
{
	prs_struct data; 
	prs_struct rdata;
	SRV_Q_NET_FILE_ENUM q_o;
	BOOL valid_enum = False;
	struct cli_connection *con = NULL;

	if (ctr == NULL || preferred_len == 0) return False;

	if (!cli_connection_init(srv_name, PIPE_SRVSVC, &con))
	{
		return False;
	}

	prs_init(&data , 1024, 4, False);
	prs_init(&rdata, 0   , 4, True );

	/* create and send a MSRPC command with api SRV_NETFILEENUM */

	DEBUG(4,("SRV Get File Info level %d, enum:%8x\n",
				switch_value, get_enum_hnd(hnd)));
				
	q_o.file_level = switch_value;

	ctr->switch_value = switch_value;
	ctr->ptr_file_ctr = 1;
	ctr->file.info3.num_entries_read = 0;
	ctr->file.info3.ptr_file_info    = 1;

	/* store the parameters */
	make_srv_q_net_file_enum(&q_o, srv_name, qual_name, file_id,
	                         switch_value, ctr,
	                         preferred_len,
	                         hnd);

	/* turn parameters into data stream */
	srv_io_q_net_file_enum("", &q_o, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SRV_NETFILEENUM, &data, &rdata))
	{
		SRV_R_NET_FILE_ENUM r_o;
		BOOL p;

		r_o.ctr = ctr;

		srv_io_r_net_file_enum("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SRV_R_NET_SRV_GET_INFO: %s\n", get_nt_error_msg(r_o.status)));
			p = 0;
		}

		if (p && r_o.ctr->switch_value != switch_value)
		{
			/* different switch levels.  oops. */
			DEBUG(0,("SRV_R_NET_SRV_FILE_ENUM: info class %d does not match request %d\n",
				r_o.ctr->switch_value, switch_value));
			p = 0;
		}

		if (p)
		{
			/* ok, at last: we're happy. */
			valid_enum = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );
	
	cli_connection_unlink(con);

	return valid_enum;
}

/****************************************************************************
do a server get info 
****************************************************************************/
BOOL srv_net_srv_get_info( char *srv_name, uint32 switch_value,
				SRV_INFO_CTR *ctr)
{
	prs_struct data; 
	prs_struct rdata;
	SRV_Q_NET_SRV_GET_INFO q_o;
	BOOL valid_info = False;
	struct cli_connection *con = NULL;

	if (switch_value == 0 || ctr == NULL) return False;

	if (!cli_connection_init(srv_name, PIPE_SRVSVC, &con))
	{
		return False;
	}

	prs_init(&data , 1024, 4, False);
	prs_init(&rdata, 0   , 4, True );

	/* create and send a MSRPC command with api SRV_NET_SRV_GET_INFO */

	DEBUG(4,("SRV Get Server Info level %d\n", switch_value));

	/* store the parameters */
	make_srv_q_net_srv_get_info(&q_o, srv_name, switch_value);

	/* turn parameters into data stream */
	srv_io_q_net_srv_get_info("", &q_o, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SRV_NET_SRV_GET_INFO, &data, &rdata))
	{
		SRV_R_NET_SRV_GET_INFO r_o;
		BOOL p;

		r_o.ctr = ctr;

		srv_io_r_net_srv_get_info("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SRV_R_NET_SRV_GET_INFO: %s\n", get_nt_error_msg(r_o.status)));
			p = 0;
		}

		if (p && r_o.ctr->switch_value != q_o.switch_value)
		{
			/* different switch levels.  oops. */
			DEBUG(0,("SRV_R_NET_SRV_GET_INFO: info class %d does not match request %d\n",
				r_o.ctr->switch_value, q_o.switch_value));
			p = 0;
		}

		if (p)
		{
			/* ok, at last: we're happy. */
			valid_info = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );
	
	cli_connection_unlink(con);

	return valid_info;
}

/****************************************************************************
get server time
****************************************************************************/
BOOL srv_net_remote_tod( char *srv_name, TIME_OF_DAY_INFO *tod)
{
	prs_struct data; 
	prs_struct rdata;
	SRV_Q_NET_REMOTE_TOD q_t;
	BOOL valid_info = False;
	struct cli_connection *con = NULL;

	if (tod == NULL) return False;

	if (!cli_connection_init(srv_name, PIPE_SRVSVC, &con))
	{
		return False;
	}

	prs_init(&data , 1024, 4, False);
	prs_init(&rdata, 0   , 4, True );

	/* create and send a MSRPC command with api SRV_NET_REMOTE_TOD */

	DEBUG(4,("SRV Remote TOD (%s)\n", srv_name));

	/* store the parameters */
	make_srv_q_net_remote_tod(&q_t, srv_name);

	/* turn parameters into data stream */
	srv_io_q_net_remote_tod("", &q_t, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, SRV_NET_REMOTE_TOD, &data, &rdata))
	{
		SRV_R_NET_REMOTE_TOD r_t;
		BOOL p;

		r_t.tod = tod;

		srv_io_r_net_remote_tod("", &r_t, &rdata, 0);
		p = rdata.offset != 0;
		p = rdata.offset != 0;
		
		if (p && r_t.status != 0)
		{
			/* report error code */
			DEBUG(0,("SRV_R_NET_REMOTE_TOD: %s\n", get_nt_error_msg(r_t.status)));
			p = False;
		}

		if (p)
		{
			valid_info = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );
	
	cli_connection_unlink(con);

	return valid_info;
}
