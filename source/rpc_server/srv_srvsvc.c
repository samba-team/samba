
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
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;
extern pstring global_myname;

/*******************************************************************
********************************************************************/
static BOOL api_srv_net_srv_get_info(prs_struct *data,
				     prs_struct *rdata)
{
	SRV_Q_NET_SRV_GET_INFO q_n;
	SRV_R_NET_SRV_GET_INFO r_n;
	SRV_INFO_CTR ctr;
	uint32 status;

	ZERO_STRUCT(q_n);
	ZERO_STRUCT(r_n);

	/* grab the net server get info */
	if (!srv_io_q_net_srv_get_info("", &q_n, data, 0))
	{
		return False;
	}

	status = _srv_net_srv_get_info(&q_n.uni_srv_name, q_n.switch_value,
				       &ctr);

	/* set up the net server get info structure */
	make_srv_r_net_srv_get_info(&r_n, q_n.switch_value, &ctr, status);

	/* store the response in the SMB stream */
	return srv_io_r_net_srv_get_info("", &r_n, rdata, 0);
}

/*******************************************************************
********************************************************************/
static BOOL api_srv_net_file_enum(prs_struct *data,
				  prs_struct *rdata)
{
	SRV_Q_NET_FILE_ENUM q_n;
	SRV_R_NET_FILE_ENUM r_n;
	SRV_FILE_INFO_CTR ctr;
	BOOL ret;

	ZERO_STRUCT(q_n);
	ZERO_STRUCT(r_n);
	ZERO_STRUCT(ctr);

	q_n.ctr = &ctr;
	r_n.ctr = &ctr;

	/* grab the net server get enum */
	if (!srv_io_q_net_file_enum("", &q_n, data, 0))
	{
		return False;
	}

	r_n.file_level = q_n.file_level;

	r_n.status = _srv_net_file_enum(&q_n.uni_srv_name,
					ctr.switch_value, &ctr,
					q_n.preferred_len, &q_n.enum_hnd,
					&(r_n.total_entries), q_n.file_level);

	r_n.enum_hnd = q_n.enum_hnd;

	/* store the response in the SMB stream */
	ret = srv_io_r_net_file_enum("", &r_n, rdata, 0);

	srv_free_srv_file_ctr(&ctr);

	return ret;
}

/*******************************************************************
********************************************************************/
static BOOL api_srv_net_conn_enum(prs_struct *data,
				  prs_struct *rdata)
{
	SRV_Q_NET_CONN_ENUM q_n;
	SRV_R_NET_CONN_ENUM r_n;
	SRV_CONN_INFO_CTR ctr;

	ZERO_STRUCT(q_n);
	ZERO_STRUCT(r_n);

	q_n.ctr = &ctr;
	r_n.ctr = &ctr;

	r_n.conn_level = q_n.conn_level;

	/* grab the net server get enum */
	if (!srv_io_q_net_conn_enum("", &q_n, data, 0))
	{
		return False;
	}


	r_n.status = _srv_net_conn_enum(&q_n.uni_srv_name,
					ctr.switch_value, &ctr,
					q_n.preferred_len, &q_n.enum_hnd,
					&(r_n.total_entries), q_n.conn_level);

	r_n.enum_hnd = q_n.enum_hnd;

	/* store the response in the SMB stream */
	return srv_io_r_net_conn_enum("", &r_n, rdata, 0);
}

/*******************************************************************
********************************************************************/
static BOOL api_srv_net_sess_enum(prs_struct *data,
				  prs_struct *rdata)
{
	SRV_Q_NET_SESS_ENUM q_n;
	SRV_R_NET_SESS_ENUM r_n;
	SRV_SESS_INFO_CTR ctr;

	ZERO_STRUCT(q_n);
	ZERO_STRUCT(r_n);

	q_n.ctr = &ctr;
	r_n.ctr = &ctr;

	/* grab the net server get enum */
	if (!srv_io_q_net_sess_enum("", &q_n, data, 0))
	{
		return False;
	}

	r_n.sess_level = q_n.sess_level;

	r_n.status = _srv_net_sess_enum(&q_n.uni_srv_name,
					ctr.switch_value, &ctr,
					q_n.preferred_len, &q_n.enum_hnd,
					&(r_n.total_entries), q_n.sess_level);

	r_n.enum_hnd = q_n.enum_hnd;

	/* store the response in the SMB stream */
	return srv_io_r_net_sess_enum("", &r_n, rdata, 0);
}

/*******************************************************************
********************************************************************/
static BOOL api_srv_net_share_enum(prs_struct *data,
				   prs_struct *rdata)
{
	SRV_Q_NET_SHARE_ENUM q_n;
	SRV_R_NET_SHARE_ENUM r_n;
	SRV_SHARE_INFO_CTR ctr;

	BOOL ret;

	ZERO_STRUCT(q_n);
	ZERO_STRUCT(r_n);
	ZERO_STRUCT(ctr);

	q_n.ctr = &ctr;
	r_n.ctr = &ctr;

	/* grab the net server get enum */
	if (!srv_io_q_net_share_enum("", &q_n, data, 0))
	{
		return False;
	}

	r_n.share_level = q_n.share_level;

	r_n.status = _srv_net_share_enum(&q_n.uni_srv_name,
					 ctr.switch_value, &ctr,
					 q_n.preferred_len, &q_n.enum_hnd,
					 &(r_n.total_entries),
					 q_n.share_level);

	r_n.enum_hnd = q_n.enum_hnd;

	/* store the response in the SMB stream */
	ret = srv_io_r_net_share_enum("", &r_n, rdata, 0);
	srv_free_srv_share_ctr(&ctr);
	return ret;
}

/*******************************************************************
********************************************************************/
static BOOL api_srv_net_share_add(prs_struct *data,
				  prs_struct *rdata)
{
	SRV_Q_NET_SHARE_ADD q_n;
	SRV_R_NET_SHARE_ADD r_n;

	ZERO_STRUCT(q_n);
	ZERO_STRUCT(r_n);

	if (!srv_io_q_net_share_add("srv_q_net_share_add", &q_n, data, 0))
	{
		return False;
	}

	r_n.status = _srv_net_share_add(&q_n.uni_srv_name,
					q_n.info_level,
					&q_n.ctr, &q_n.parm_error);
	r_n.parm_error = q_n.parm_error;
	srv_free_share_info_ctr(&q_n.ctr);

	return srv_io_r_net_share_add("srv_r_net_share_add", &r_n, rdata, 0);
}

/*******************************************************************
********************************************************************/
static BOOL api_srv_net_share_del(prs_struct *data, prs_struct *rdata)
{
	SRV_Q_NET_SHARE_DEL q_n;

	ZERO_STRUCT(q_n);

	if (!srv_io_q_net_share_del("srv_q_net_share_del", &q_n, data, 0))
	{
		return False;
	}

	return False;
}

/*******************************************************************
********************************************************************/
static BOOL api_srv_net_share_get_info(prs_struct *data,
				       prs_struct *rdata)
{
	SRV_Q_NET_SHARE_GET_INFO q_n;
	SRV_R_NET_SHARE_GET_INFO r_n;
	SHARE_INFO_CTR ctr;
	uint32 status;
	BOOL ret;

	ZERO_STRUCT(q_n);
	ZERO_STRUCT(r_n);
	ZERO_STRUCT(ctr);

	/* grab the request */
	if (!srv_io_q_net_share_get_info("", &q_n, data, 0))
	{
		return False;
	}

	status = _srv_net_share_get_info(&q_n.uni_srv_name,
					 &q_n.share_name, q_n.info_level,
					 &ctr);

	make_srv_r_net_share_get_info(&r_n, q_n.info_level, &ctr, status);
	ctr.info_level = q_n.info_level;

	ret = srv_io_r_net_share_get_info("", &r_n, rdata, 0);

	srv_free_share_info_ctr(&ctr);

	return ret;
}

/*******************************************************************
********************************************************************/
static BOOL api_srv_net_remote_tod(prs_struct *data,
				   prs_struct *rdata)
{
	SRV_Q_NET_REMOTE_TOD q_n;
	SRV_R_NET_REMOTE_TOD r_n;
	TIME_OF_DAY_INFO tod;
	uint32 status;

	ZERO_STRUCT(q_n);
	ZERO_STRUCT(r_n);

	/* grab the net server get enum */
	if (!srv_io_q_net_remote_tod("", &q_n, data, 0))
	{
		return False;
	}


	status = _srv_net_remote_tod(&q_n.uni_srv_name, &tod);

	r_n.tod = &tod;
	r_n.ptr_srv_tod = 0x1;
	r_n.status = status;

	/* store the response in the SMB stream */
	return srv_io_r_net_remote_tod("", &r_n, rdata, 0);
}


/*******************************************************************
\PIPE\srvsvc commands
********************************************************************/
static const struct api_struct api_srv_cmds[] = {
	{"NETCONNENUM", SRV_NETCONNENUM, api_srv_net_conn_enum},
	{"NETSESSENUM", SRV_NETSESSENUM, api_srv_net_sess_enum},
	{"NETSHAREENUM", SRV_NETSHAREENUM, api_srv_net_share_enum},
	{"NETSHAREENUM2", SRV_NETSHAREENUM2, api_srv_net_share_enum},
	{"NETSHAREGETINFO", SRV_NETSHAREGETINFO, api_srv_net_share_get_info},
	{"NETSHAREADD", SRV_NETSHAREADD, api_srv_net_share_add},
	{"NETSHAREDEL", SRV_NETSHAREDEL, api_srv_net_share_del},
	{"NETFILEENUM", SRV_NETFILEENUM, api_srv_net_file_enum},
	{"NET_SRV_GET_INFO", SRV_NET_SRV_GET_INFO, api_srv_net_srv_get_info},
	{"NET_REMOTE_TOD", SRV_NET_REMOTE_TOD, api_srv_net_remote_tod},
	{NULL, 0, NULL}
};

/*******************************************************************
receives a srvsvc pipe and responds.
********************************************************************/
BOOL api_srvsvc_rpc(rpcsrv_struct * p)
{
	return api_rpcTNP(p, "api_srvsvc_rpc", api_srv_cmds);
}
