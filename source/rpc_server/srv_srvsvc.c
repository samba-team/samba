
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
extern pstring global_myname;

/*******************************************************************
 fill in a file info level 3 structure.
 ********************************************************************/
static void make_srv_file_3_info(FILE_INFO_3     *fl3, FILE_INFO_3_STR *str3,
				uint32 fnum, uint32 perms, uint32 num_locks,
				char *path_name, char *user_name)
{
	make_srv_file_info3    (fl3 , fnum, perms, num_locks, path_name, user_name);
	make_srv_file_info3_str(str3, path_name, user_name);
}

/*******************************************************************
 fill in a file info level 3 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_file_info_3(SRV_FILE_INFO_3 *fl3, uint32 *fnum, uint32 *ftot)
{
	uint32 num_entries = 0;
	(*ftot) = 1;

	if (fl3 == NULL)
	{
		(*fnum) = 0;
		return;
	}

	DEBUG(5,("make_srv_file_3_fl3\n"));

	for (; (*fnum) < (*ftot) && num_entries < MAX_FILE_ENTRIES; (*fnum)++)
	{
		make_srv_file_3_info(&(fl3->info_3    [num_entries]),
			                 &(fl3->info_3_str[num_entries]),
		                     (*fnum), 0x35, 0, "\\PIPE\\samr", "dummy user");

		/* move on to creating next file */
		num_entries++;
	}

	fl3->num_entries_read  = num_entries;
	fl3->ptr_file_info     = num_entries > 0 ? 1 : 0;
	fl3->num_entries_read2 = num_entries;
	
	if ((*fnum) >= (*ftot))
	{
		(*fnum) = 0;
	}
}

/*******************************************************************
 makes a SRV_R_NET_FILE_ENUM structure.
********************************************************************/
static uint32 make_srv_file_info_ctr(SRV_FILE_INFO_CTR *ctr,
				int switch_value, uint32 *resume_hnd, uint32 *total_entries)  
{
	uint32 status = NT_STATUS_NOPROBLEMO;
	DEBUG(5,("make_srv_file_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value)
	{
		case 3:
		{
			make_srv_file_info_3(&(ctr->file.info3), resume_hnd, total_entries);
			ctr->ptr_file_ctr = 1;
			break;
		}
		default:
		{
			DEBUG(5,("make_srv_file_info_ctr: unsupported switch value %d\n",
			          switch_value));
			(*resume_hnd = 0);
			(*total_entries) = 0;
			ctr->ptr_file_ctr = 0;
			status = NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	}

	return status;
}

/*******************************************************************
 makes a SRV_R_NET_FILE_ENUM structure.
********************************************************************/
static void make_srv_r_net_file_enum(SRV_R_NET_FILE_ENUM *r_n,
				uint32 resume_hnd, int file_level, int switch_value)  
{
	DEBUG(5,("make_srv_r_net_file_enum: %d\n", __LINE__));

	r_n->file_level  = file_level;
	if (file_level == 0)
	{
		r_n->status = NT_STATUS_INVALID_INFO_CLASS;
	}
	else
	{
		r_n->status = make_srv_file_info_ctr(r_n->ctr, switch_value, &resume_hnd, &(r_n->total_entries));
	}
	if (r_n->status != NT_STATUS_NOPROBLEMO)
	{
		resume_hnd = 0;
	}
	make_enum_hnd(&(r_n->enum_hnd), resume_hnd);
}

/*******************************************************************
net file enum
********************************************************************/
static void srv_reply_net_file_enum(SRV_Q_NET_FILE_ENUM *q_n,
				prs_struct *rdata)
{
	SRV_R_NET_FILE_ENUM r_n;
	SRV_FILE_INFO_CTR ctr;

	r_n.ctr = &ctr;

	DEBUG(5,("srv_net_file_enum: %d\n", __LINE__));

	/* set up the */
	make_srv_r_net_file_enum(&r_n,
				get_enum_hnd(&q_n->enum_hnd),
				q_n->file_level,
				q_n->ctr->switch_value);

	/* store the response in the SMB stream */
	srv_io_r_net_file_enum("", &r_n, rdata, 0);

	DEBUG(5,("srv_net_file_enum: %d\n", __LINE__));
}

/*******************************************************************
********************************************************************/
static void api_srv_net_srv_get_info( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	SRV_Q_NET_SRV_GET_INFO q_n;
	SRV_R_NET_SRV_GET_INFO r_n;
	SRV_INFO_CTR ctr;
	uint32 status;

	ZERO_STRUCT(q_n);
	ZERO_STRUCT(r_n);

	/* grab the net server get info */
	srv_io_q_net_srv_get_info("", &q_n, data, 0);

	status = _srv_net_srv_get_info( &q_n.uni_srv_name, q_n.switch_value,
					&ctr );

        /* set up the net server get info structure */
        make_srv_r_net_srv_get_info(&r_n, q_n.switch_value, &ctr, status);

        /* store the response in the SMB stream */
        srv_io_r_net_srv_get_info("", &r_n, rdata, 0);
}


/*******************************************************************
********************************************************************/
static void api_srv_net_file_enum( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	SRV_Q_NET_FILE_ENUM q_n;
	SRV_FILE_INFO_CTR ctr;

	q_n.ctr = &ctr;

	/* grab the net file enum */
	srv_io_q_net_file_enum("", &q_n, data, 0);

	/* construct reply.  always indicate success */
	srv_reply_net_file_enum(&q_n, rdata);
}

/*******************************************************************
********************************************************************/
static void api_srv_net_conn_enum( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
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
	srv_io_q_net_conn_enum("", &q_n, data, 0);

	r_n.status = _srv_net_conn_enum( &q_n.uni_srv_name,
					ctr.switch_value, &ctr,
					q_n.preferred_len, &q_n.enum_hnd,
					&(r_n.total_entries),
					q_n.conn_level );

	memcpy(&r_n.enum_hnd, &q_n.enum_hnd, sizeof(r_n.enum_hnd));

	/* store the response in the SMB stream */
	srv_io_r_net_conn_enum("", &r_n, rdata, 0);
}

/*******************************************************************
********************************************************************/
static void api_srv_net_sess_enum( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	SRV_Q_NET_SESS_ENUM q_n;
	SRV_R_NET_SESS_ENUM r_n;
	SRV_SESS_INFO_CTR ctr;

	ZERO_STRUCT(q_n);
	ZERO_STRUCT(r_n);

	q_n.ctr = &ctr;
	r_n.ctr = &ctr;

	/* grab the net server get enum */
	srv_io_q_net_sess_enum("", &q_n, data, 0);

	r_n.sess_level = q_n.sess_level;

	r_n.status = _srv_net_sess_enum( &q_n.uni_srv_name,
					ctr.switch_value, &ctr,
					q_n.preferred_len, &q_n.enum_hnd,
					&(r_n.total_entries),
					q_n.sess_level );

        memcpy(&r_n.enum_hnd, &q_n.enum_hnd, sizeof(r_n.enum_hnd));

	/* store the response in the SMB stream */
	srv_io_r_net_sess_enum("", &r_n, rdata, 0);
}

/*******************************************************************
********************************************************************/
static void api_srv_net_share_enum( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
        SRV_Q_NET_SHARE_ENUM q_n;
	SRV_R_NET_SHARE_ENUM r_n;
        SRV_SHARE_INFO_CTR ctr;

	ZERO_STRUCT(q_n);
	ZERO_STRUCT(r_n);

        q_n.ctr = &ctr;
	r_n.ctr = &ctr;

        /* grab the net server get enum */
        srv_io_q_net_share_enum("", &q_n, data, 0);

	r_n.share_level = q_n.share_level;

	r_n.status = _srv_net_share_enum( &q_n.uni_srv_name, 
				ctr.switch_value, &ctr,
				q_n.preferred_len, &q_n.enum_hnd,
				&(r_n.total_entries),
				q_n.share_level );

	memcpy(&r_n.enum_hnd, &q_n.enum_hnd, sizeof(r_n.enum_hnd));

	/* store the response in the SMB stream */
	srv_io_r_net_share_enum("", &r_n, rdata, 0);
}

/*******************************************************************
********************************************************************/
static void api_srv_net_remote_tod( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
        SRV_Q_NET_REMOTE_TOD q_n;
        SRV_R_NET_REMOTE_TOD r_n;
        TIME_OF_DAY_INFO tod;
	uint32 status;

	ZERO_STRUCT(q_n);
	ZERO_STRUCT(r_n);

	/* grab the net server get enum */
	srv_io_q_net_remote_tod("", &q_n, data, 0);

	status = _srv_net_remote_tod( &q_n.uni_srv_name, &tod );

	r_n.tod = &tod;
	r_n.ptr_srv_tod = 0x1;
	r_n.status = status;

	/* store the response in the SMB stream */
	srv_io_r_net_remote_tod("", &r_n, rdata, 0);
}


/*******************************************************************
\PIPE\srvsvc commands
********************************************************************/
struct api_struct api_srv_cmds[] =
{
	{ "SRV_NETCONNENUM"     , SRV_NETCONNENUM     , api_srv_net_conn_enum    },
	{ "SRV_NETSESSENUM"     , SRV_NETSESSENUM     , api_srv_net_sess_enum    },
	{ "SRV_NETSHAREENUM"    , SRV_NETSHAREENUM    , api_srv_net_share_enum   },
	{ "SRV_NETSHAREENUM2"   , SRV_NETSHAREENUM2   , api_srv_net_share_enum   },
	{ "SRV_NETFILEENUM"     , SRV_NETFILEENUM     , api_srv_net_file_enum    },
	{ "SRV_NET_SRV_GET_INFO", SRV_NET_SRV_GET_INFO, api_srv_net_srv_get_info },
	{ "SRV_NET_REMOTE_TOD"  , SRV_NET_REMOTE_TOD  , api_srv_net_remote_tod   },
	{ NULL                  , 0                   , NULL                     }
};

/*******************************************************************
receives a srvsvc pipe and responds.
********************************************************************/
BOOL api_srvsvc_rpc(rpcsrv_struct *p)
{
	return api_rpcTNP(p, "api_srvsvc_rpc", api_srv_cmds);
}

