
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1999,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
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
 create_brs_info_100
 ********************************************************************/
static void create_brs_info_100(BRS_INFO_100 *inf)
{
	DEBUG(5,("create_brs_info_100: %d\n", __LINE__));

	make_brs_info_100(inf);
}

/*******************************************************************
 brs_reply_query_info
 
 only supports info level 100 at the moment.

 ********************************************************************/
static void brs_reply_query_info(BRS_Q_QUERY_INFO *q_u,
				prs_struct *rdata,
				int status)
{
	BRS_R_QUERY_INFO r_u;
	BRS_INFO_100 brs100;

	DEBUG(5,("brs_query_info: %d\n", __LINE__));

	create_brs_info_100(&brs100);
	make_brs_r_query_info(&r_u, q_u->switch_value1, &brs100, status);

	/* store the response in the SMB stream */
	brs_io_r_query_info("", &r_u, rdata, 0);

	DEBUG(5,("brs_query_info: %d\n", __LINE__));
}

/*******************************************************************
 api_brs_query_info
 ********************************************************************/
static void api_brs_query_info( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	BRS_Q_QUERY_INFO q_u;

	/* grab the net share enum */
	brs_io_q_query_info("", &q_u, data, 0);

	/* construct reply.  always indicate success */
	brs_reply_query_info(&q_u, rdata, 0x0);
}


/*******************************************************************
 \PIPE\brssvc commands
 ********************************************************************/
struct api_struct api_brs_cmds[] =
{
	{ "BRS_Q_QUERY_INFO", BRS_QUERY_INFO, api_brs_query_info },
	{ NULL             , 0            , NULL }
};

/*******************************************************************
 receives a browser pipe and responds.
 ********************************************************************/
BOOL api_brs_rpc(rpcsrv_struct *p, prs_struct *data)
{
	return api_rpcTNP(p, "api_brssvc_rpc", api_brs_cmds, data);
}

