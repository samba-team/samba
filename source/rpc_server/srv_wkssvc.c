
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
 api_wks_query_info
 ********************************************************************/
static void api_wks_query_info( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	WKS_Q_QUERY_INFO q_u;
	WKS_R_QUERY_INFO r_u;
	WKS_INFO_100 wks100;
	uint32 status;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* grab the net share enum */
	wks_io_q_query_info("", &q_u, data, 0);

	status = _wks_query_info(&q_u.uni_srv_name, q_u.switch_value, &wks100);
	make_wks_r_query_info(&r_u, q_u.switch_value, &wks100, status);

	/* store the response in the SMB stream */
	wks_io_r_query_info("", &r_u, rdata, 0);
}


/*******************************************************************
 \PIPE\wkssvc commands
 ********************************************************************/
struct api_struct api_wks_cmds[] =
{
	{ "WKS_Q_QUERY_INFO", WKS_QUERY_INFO, api_wks_query_info },
	{ NULL             , 0            , NULL }
};

/*******************************************************************
 receives a wkssvc pipe and responds.
 ********************************************************************/
BOOL api_wkssvc_rpc(rpcsrv_struct *p)
{
	return api_rpcTNP(p, "api_wkssvc_rpc", api_wks_cmds);
}

