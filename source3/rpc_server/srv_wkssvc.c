/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Anthony Liguori                   2003.
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

/* This is the interface to the wks pipe. */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*******************************************************************
 api_wks_query_info
 ********************************************************************/

static BOOL api_wks_query_info(pipes_struct *p)
{
	WKS_Q_QUERY_INFO q_u;
	WKS_R_QUERY_INFO r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* grab the net share enum */
	if(!wks_io_q_query_info("", &q_u, data, 0))
		return False;

	r_u.status = _wks_query_info(p, &q_u, &r_u);

	/* store the response in the SMB stream */
	if(!wks_io_r_query_info("", &r_u, rdata, 0))
		return False;

	return True;
}


/*******************************************************************
 \PIPE\wkssvc commands
 ********************************************************************/

#ifdef RPC_WKS_DYNAMIC
int rpc_pipe_init(void)
#else
int rpc_wks_init(void)
#endif
{
  static struct api_struct api_wks_cmds[] =
    {
      { "WKS_Q_QUERY_INFO", WKS_QUERY_INFO, api_wks_query_info }
    };
  return rpc_pipe_register_commands("wkssvc", "ntsvcs", api_wks_cmds,
				    sizeof(api_wks_cmds) / sizeof(struct api_struct));
}
