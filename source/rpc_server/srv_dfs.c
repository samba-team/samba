/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines for Dfs
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Shirish Kalele               2000.
 *  Copyright (C) Jeremy Allison				2001.
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

/* This is the interface to the dfs pipe. */

#include "includes.h"
#include "nterr.h"

#define MAX_MSDFS_JUNCTIONS 256

extern pstring global_myname;

#ifdef WITH_MSDFS

/**********************************************************************
 api_dfs_exist
 **********************************************************************/

static BOOL api_dfs_exist(pipes_struct *p)
{
	DFS_Q_DFS_EXIST q_u;
	DFS_R_DFS_EXIST r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	if(!dfs_io_q_dfs_exist("", &q_u, data, 0))
		return False;
	
	r_u.status = _dfs_exist(p, &q_u, &r_u);
	
	if (!dfs_io_r_dfs_exist("", &r_u, rdata, 0))
		return False;

	return True;
}

/*****************************************************************
 api_dfs_add
 *****************************************************************/

static BOOL api_dfs_add(pipes_struct *p)
{
	DFS_Q_DFS_ADD q_u;
	DFS_R_DFS_ADD r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	if(!dfs_io_q_dfs_add("", &q_u, data, 0))
		return False;
	
	r_u.status = _dfs_add(p, &q_u, &r_u);
	
	if (!dfs_io_r_dfs_add("", &r_u, rdata, 0))
		return False;
	
	return True;
}

/*****************************************************************
 api_dfs_remove
 *****************************************************************/

static BOOL api_dfs_remove(pipes_struct *p)
{
	DFS_Q_DFS_REMOVE q_u;
	DFS_R_DFS_REMOVE r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	if(!dfs_io_q_dfs_remove("", &q_u, data, 0))
		return False;
	
	r_u.status = _dfs_remove(p, &q_u, &r_u);
	
	if (!dfs_io_r_dfs_remove("", &r_u, rdata, 0))
		return False;
	
	return True;
}

/*******************************************************************
 api_dfs_get_info
 *******************************************************************/

static BOOL api_dfs_get_info(pipes_struct *p)
{
	DFS_Q_DFS_GET_INFO q_u;
	DFS_R_DFS_GET_INFO r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	if(!dfs_io_q_dfs_get_info("", &q_u, data, 0))
		return False;
	
	r_u.status = _dfs_get_info(p, &q_u, &r_u);
	
	if(!dfs_io_r_dfs_get_info("", &r_u, rdata, 0))
		return False;

	return True;
}

/*******************************************************************
 api_dfs_enum
 *******************************************************************/

static BOOL api_dfs_enum(pipes_struct *p)
{
	DFS_Q_DFS_ENUM q_u;
	DFS_R_DFS_ENUM r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if(!dfs_io_q_dfs_enum("", &q_u, data, 0))
		return False;
	
	r_u.status = _dfs_enum(p, &q_u, &r_u);
	
	if(!dfs_io_r_dfs_enum("", &r_u, rdata, 0))
		return False;

	return True;
}

/*******************************************************************
\pipe\netdfs commands
********************************************************************/

struct api_struct api_netdfs_cmds[] =
{
	{"DFS_EXIST",        DFS_EXIST,               api_dfs_exist    },
	{"DFS_ADD",          DFS_ADD,                 api_dfs_add      },
	{"DFS_REMOVE",       DFS_REMOVE,              api_dfs_remove   },
	{"DFS_GET_INFO",     DFS_GET_INFO,            api_dfs_get_info },
	{"DFS_ENUM",         DFS_ENUM,                api_dfs_enum     },
	{NULL,               0,                       NULL             }
};

/*******************************************************************
receives a netdfs pipe and responds.
********************************************************************/

BOOL api_netdfs_rpc(pipes_struct *p)
{
	return api_rpcTNP(p, "api_netdfs_rpc", api_netdfs_cmds);
}

#else

 void dfs_dummy(void) {;} /* So some compilers don't complain. */

#endif
