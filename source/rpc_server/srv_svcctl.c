/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2003.
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*******************************************************************
 ********************************************************************/

static BOOL api_svcctl_close_service(pipes_struct *p)
{
	SVCCTL_Q_CLOSE_SERVICE q_u;
	SVCCTL_R_CLOSE_SERVICE r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if(!svcctl_io_q_close_service("", &q_u, data, 0))
		return False;

	r_u.status = _svcctl_close_service(p, &q_u, &r_u);

	if(!svcctl_io_r_close_service("", &r_u, rdata, 0))
		return False;

	return True;
}

/*******************************************************************
 ********************************************************************/

static BOOL api_svcctl_open_scmanager(pipes_struct *p)
{
	SVCCTL_Q_OPEN_SCMANAGER q_u;
	SVCCTL_R_OPEN_SCMANAGER r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if(!svcctl_io_q_open_scmanager("", &q_u, data, 0))
		return False;

	r_u.status = _svcctl_open_scmanager(p, &q_u, &r_u);

	if(!svcctl_io_r_open_scmanager("", &r_u, rdata, 0))
		return False;

	return True;
}

/*******************************************************************
 ********************************************************************/

static BOOL api_svcctl_get_display_name(pipes_struct *p)
{
	SVCCTL_Q_GET_DISPLAY_NAME q_u;
	SVCCTL_R_GET_DISPLAY_NAME r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if(!svcctl_io_q_get_display_name("", &q_u, data, 0))
		return False;

	r_u.status = _svcctl_get_display_name(p, &q_u, &r_u);

	if(!svcctl_io_r_get_display_name("", &r_u, rdata, 0))
		return False;

	return True;
}


/*******************************************************************
 \PIPE\svcctl commands
 ********************************************************************/

static struct api_struct api_svcctl_cmds[] =
{
      { "SVCCTL_CLOSE_SERVICE"      , SVCCTL_CLOSE_SERVICE       , api_svcctl_close_service },
      { "SVCCTL_OPEN_SCMANAGER"     , SVCCTL_OPEN_SCMANAGER      , api_svcctl_open_scmanager },
      { "SVCCTL_GET_DISPLAY_NAME"   , SVCCTL_GET_DISPLAY_NAME    , api_svcctl_get_display_name }
};

void svcctl_get_pipe_fns( struct api_struct **fns, int *n_fns )
{
	*fns = api_svcctl_cmds;
	*n_fns = sizeof(api_svcctl_cmds) / sizeof(struct api_struct);
}

NTSTATUS rpc_svcctl_init(void)
{
  return rpc_pipe_register_commands(SMB_RPC_INTERFACE_VERSION, "svcctl", "ntsvcs", api_svcctl_cmds,
				    sizeof(api_svcctl_cmds) / sizeof(struct api_struct));
}
