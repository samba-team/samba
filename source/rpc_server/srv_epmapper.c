
/* 
   Unix SMB/CIFS implementation.
   Samba end point mapper utility and mapping functions
   Copyright (C) Jim McDonough (jmcd@us.ibm.com) 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/*****************************************************************
  api_handle_map_req - handles standard epm mapping request
******************************************************************/
static BOOL api_handle_map_req(pipes_struct * p)
{

	EPM_Q_MAP q_in;
	EPM_R_MAP q_out;

	prs_struct *in_data = &p->in_data.data;
	prs_struct *ret_data = &p->out_data.rdata;

	ZERO_STRUCT(q_in);
	ZERO_STRUCT(q_out);

	/* process input request and parse packet */

	if (!epm_io_q_map("", &q_in, in_data, 0)) {
		DEBUG(0,
		      ("api_handle_map_request: unable to unmarshall EPMD_MAP\n"));
		return False;
	}

	_epm_map(p, &q_in, &q_out);

	if (!epm_io_r_map("", &q_out, ret_data, 0)) {
		DEBUG(0,
		      ("api_handle_map_req: unable to marshall EPMD_MAP\n"));
		return False;
	}

	return True;
}

/*******************************************************************/
/*                  \pipe\epmapper commands                        */
/*******************************************************************/
/* opnum is 3 on map request */

struct api_struct api_epmapper_cmds[] = {
	{"MAP_PIPE_NAME", EPM_MAP_PIPE_NAME, api_handle_map_req},
};

/*******************************************************************/
/*                                                                 */
/*******************************************************************/

void epm_get_pipe_fns(struct api_struct **funcs, int *n_funcs)
{
	*funcs = api_epmapper_cmds;
	*n_funcs = sizeof(api_epmapper_cmds) / sizeof(struct api_struct);
}

/*******************************************************************/
/*                                                                 */
/*******************************************************************/

NTSTATUS rpc_epmapper_init(void)
{
	return rpc_pipe_register_commands(SMB_RPC_INTERFACE_VERSION,
					  EPM_PIPE_NM, EPM_PIPE_NM,
					  api_epmapper_cmds,
					  sizeof(api_epmapper_cmds) /
					  sizeof(struct api_struct));
}
