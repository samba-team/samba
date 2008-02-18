/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald Carter                   2005.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*******************************************************************
 ********************************************************************/

static bool proxy_ntsvcs_call(pipes_struct *p, uint8_t opnum)
{
	struct api_struct *fns;
	int n_fns;

	ntsvcs_get_pipe_fns(&fns, &n_fns);

	if (opnum >= n_fns) {
		return false;
	}

	if (fns[opnum].opnum != opnum) {
		smb_panic("NTSVCS function table not sorted");
	}

	return fns[opnum].fn(p);
}

/*******************************************************************
 ********************************************************************/

static bool api_ntsvcs_get_version(pipes_struct *p)
{
	return proxy_ntsvcs_call(p, NDR_PNP_GETVERSION);
}

/*******************************************************************
 ********************************************************************/

static bool api_ntsvcs_get_device_list_size(pipes_struct *p)
{
	return proxy_ntsvcs_call(p, NDR_PNP_GETDEVICELISTSIZE);
}

/*******************************************************************
 ********************************************************************/

static bool api_ntsvcs_get_device_list(pipes_struct *p)
{
	NTSVCS_Q_GET_DEVICE_LIST q_u;
	NTSVCS_R_GET_DEVICE_LIST r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if(!ntsvcs_io_q_get_device_list("", &q_u, data, 0))
		return False;

	r_u.status = _ntsvcs_get_device_list(p, &q_u, &r_u);

	if(!ntsvcs_io_r_get_device_list("", &r_u, rdata, 0))
		return False;

	return True;
}

/*******************************************************************
 ********************************************************************/

static bool api_ntsvcs_validate_device_instance(pipes_struct *p)
{
	return proxy_ntsvcs_call(p, NDR_PNP_VALIDATEDEVICEINSTANCE);
}

/*******************************************************************
 ********************************************************************/

static bool api_ntsvcs_get_device_reg_property(pipes_struct *p)
{
	NTSVCS_Q_GET_DEVICE_REG_PROPERTY q_u;
	NTSVCS_R_GET_DEVICE_REG_PROPERTY r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if(!ntsvcs_io_q_get_device_reg_property("", &q_u, data, 0))
		return False;

	r_u.status = _ntsvcs_get_device_reg_property(p, &q_u, &r_u);

	if(!ntsvcs_io_r_get_device_reg_property("", &r_u, rdata, 0))
		return False;

	return True;
}

/*******************************************************************
 ********************************************************************/

static bool api_ntsvcs_get_hw_profile_info(pipes_struct *p)
{
	return proxy_ntsvcs_call(p, NDR_PNP_GETHWPROFINFO);
}

/*******************************************************************
 ********************************************************************/

static bool api_ntsvcs_hw_profile_flags(pipes_struct *p)
{
	return proxy_ntsvcs_call(p, NDR_PNP_HWPROFFLAGS);
}

/*******************************************************************
 \PIPE\svcctl commands
 ********************************************************************/

static struct api_struct api_ntsvcs_cmds[] =
{
      { "NTSVCS_GET_VERSION"              , NTSVCS_GET_VERSION              , api_ntsvcs_get_version },
      { "NTSVCS_GET_DEVICE_LIST_SIZE"     , NTSVCS_GET_DEVICE_LIST_SIZE     , api_ntsvcs_get_device_list_size },
      { "NTSVCS_GET_DEVICE_LIST"          , NTSVCS_GET_DEVICE_LIST          , api_ntsvcs_get_device_list },
      { "NTSVCS_VALIDATE_DEVICE_INSTANCE" , NTSVCS_VALIDATE_DEVICE_INSTANCE , api_ntsvcs_validate_device_instance },
      { "NTSVCS_GET_DEVICE_REG_PROPERTY"  , NTSVCS_GET_DEVICE_REG_PROPERTY  , api_ntsvcs_get_device_reg_property },
      { "NTSVCS_GET_HW_PROFILE_INFO"      , NTSVCS_GET_HW_PROFILE_INFO      , api_ntsvcs_get_hw_profile_info },
      { "NTSVCS_HW_PROFILE_FLAGS"         , NTSVCS_HW_PROFILE_FLAGS         , api_ntsvcs_hw_profile_flags }
};


void ntsvcs2_get_pipe_fns( struct api_struct **fns, int *n_fns )
{
	*fns = api_ntsvcs_cmds;
	*n_fns = sizeof(api_ntsvcs_cmds) / sizeof(struct api_struct);
}

NTSTATUS rpc_ntsvcs2_init(void)
{
  return rpc_pipe_register_commands(SMB_RPC_INTERFACE_VERSION, "ntsvcs", "ntsvcs", api_ntsvcs_cmds,
				    sizeof(api_ntsvcs_cmds) / sizeof(struct api_struct));
}
