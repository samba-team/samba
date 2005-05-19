/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines for unixinfo-pipe
 *  Copyright (C) Volker Lendecke 2005
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

/* This is the interface to the rpcunixinfo pipe. */

#include "includes.h"
#include "nterr.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static BOOL api_sid_to_uid(pipes_struct *p)
{
	UNIXINFO_Q_SID_TO_UID q_u;
	UNIXINFO_R_SID_TO_UID r_u;

	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!unixinfo_io_q_unixinfo_sid_to_uid("", &q_u, data, 0))
		return False;

	r_u.status = _unixinfo_sid_to_uid(p, &q_u, &r_u);

	if (!unixinfo_io_r_unixinfo_sid_to_uid("", &r_u, rdata, 0))
		return False;

	return True;
}

static BOOL api_uid_to_sid(pipes_struct *p)
{
	UNIXINFO_Q_UID_TO_SID q_u;
	UNIXINFO_R_UID_TO_SID r_u;

	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!unixinfo_io_q_unixinfo_uid_to_sid("", &q_u, data, 0))
		return False;

	r_u.status = _unixinfo_uid_to_sid(p, &q_u, &r_u);

	if (!unixinfo_io_r_unixinfo_uid_to_sid("", &r_u, rdata, 0))
		return False;

	return True;
}

static BOOL api_sid_to_gid(pipes_struct *p)
{
	UNIXINFO_Q_SID_TO_GID q_u;
	UNIXINFO_R_SID_TO_GID r_u;

	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!unixinfo_io_q_unixinfo_sid_to_gid("", &q_u, data, 0))
		return False;

	r_u.status = _unixinfo_sid_to_gid(p, &q_u, &r_u);

	if (!unixinfo_io_r_unixinfo_sid_to_gid("", &r_u, rdata, 0))
		return False;

	return True;
}

static BOOL api_gid_to_sid(pipes_struct *p)
{
	UNIXINFO_Q_GID_TO_SID q_u;
	UNIXINFO_R_GID_TO_SID r_u;

	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!unixinfo_io_q_unixinfo_gid_to_sid("", &q_u, data, 0))
		return False;

	r_u.status = _unixinfo_gid_to_sid(p, &q_u, &r_u);

	if (!unixinfo_io_r_unixinfo_gid_to_sid("", &r_u, rdata, 0))
		return False;

	return True;
}

static BOOL api_getpwuid(pipes_struct *p)
{
	UNIXINFO_Q_GETPWUID q_u;
	UNIXINFO_R_GETPWUID r_u;

	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!unixinfo_io_q_unixinfo_getpwuid("", &q_u, data, 0))
		return False;

	r_u.status = _unixinfo_getpwuid(p, &q_u, &r_u);

	if (!unixinfo_io_r_unixinfo_getpwuid("", &r_u, rdata, 0))
		return False;

	return True;
}

/*******************************************************************
\pipe\unixinfo commands
********************************************************************/

struct api_struct api_unixinfo_cmds[] = {
	{"SID_TO_UID",       UNIXINFO_SID_TO_UID,     api_sid_to_uid },
	{"UID_TO_SID",       UNIXINFO_UID_TO_SID,     api_uid_to_sid },
	{"SID_TO_GID",       UNIXINFO_SID_TO_GID,     api_sid_to_gid },
	{"GID_TO_SID",       UNIXINFO_GID_TO_SID,     api_gid_to_sid },
	{"GETPWUID",         UNIXINFO_GETPWUID,       api_getpwuid },
};


void unixinfo_get_pipe_fns( struct api_struct **fns, int *n_fns )
{
	*fns = api_unixinfo_cmds;
	*n_fns = sizeof(api_unixinfo_cmds) / sizeof(struct api_struct);
}

NTSTATUS rpc_unixinfo_init(void)
{
	return rpc_pipe_register_commands(SMB_RPC_INTERFACE_VERSION,
		"unixinfo", "unixinfo", api_unixinfo_cmds,
		sizeof(api_unixinfo_cmds) / sizeof(struct api_struct));
}
