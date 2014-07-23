/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines for mdssvc
 *  Copyright (C) Ralph Boehme 2014
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
#include "mdssvc.h"
#include "ntdomain.h"
#include "../librpc/gen_ndr/srv_mdssvc.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

void _mdssvc_open(struct pipes_struct *p, struct mdssvc_open *r)
{
	DEBUG(10, ("%s\n", __func__));
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return;
}

void _mdssvc_unknown1(struct pipes_struct *p, struct mdssvc_unknown1 *r)
{
	DEBUG(10, ("%s\n", __func__));
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return;
}

void _mdssvc_cmd(struct pipes_struct *p, struct mdssvc_cmd *r)
{
	DEBUG(10, ("%s\n", __func__));
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;

	mds_dispatch();

	return;
}

void _mdssvc_close(struct pipes_struct *p, struct mdssvc_close *r)
{
	DEBUG(10, ("%s\n", __func__));
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return;
}
