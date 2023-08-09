/*
 *  Unix SMB/CIFS implementation.
 *
 *  Copyright (C) 2023 Stefan Metzmacher
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
#include "librpc/rpc/dcesrv_core.h"
#include "librpc/gen_ndr/ndr_witness_scompat.h"
#include "rpc_server/rpc_server.h"

/****************************************************************
 _witness_GetInterfaceList
****************************************************************/

WERROR _witness_GetInterfaceList(struct pipes_struct *p,
				 struct witness_GetInterfaceList *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
 _witness_Register
****************************************************************/

WERROR _witness_Register(struct pipes_struct *p,
			 struct witness_Register *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _witness_UnRegister
****************************************************************/

WERROR _witness_UnRegister(struct pipes_struct *p,
			   struct witness_UnRegister *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
 _witness_AsyncNotify
****************************************************************/

WERROR _witness_AsyncNotify(struct pipes_struct *p,
			    struct witness_AsyncNotify *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
 _witness_RegisterEx
****************************************************************/

WERROR _witness_RegisterEx(struct pipes_struct *p,
			   struct witness_RegisterEx *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_witness_scompat.c"
