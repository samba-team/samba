/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald (Jerry) Carter             2005.
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
#define DBGC_CLASS DBGC_RPC_PARSE

/*******************************************************************
********************************************************************/

BOOL ntsvcs_io_q_get_version(const char *desc, NTSVCS_Q_GET_VERSION *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "ntsvcs_io_q_get_version");
	depth++;

	/* there is nothing to parse in this PDU */

	return True;

}

/*******************************************************************
********************************************************************/

BOOL ntsvcs_io_r_get_version(const char *desc, NTSVCS_R_GET_VERSION *r_u, prs_struct *ps, int depth)
{
	if ( !r_u )
		return False;

	prs_debug(ps, depth, desc, "ntsvcs_io_r_get_version");
	depth++;

	if(!prs_align(ps))
		return False;
		
	if(!prs_uint32("version", ps, depth, &r_u->version))
		return False;
		
	if(!prs_ntstatus("status", ps, depth, &r_u->status))
		return False;

	return True;
}




