/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald (Jerry) Carter             2005.
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
#define DBGC_CLASS DBGC_RPC_PARSE

/*******************************************************************
********************************************************************/

bool ntsvcs_io_q_get_device_list(const char *desc, NTSVCS_Q_GET_DEVICE_LIST *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "ntsvcs_io_q_get_device_list");
	depth++;
	
	if(!prs_align(ps))
		return False;

	if ( !prs_pointer("devicename", ps, depth, (void*)&q_u->devicename, sizeof(UNISTR2), (PRS_POINTER_CAST)prs_io_unistr2) )
		return False;
	if( !prs_align(ps) )
		return False;
		
	if ( !prs_uint32("buffer_size", ps, depth, &q_u->buffer_size) )
		return False;
	if ( !prs_uint32("flags", ps, depth, &q_u->flags) )
		return False;
	
	return True;

}

/*******************************************************************
********************************************************************/

bool ntsvcs_io_r_get_device_list(const char *desc, NTSVCS_R_GET_DEVICE_LIST *r_u, prs_struct *ps, int depth)
{
	if ( !r_u )
		return False;

	prs_debug(ps, depth, desc, "ntsvcs_io_r_get_device_list_size");
	depth++;

	if(!prs_align(ps))
		return False;
		
	if ( !prs_io_unistr2("devicepath", ps, depth, &r_u->devicepath) )
		return False;
	if(!prs_align(ps))
		return False;
		
	if(!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}
