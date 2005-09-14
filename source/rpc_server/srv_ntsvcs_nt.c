/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *
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
#define DBGC_CLASS DBGC_RPC_SRV

/********************************************************************
********************************************************************/

static char* get_device_path( const char *device )
{
	static pstring path;

	pstr_sprintf( path, "ROOT\\Legacy_%s\\0000", device );

	return path;
}

/********************************************************************
********************************************************************/

WERROR _ntsvcs_get_version( pipes_struct *p, NTSVCS_Q_GET_VERSION *q_u, NTSVCS_R_GET_VERSION *r_u )
{
	r_u->version = 0x00000400;	/* no idea what this means */
		
	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _ntsvcs_get_device_list_size( pipes_struct *p, NTSVCS_Q_GET_DEVICE_LIST_SIZE *q_u, NTSVCS_R_GET_DEVICE_LIST_SIZE *r_u )
{
	fstring device;
	const char *devicepath;

	if ( !q_u->devicename )
		return WERR_ACCESS_DENIED;

	rpcstr_pull(device, q_u->devicename->buffer, sizeof(device), q_u->devicename->uni_str_len*2, 0);
	devicepath = get_device_path( device );

	r_u->size = strlen(devicepath) + 1;

	return WERR_OK;
}


/********************************************************************
********************************************************************/

WERROR _ntsvcs_get_device_list( pipes_struct *p, NTSVCS_Q_GET_DEVICE_LIST *q_u, NTSVCS_R_GET_DEVICE_LIST *r_u )
{
	fstring device;
	const char *devicepath;

	if ( !q_u->devicename )
		return WERR_ACCESS_DENIED;

	rpcstr_pull(device, q_u->devicename->buffer, sizeof(device), q_u->devicename->uni_str_len*2, 0);
	devicepath = get_device_path( device );

	/* From the packet traces I've see, I think this really should be an array
	   of UNISTR2's.  But I've never seen more than one string in spite of the 
	   fact that the string in dounel NULL terminated.  -- jerry */

	init_unistr2( &r_u->devicepath, devicepath, UNI_STR_TERMINATE );
	r_u->needed = r_u->devicepath.uni_str_len;

	return WERR_OK;
}

