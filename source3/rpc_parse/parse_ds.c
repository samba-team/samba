/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald Carter				2002
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

static BOOL ds_io_dominfobasic( const char *desc, prs_struct *ps, int depth, DSROLE_PRIMARY_DOMAIN_INFO_BASIC **basic)
{
	DSROLE_PRIMARY_DOMAIN_INFO_BASIC *p = *basic;
	
	if ( UNMARSHALLING(ps) )
		p = *basic = (DSROLE_PRIMARY_DOMAIN_INFO_BASIC *)prs_alloc_mem(ps, sizeof(DSROLE_PRIMARY_DOMAIN_INFO_BASIC));
		
	if ( !p )
		return False;
		
	if ( !prs_uint16("machine_role", ps, depth, &p->machine_role) )
		return False;
	if ( !prs_uint16("unknown", ps, depth, &p->unknown) )
		return False;

	if ( !prs_uint32("flags", ps, depth, &p->flags) )
		return False;

	if ( !prs_uint32("netbios_ptr", ps, depth, &p->netbios_ptr) )
		return False;
	if ( !prs_uint32("dnsname_ptr", ps, depth, &p->dnsname_ptr) )
		return False;
	if ( !prs_uint32("forestname_ptr", ps, depth, &p->forestname_ptr) )
		return False;
		
	if ( !prs_uint8s(False, "domain_guid", ps, depth, p->domain_guid.info, GUID_SIZE) )
		return False;
		
	if ( !smb_io_unistr2( "netbios_domain", &p->netbios_domain, p->netbios_ptr, ps, depth) )
		return False;
	if ( !prs_align(ps) )
		return False;
	
	if ( !smb_io_unistr2( "dns_domain", &p->dns_domain, p->dnsname_ptr, ps, depth) )
		return False;
	if ( !prs_align(ps) )
		return False;
	
	if ( !smb_io_unistr2( "forest_domain", &p->forest_domain, p->forestname_ptr, ps, depth) )
		return False;
	if ( !prs_align(ps) )
		return False;
	
		
	return True;
		
}

BOOL ds_io_q_getprimdominfo( const char *desc, DS_Q_GETPRIMDOMINFO *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "ds_io_q_getprimdominfo");
	depth++;

	if(!prs_align(ps))
		return False;

	if ( !prs_uint16( "level", ps, depth, &q_u->level ) )
		return False;
		
	return True;
}

BOOL ds_io_r_getprimdominfo( const char *desc, DS_R_GETPRIMDOMINFO *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "ds_io_r_getprimdominfo");
	depth++;

	if(!prs_align(ps))
		return False;

	if ( !prs_uint32( "ptr", ps, depth, &r_u->ptr ) )
		return False;
		
	if ( r_u->ptr )
	{
		if ( !prs_uint16( "level", ps, depth, &r_u->level ) )
			return False;
	
		if ( !prs_uint16( "unknown0", ps, depth, &r_u->unknown0 ) )
			return False;
		
		switch ( r_u->level )
		{
			case DsRolePrimaryDomainInfoBasic:
				if ( !ds_io_dominfobasic( "dominfobasic", ps, depth, &r_u->info.basic ) )
					return False;
				break;
			default:
				return False;
		}
	}

	if ( !prs_align(ps) )
		return False;
	
	if ( !prs_ntstatus("status", ps, depth, &r_u->status ) )
		return False;		
		
	return True;
}
