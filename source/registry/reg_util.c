/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer (utility functions)
 *  Copyright (C) Gerald Carter                     2002-2005
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

/* Implementation of registry frontend view functions. */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/***********************************************************************
 Utility function for splitting the base path of a registry path off
 by setting base and new_path to the apprapriate offsets withing the
 path.
 
 WARNING!!  Does modify the original string!
 ***********************************************************************/

BOOL reg_split_path( char *path, char **base, char **new_path )
{
	char *p;
	
	*new_path = *base = NULL;
	
	if ( !path)
		return False;
	
	*base = path;
	
	p = strchr( path, '\\' );
	
	if ( p ) {
		*p = '\0';
		*new_path = p+1;
	}
	
	return True;
}


/***********************************************************************
 Utility function for splitting the base path of a registry path off
 by setting base and new_path to the appropriate offsets withing the
 path.
 
 WARNING!!  Does modify the original string!
 ***********************************************************************/

BOOL reg_split_key( char *path, char **base, char **key )
{
	char *p;
	
	*key = *base = NULL;
	
	if ( !path)
		return False;
	
	*base = path;
	
	p = strrchr( path, '\\' );
	
	if ( p ) {
		*p = '\0';
		*key = p+1;
	}
	
	return True;
}


/**********************************************************************
 The full path to the registry key is used as database after the 
 \'s are converted to /'s.  Key string is also normalized to UPPER
 case. 
**********************************************************************/

void normalize_reg_path( pstring keyname )
{
	pstring_sub( keyname, "\\", "/" );
	strupper_m( keyname  );
}

