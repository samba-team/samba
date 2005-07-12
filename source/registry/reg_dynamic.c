/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
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

struct reg_dyn_values {
	const char *path;
	int (*fetch_values) ( REGVAL_CTR *val );
};

/***********************************************************************
***********************************************************************/

static int netlogon_params( REGVAL_CTR *regvals )
{
	uint32 dwValue;
	
	if ( !account_policy_get(AP_REFUSE_MACHINE_PW_CHANGE, &dwValue) )
		dwValue = 0;
		
	regval_ctr_addvalue( regvals, "RefusePasswordChange", REG_DWORD,
		(char*)&dwValue, sizeof(dwValue) );

	return regval_ctr_numvals( regvals );
}

/***********************************************************************
***********************************************************************/

static int prod_options( REGVAL_CTR *regvals )
{
	const char              *value_ascii = "";
	fstring                 value;
	int                     value_length;
	
	switch (lp_server_role()) {
		case ROLE_DOMAIN_PDC:
		case ROLE_DOMAIN_BDC:
			value_ascii = "LanmanNT";
			break;
		case ROLE_STANDALONE:
			value_ascii = "ServerNT";
			break;
		case ROLE_DOMAIN_MEMBER:
			value_ascii = "WinNT";
			break;
	}
		
	value_length = push_ucs2( value, value, value_ascii, sizeof(value), 
		STR_TERMINATE|STR_NOALIGN );
	regval_ctr_addvalue( regvals, "ProductType", REG_SZ, value, 
		value_length );
	
	return regval_ctr_numvals( regvals );
}

/***********************************************************************
***********************************************************************/

static int tcpip_params( REGVAL_CTR *regvals )
{
	fstring                 value;
	int                     value_length;
	char   			*hname;
	fstring 		mydomainname;
	

	hname = myhostname();
	value_length = push_ucs2( value, value, hname, sizeof(value), STR_TERMINATE|STR_NOALIGN);		
	regval_ctr_addvalue( regvals, "Hostname",REG_SZ, value, value_length );
	
	get_mydnsdomname( mydomainname );		
	value_length = push_ucs2( value, value, mydomainname, sizeof(value), STR_TERMINATE|STR_NOALIGN);		
	regval_ctr_addvalue( regvals, "Domain", REG_SZ, value, value_length );
		
	return regval_ctr_numvals( regvals );
}


/***********************************************************************
 Structure holding the registry paths and pointers to the value 
 enumeration functions
***********************************************************************/

static struct reg_dyn_values dynamic_values[] = {
	{ "HKLM/SYSTEM/CURRENTCONTROLSET/SERVICES/NETLOGON/PARAMETERS", &netlogon_params  },
	{ "HKLM/SYSTEM/CURRENTCONTROLSET/CONTROL/PRODUCTOPTIONS",       &prod_options     },
	{ "HKLM/SYSTEM/CURRENTCONTROLSET/SERVICES/TCPIP/PARAMETERS",    &tcpip_params     },
	{ NULL, NULL }
};

/***********************************************************************
***********************************************************************/

int fetch_dynamic_reg_values( REGISTRY_KEY *key, REGVAL_CTR *val )
{
	int i;
	pstring path;
	
	pstrcpy( path, key->name );
	normalize_reg_path( path );
	
	for ( i=0; dynamic_values[i].path; i++ ) {
		if ( strcmp( path, dynamic_values[i].path ) == 0 )
			return dynamic_values[i].fetch_values( val );
	}
	
	return -1;
}

/***********************************************************************
***********************************************************************/

BOOL check_dynamic_reg_values( REGISTRY_KEY *key )
{
	int i;
	pstring path;
	
	pstrcpy( path, key->name );
	normalize_reg_path( path );
	
	for ( i=0; dynamic_values[i].path; i++ ) {
		/* can't write to dynamic keys */
		if ( strcmp( path, dynamic_values[i].path ) == 0 )
			return True;
	}
	
	return False;
}

