/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Marcin Krzysztof Porwit    2005,
 *  Copyright (C) Brian Moran                2005.
 *  Copyright (C) Gerald (Jerry) Carter      2005.
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


/**********************************************************************
 for an eventlog, add in the default values
*********************************************************************/

BOOL eventlog_init_keys( void )
{
	/* Find all of the eventlogs, add keys for each of them */
	const char **elogs = lp_eventlog_list(  );
	pstring evtlogpath;
	REGSUBKEY_CTR *subkeys;
	REGVAL_CTR *values;
	uint32 uiDisplayNameId;
	uint32 uiMaxSize;
	uint32 uiRetention;
	uint32 uiCategoryCount;
	UNISTR2 data;

	while ( elogs && *elogs ) {
		if ( !( subkeys = TALLOC_ZERO_P( NULL, REGSUBKEY_CTR ) ) ) {
			DEBUG( 0, ( "talloc() failure!\n" ) );
			return False;
		}
		regdb_fetch_keys( KEY_EVENTLOG, subkeys );
		regsubkey_ctr_addkey( subkeys, *elogs );
		if ( !regdb_store_keys( KEY_EVENTLOG, subkeys ) )
			return False;
		TALLOC_FREE( subkeys );

		/* add in the key of form KEY_EVENTLOG/Application */
		DEBUG( 5,
		       ( "Adding key of [%s] to path of [%s]\n", *elogs,
			 KEY_EVENTLOG ) );

		slprintf( evtlogpath, sizeof( evtlogpath ) - 1, "%s\\%s",
			  KEY_EVENTLOG, *elogs );
		/* add in the key of form KEY_EVENTLOG/Application/Application */
		DEBUG( 5,
		       ( "Adding key of [%s] to path of [%s]\n", *elogs,
			 evtlogpath ) );
		if ( !( subkeys = TALLOC_ZERO_P( NULL, REGSUBKEY_CTR ) ) ) {
			DEBUG( 0, ( "talloc() failure!\n" ) );
			return False;
		}
		regdb_fetch_keys( evtlogpath, subkeys );
		regsubkey_ctr_addkey( subkeys, *elogs );

		if ( !regdb_store_keys( evtlogpath, subkeys ) )
			return False;
		TALLOC_FREE( subkeys );

		/* now add the values to the KEY_EVENTLOG/Application form key */
		if ( !( values = TALLOC_ZERO_P( NULL, REGVAL_CTR ) ) ) {
			DEBUG( 0, ( "talloc() failure!\n" ) );
			return False;
		}
		DEBUG( 5,
		       ( "Storing values to eventlog path of [%s]\n",
			 evtlogpath ) );
		regdb_fetch_values( evtlogpath, values );

		if ( !regval_ctr_key_exists( values, "MaxSize" ) ) {
			/* assume we have none, add them all */

			/* hard code some initial values */

			uiDisplayNameId = 0x00000100;
			uiMaxSize = 0x00080000;
			uiRetention = 0x93A80;

			regval_ctr_addvalue( values, "MaxSize", REG_DWORD,
					     ( char * ) &uiMaxSize,
					     sizeof( uint32 ) );
			regval_ctr_addvalue( values, "Retention", REG_DWORD,
					     ( char * ) &uiRetention,
					     sizeof( uint32 ) );
			init_unistr2( &data, *elogs, UNI_STR_TERMINATE );
			regval_ctr_addvalue( values, "PrimaryModule", REG_SZ,
					     ( char * ) data.buffer,
					     data.uni_str_len *
					     sizeof( uint16 ) );
			init_unistr2( &data, *elogs, UNI_STR_TERMINATE );

			regval_ctr_addvalue( values, "Sources", REG_MULTI_SZ,
					     ( char * ) data.buffer,
					     data.uni_str_len *
					     sizeof( uint16 ) );
			regdb_store_values( evtlogpath, values );

		}

		TALLOC_FREE( values );

		/* now do the values under KEY_EVENTLOG/Application/Application */
		slprintf( evtlogpath, sizeof( evtlogpath ) - 1, "%s\\%s\\%s",
			  KEY_EVENTLOG, *elogs, *elogs );
		if ( !( values = TALLOC_ZERO_P( NULL, REGVAL_CTR ) ) ) {
			DEBUG( 0, ( "talloc() failure!\n" ) );
			return False;
		}
		DEBUG( 5,
		       ( "Storing values to eventlog path of [%s]\n",
			 evtlogpath ) );
		regdb_fetch_values( evtlogpath, values );
		if ( !regval_ctr_key_exists( values, "CategoryCount" ) ) {

			/* hard code some initial values */

			uiCategoryCount = 0x00000007;
			regval_ctr_addvalue( values, "CategoryCount",
					     REG_DWORD,
					     ( char * ) &uiCategoryCount,
					     sizeof( uint32 ) );
			init_unistr2( &data,
				      "%SystemRoot%\\system32\\eventlog.dll",
				      UNI_STR_TERMINATE );

			regval_ctr_addvalue( values, "CategoryMessageFile",
					     REG_EXPAND_SZ,
					     ( char * ) data.buffer,
					     data.uni_str_len *
					     sizeof( uint16 ) );
			regdb_store_values( evtlogpath, values );
		}
		TALLOC_FREE( values );
		elogs++;
	}
	return True;
}
