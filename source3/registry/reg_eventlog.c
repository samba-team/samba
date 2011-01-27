
/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Marcin Krzysztof Porwit    2005,
 *  Copyright (C) Brian Moran                2005.
 *  Copyright (C) Gerald (Jerry) Carter      2005.
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
#include "registry.h"
#include "reg_backend_db.h"
#include "reg_eventlog.h"
#include "reg_objects.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

/**********************************************************************
 for an eventlog, add in the default values
*********************************************************************/

bool eventlog_init_keys(void)
{
	/* Find all of the eventlogs, add keys for each of them */
	const char **elogs = lp_eventlog_list();
	char *evtlogpath = NULL;
	char *evtfilepath = NULL;
	struct regsubkey_ctr *subkeys;
	struct regval_ctr *values;
	uint32 uiMaxSize;
	uint32 uiRetention;
	uint32 uiCategoryCount;
	DATA_BLOB data;
	TALLOC_CTX *ctx = talloc_tos();
	WERROR werr;

	while (elogs && *elogs) {
		werr = regsubkey_ctr_init(ctx, &subkeys);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG( 0, ( "talloc() failure!\n" ) );
			return False;
		}
		regdb_fetch_keys(KEY_EVENTLOG, subkeys);
		regsubkey_ctr_addkey( subkeys, *elogs );
		if ( !regdb_store_keys( KEY_EVENTLOG, subkeys ) ) {
			TALLOC_FREE(subkeys);
			return False;
		}
		TALLOC_FREE(subkeys);

		/* add in the key of form KEY_EVENTLOG/Application */
		DEBUG( 5,
		       ( "Adding key of [%s] to path of [%s]\n", *elogs,
			 KEY_EVENTLOG ) );

		evtlogpath = talloc_asprintf(ctx, "%s\\%s",
			  KEY_EVENTLOG, *elogs);
		if (!evtlogpath) {
			return false;
		}
		/* add in the key of form KEY_EVENTLOG/Application/Application */
		DEBUG( 5,
		       ( "Adding key of [%s] to path of [%s]\n", *elogs,
			 evtlogpath ) );
		werr = regsubkey_ctr_init(ctx, &subkeys);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG( 0, ( "talloc() failure!\n" ) );
			return False;
		}
		regdb_fetch_keys( evtlogpath, subkeys );
		regsubkey_ctr_addkey( subkeys, *elogs );

		if ( !regdb_store_keys( evtlogpath, subkeys ) ) {
			TALLOC_FREE(subkeys);
			return False;
		}
		TALLOC_FREE( subkeys );

		/* now add the values to the KEY_EVENTLOG/Application form key */

		werr = regval_ctr_init(ctx, &values);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG( 0, ( "talloc() failure!\n" ) );
			return False;
		}
		DEBUG( 5,
		       ( "Storing values to eventlog path of [%s]\n",
			 evtlogpath ) );
		regdb_fetch_values( evtlogpath, values );


		if (!regval_ctr_key_exists(values, "MaxSize")) {

			/* assume we have none, add them all */

			/* hard code some initial values */

			/* uiDisplayNameId = 0x00000100; */
			uiMaxSize = 0x00080000;
			uiRetention = 0x93A80;

			regval_ctr_addvalue(values, "MaxSize", REG_DWORD,
					     (uint8 *)&uiMaxSize,
					     sizeof(uint32));

			regval_ctr_addvalue(values, "Retention", REG_DWORD,
					     (uint8 *)&uiRetention,
					     sizeof(uint32));

			regval_ctr_addvalue_sz(values, "PrimaryModule", *elogs);
			push_reg_sz(talloc_tos(), &data, *elogs);

			regval_ctr_addvalue(values, "Sources", REG_MULTI_SZ,
					     data.data,
					     data.length);

			evtfilepath = talloc_asprintf(ctx,
					"%%SystemRoot%%\\system32\\config\\%s.tdb",
					*elogs);
			if (!evtfilepath) {
				TALLOC_FREE(values);
			}
			push_reg_sz(talloc_tos(), &data, evtfilepath);
			regval_ctr_addvalue(values, "File", REG_EXPAND_SZ, data.data,
					     data.length);
			regdb_store_values(evtlogpath, values);

		}

		TALLOC_FREE(values);

		/* now do the values under KEY_EVENTLOG/Application/Application */
		TALLOC_FREE(evtlogpath);
		evtlogpath = talloc_asprintf(ctx, "%s\\%s\\%s",
			  KEY_EVENTLOG, *elogs, *elogs);
		if (!evtlogpath) {
			return false;
		}

		werr = regval_ctr_init(ctx, &values);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG( 0, ( "talloc() failure!\n" ) );
			return False;
		}
		DEBUG( 5,
		       ( "Storing values to eventlog path of [%s]\n",
			 evtlogpath));
		regdb_fetch_values(evtlogpath, values);
		if (!regval_ctr_key_exists( values, "CategoryCount")) {

			/* hard code some initial values */

			uiCategoryCount = 0x00000007;
			regval_ctr_addvalue( values, "CategoryCount",
					     REG_DWORD,
					     (uint8 *) &uiCategoryCount,
					     sizeof( uint32 ) );
			push_reg_sz(talloc_tos(), &data,
				      "%SystemRoot%\\system32\\eventlog.dll");

			regval_ctr_addvalue( values, "CategoryMessageFile",
					     REG_EXPAND_SZ,
					     data.data,
					     data.length);
			regdb_store_values( evtlogpath, values );
		}
		TALLOC_FREE(values);
		elogs++;
	}

	return true;
}
