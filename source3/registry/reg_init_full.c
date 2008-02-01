/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
 *  Copyright (C) Michael Adam                      2008
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

/* Initialize the registry with all available backends. */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

extern REGISTRY_OPS printing_ops;
extern REGISTRY_OPS eventlog_ops;
extern REGISTRY_OPS shares_reg_ops;
extern REGISTRY_OPS smbconf_reg_ops;
extern REGISTRY_OPS netlogon_params_reg_ops;
extern REGISTRY_OPS prod_options_reg_ops;
extern REGISTRY_OPS tcpip_params_reg_ops;
extern REGISTRY_OPS hkpt_params_reg_ops;
extern REGISTRY_OPS current_version_reg_ops;
extern REGISTRY_OPS perflib_reg_ops;
extern REGISTRY_OPS regdb_ops;		/* these are the default */

/* array of REGISTRY_HOOK's which are read into a tree for easy access */
/* #define REG_TDB_ONLY		1 */

REGISTRY_HOOK reg_hooks[] = {
#ifndef REG_TDB_ONLY 
  { KEY_PRINTING,    		&printing_ops },
  { KEY_PRINTING_2K, 		&printing_ops },
  { KEY_PRINTING_PORTS, 	&printing_ops },
  { KEY_SHARES,      		&shares_reg_ops },
  { KEY_SMBCONF,      		&smbconf_reg_ops },
  { KEY_NETLOGON_PARAMS,	&netlogon_params_reg_ops },
  { KEY_PROD_OPTIONS,		&prod_options_reg_ops },
  { KEY_TCPIP_PARAMS,		&tcpip_params_reg_ops },
  { KEY_HKPT,			&hkpt_params_reg_ops },
  { KEY_CURRENT_VERSION,	&current_version_reg_ops },
  { KEY_PERFLIB,		&perflib_reg_ops },
#endif
  { NULL, NULL }
};

/***********************************************************************
 Open the registry database and initialize the REGISTRY_HOOK cache
 with all available backens.
 ***********************************************************************/
 
bool init_registry( void )
{
	int i;
	bool ret = false;
	TALLOC_CTX *frame = talloc_stackframe();
	
	
	if ( !regdb_init() ) {
		DEBUG(0,("init_registry: failed to initialize the registry tdb!\n"));
		goto fail;
	}

	/* build the cache tree of registry hooks */
	
	reghook_cache_init();
	
	for ( i=0; reg_hooks[i].keyname; i++ ) {
		if ( !reghook_cache_add(&reg_hooks[i]) )
			goto fail;
	}

	if ( DEBUGLEVEL >= 20 )
		reghook_dump_cache(20);

	/* add any keys for other services */

	svcctl_init_keys();
	eventlog_init_keys();
	perfcount_init_keys();

	/* close and let each smbd open up as necessary */

	regdb_close();

	ret = true;
 fail:
	TALLOC_FREE(frame);
	return ret;
}
