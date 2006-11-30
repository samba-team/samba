/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Volker Lendecke 2006
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

extern REGISTRY_OPS regdb_ops;		/* these are the default */

static int smbconf_fetch_keys( const char *key, REGSUBKEY_CTR *subkey_ctr )
{
	return regdb_ops.fetch_subkeys(key, subkey_ctr);
}

static BOOL smbconf_store_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	return regdb_ops.store_subkeys(key, subkeys);
}

static int smbconf_fetch_values( const char *key, REGVAL_CTR *val )
{
	return regdb_ops.fetch_values(key, val);
}

static BOOL smbconf_store_values( const char *key, REGVAL_CTR *val )
{
	return regdb_ops.store_values(key, val);
}

static BOOL smbconf_reg_access_check(const char *keyname, uint32 requested,
				     uint32 *granted,
				     const struct nt_user_token *token)
{
	if (!(user_has_privileges(token, &se_disk_operators))) {
		return False;
	}

	*granted = REG_KEY_ALL;
	return True;
}

static WERROR smbconf_get_secdesc(TALLOC_CTX *mem_ctx, const char *key,
				  struct security_descriptor **psecdesc)
{
	return regdb_ops.get_secdesc(mem_ctx, key, psecdesc);
}

static WERROR smbconf_set_secdesc(const char *key,
				  struct security_descriptor *secdesc)
{
	return regdb_ops.set_secdesc(key, secdesc);
}


/* 
 * Table of function pointers for accessing smb.conf data
 */
 
REGISTRY_OPS smbconf_reg_ops = {
	smbconf_fetch_keys,
	smbconf_fetch_values,
	smbconf_store_keys,
	smbconf_store_values,
	smbconf_reg_access_check,
	smbconf_get_secdesc,
	smbconf_set_secdesc
};
