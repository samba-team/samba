/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
 *  Copyright (C) Michael Adam 2006
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

/* 
 * Implementation of registry frontend view functions. 
 * Functions moved from reg_frontend.c to minimize linker deps.
 */

#include "includes.h"


static struct generic_mapping reg_generic_map = 
	{ REG_KEY_READ, REG_KEY_WRITE, REG_KEY_EXECUTE, REG_KEY_ALL };

/********************************************************************
********************************************************************/

static SEC_DESC* construct_registry_sd( TALLOC_CTX *ctx )
{
	SEC_ACE ace[3];
	SEC_ACCESS mask;
	size_t i = 0;
	SEC_DESC *sd;
	SEC_ACL *acl;
	size_t sd_size;

	/* basic access for Everyone */
	
	init_sec_access(&mask, REG_KEY_READ );
	init_sec_ace(&ace[i++], &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);
	
	/* Full Access 'BUILTIN\Administrators' */
	
	init_sec_access(&mask, REG_KEY_ALL );
	init_sec_ace(&ace[i++], &global_sid_Builtin_Administrators, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	/* Full Access 'NT Authority\System' */

	init_sec_access(&mask, REG_KEY_ALL );
	init_sec_ace(&ace[i++], &global_sid_System, SEC_ACE_TYPE_ACCESS_ALLOWED, mask, 0);

	
	/* create the security descriptor */
	
	if ( !(acl = make_sec_acl(ctx, NT4_ACL_REVISION, i, ace)) )
		return NULL;

	if ( !(sd = make_sec_desc(ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL, acl, &sd_size)) )
		return NULL;

	return sd;
}

/***********************************************************************
 High level wrapper function for storing registry subkeys
 ***********************************************************************/
 
BOOL store_reg_keys( REGISTRY_KEY *key, REGSUBKEY_CTR *subkeys )
{
	if ( key->hook && key->hook->ops && key->hook->ops->store_subkeys )
		return key->hook->ops->store_subkeys( key->name, subkeys );
		
	return False;

}

/***********************************************************************
 High level wrapper function for storing registry values
 ***********************************************************************/
 
BOOL store_reg_values( REGISTRY_KEY *key, REGVAL_CTR *val )
{
	if ( check_dynamic_reg_values( key ) )
		return False;

	if ( key->hook && key->hook->ops && key->hook->ops->store_values )
		return key->hook->ops->store_values( key->name, val );

	return False;
}

/***********************************************************************
 High level wrapper function for enumerating registry subkeys
 Initialize the TALLOC_CTX if necessary
 ***********************************************************************/

int fetch_reg_keys( REGISTRY_KEY *key, REGSUBKEY_CTR *subkey_ctr )
{
	int result = -1;
	
	if ( key->hook && key->hook->ops && key->hook->ops->fetch_subkeys )
		result = key->hook->ops->fetch_subkeys( key->name, subkey_ctr );

	return result;
}

/***********************************************************************
 High level wrapper function for enumerating registry values
 ***********************************************************************/

int fetch_reg_values( REGISTRY_KEY *key, REGVAL_CTR *val )
{
	int result = -1;
	
	if ( key->hook && key->hook->ops && key->hook->ops->fetch_values )
		result = key->hook->ops->fetch_values( key->name, val );
	
	/* if the backend lookup returned no data, try the dynamic overlay */
	
	if ( result == 0 ) {
		result = fetch_dynamic_reg_values( key, val );

		return ( result != -1 ) ? result : 0;
	}
	
	return result;
}

/***********************************************************************
 High level access check for passing the required access mask to the 
 underlying registry backend
 ***********************************************************************/

BOOL regkey_access_check( REGISTRY_KEY *key, uint32 requested, uint32 *granted,
			  const struct nt_user_token *token )
{
	SEC_DESC *sec_desc;
	NTSTATUS status;
	WERROR err;
	TALLOC_CTX *mem_ctx;

	/* use the default security check if the backend has not defined its
	 * own */

	if (key->hook && key->hook->ops && key->hook->ops->reg_access_check) {
		return key->hook->ops->reg_access_check( key->name, requested,
							 granted, token );
	}

	/*
	 * The secdesc routines can't yet cope with a NULL talloc ctx sanely.
	 */

	if (!(mem_ctx = talloc_init("regkey_access_check"))) {
		return False;
	}

	err = regkey_get_secdesc(mem_ctx, key, &sec_desc);

	if (!W_ERROR_IS_OK(err)) {
		TALLOC_FREE(mem_ctx);
		return False;
	}

	se_map_generic( &requested, &reg_generic_map );

	if (!se_access_check(sec_desc, token, requested, granted, &status)) {
		TALLOC_FREE(mem_ctx);
		return False;
	}

	TALLOC_FREE(mem_ctx);
	return NT_STATUS_IS_OK(status);
}

WERROR regkey_get_secdesc(TALLOC_CTX *mem_ctx, REGISTRY_KEY *key,
			  struct security_descriptor **psecdesc)
{
	struct security_descriptor *secdesc;

	if (key->hook && key->hook->ops && key->hook->ops->get_secdesc) {
		WERROR err;

		err = key->hook->ops->get_secdesc(mem_ctx, key->name,
						  psecdesc);
		if (W_ERROR_IS_OK(err)) {
			return WERR_OK;
		}
	}

	if (!(secdesc = construct_registry_sd(mem_ctx))) {
		return WERR_NOMEM;
	}

	*psecdesc = secdesc;
	return WERR_OK;
}
