/*
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Volker Lendecke 2006
 *  Copyright (C) Michael Adam 2007
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
#define DBGC_CLASS DBGC_REGISTRY

extern REGISTRY_OPS regdb_ops;		/* these are the default */

static int smbconf_fetch_keys( const char *key, REGSUBKEY_CTR *subkey_ctr )
{
	return regdb_ops.fetch_subkeys(key, subkey_ctr);
}

static bool smbconf_store_keys( const char *key, REGSUBKEY_CTR *subkeys )
{
	return regdb_ops.store_subkeys(key, subkeys);
}

static int smbconf_fetch_values( const char *key, REGVAL_CTR *val )
{
	return regdb_ops.fetch_values(key, val);
}

static WERROR regval_hilvl_to_lolvl(TALLOC_CTX *mem_ctx, const char *valname,
				    struct registry_value *src,
				    REGISTRY_VALUE **dst)
{
	WERROR err;
	DATA_BLOB value_data;
	REGISTRY_VALUE *newval = NULL;

	if (dst == NULL) {
		return WERR_INVALID_PARAM;
	}

	err = registry_push_value(mem_ctx, src, &value_data);
	if (!W_ERROR_IS_OK(err)) {
		DEBUG(10, ("error calling registry_push_value.\n"));
		return err;
	}

	newval = regval_compose(mem_ctx, valname, src->type,
				(char *)value_data.data, value_data.length);
	if (newval == NULL) {
		DEBUG(10, ("error composing registry value. (no memory?)\n"));
		return WERR_NOMEM;
	}

	*dst = newval;
	return WERR_OK;
}

static WERROR regval_lolvl_to_hilvl(TALLOC_CTX *mem_ctx, REGISTRY_VALUE *src,
				    struct registry_value **dst)
{
	if (dst == NULL) {
		return WERR_INVALID_PARAM;
	}

	return registry_pull_value(mem_ctx, dst, regval_type(src),
				   regval_data_p(src), regval_size(src),
				   regval_size(src));
}

/*
 * Utility function used by smbconf_store_values to canonicalize
 * a registry value.
 * registry_pull_value / registry_push_value are used for (un)marshalling.
 */
static REGISTRY_VALUE *smbconf_canonicalize_regval(TALLOC_CTX *mem_ctx,
						   REGISTRY_VALUE *theval)
{
	char *valstr;
	size_t len;
	const char *canon_valname;
	const char *canon_valstr;
	bool inverse;
	struct registry_value *value;
	WERROR err;
	TALLOC_CTX *tmp_ctx;
	REGISTRY_VALUE *newval = NULL;

	if (!lp_parameter_is_valid(regval_name(theval)) ||
	    lp_parameter_is_canonical(regval_name(theval)))
	{
		return theval;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		DEBUG(1, ("out of memory...\n"));
		goto done;
	}

	err = regval_lolvl_to_hilvl(tmp_ctx, theval, &value);
	if (!W_ERROR_IS_OK(err)) {
		goto done;
	}

	/* we need the value-string zero-terminated */
	valstr = value->v.sz.str;
	len = value->v.sz.len;
	if (valstr[len - 1] != '\0') {
		DEBUG(10, ("string is not '\\0'-terminated. adding '\\0'.\n"));
		valstr = TALLOC_REALLOC_ARRAY(tmp_ctx, valstr, char, len + 1);
		if (valstr == NULL) {
			DEBUG(1, ("out of memory\n"));
			goto done;
		}
		valstr[len] = '\0';
	}

	if (!lp_canonicalize_parameter(regval_name(theval), &canon_valname,
				       &inverse))
	{
		DEBUG(5, ("Error: lp_canonicalize_parameter failed after "
			  "lp_parameter_is_valid. This should not happen!\n"));
		goto done;
	}
	DEBUG(10, ("old value name: '%s', canonical value name: '%s'\n",
		   regval_name(theval), canon_valname));
	if (inverse && lp_string_is_valid_boolean(valstr)) {
		lp_invert_boolean(valstr, &canon_valstr);
	} else {
		canon_valstr = valstr;
	}

	ZERO_STRUCTP(value);
	value->type = REG_SZ;
	value->v.sz.str = CONST_DISCARD(char *, canon_valstr);
	value->v.sz.len = strlen(canon_valstr) + 1;

	err = regval_hilvl_to_lolvl(mem_ctx, canon_valname, value, &newval);
	if (!W_ERROR_IS_OK(err)) {
		DEBUG(10, ("error calling regval_hilvl_to_lolvl.\n"));
		goto done;
	}

done:
	TALLOC_FREE(tmp_ctx);
	return newval;
}

static bool smbconf_store_values( const char *key, REGVAL_CTR *val )
{
	int i;
	int num_values = regval_ctr_numvals(val);
	REGVAL_CTR *new_val_ctr;

	/*
	 * we build a second regval container and copy over the values,
	 * possibly changing names to the canonical name, because when
	 * canonicalizing parameter names and replacing the original parameter
	 * (with reval_ctr_deletevalue and regval_ctr_addvalue) in the original
	 * container, the order would change and that is not so good in the
	 * "for" loop...  :-o
	 */
	new_val_ctr = TALLOC_ZERO_P(val, REGVAL_CTR);
	if (new_val_ctr == NULL) {
		DEBUG(1, ("out of memory\n"));
		return False;
	}

	for (i=0; i < num_values; i++) {
		REGISTRY_VALUE *theval = regval_ctr_specific_value(val, i);
		const char *valname = regval_name(theval);
		int res;

		DEBUG(10, ("inspecting value '%s'\n", valname));

		/* unfortunately, we can not reject names that are not
		 * valid parameter names here, since e.g. regedit first
		 * creates values as "New Value #1" and so on and then
		 * drops into rename. */

		if (regval_type(theval) != REG_SZ) {
			DEBUG(1, ("smbconf_store_values: only registry value "
			      "type REG_SZ currently allowed under key "
			      "smbconf\n"));
			return False;
		}

		if (registry_smbconf_valname_forbidden(valname)) {
			DEBUG(1, ("smbconf_store_values: value '%s' forbidden "
			      "in registry.\n", valname));
			return False;
		}

		if (lp_parameter_is_valid(valname) &&
		    !lp_parameter_is_canonical(valname))
		{
			DEBUG(5, ("valid parameter '%s' given but it is a "
				  "synonym. going to canonicalize it.\n",
				  valname));
			theval = smbconf_canonicalize_regval(val, theval);
			if (theval == NULL) {
				DEBUG(10, ("error canonicalizing registry "
					   "value\n"));
				return False;
			}
		} else {
			DEBUG(10, ("%s parameter found, "
				   "copying it to new container...\n",
				   (lp_parameter_is_valid(valname)?
				    "valid":"unknown")));
		}
		res = regval_ctr_copyvalue(new_val_ctr, theval);
		if (res == 0) {
			DEBUG(10, ("error calling regval_ctr_copyvalue. "
				   "(no memory?)\n"));
			return False;
		}
		DEBUG(10, ("parameter copied. container now has %d values.\n",
			   res));
	}
	return regdb_ops.store_values(key, new_val_ctr);
}

static bool smbconf_reg_access_check(const char *keyname, uint32 requested,
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
	.fetch_subkeys = smbconf_fetch_keys,
	.fetch_values = smbconf_fetch_values,
	.store_subkeys = smbconf_store_keys,
	.store_values = smbconf_store_values,
	.reg_access_check = smbconf_reg_access_check,
	.get_secdesc = smbconf_get_secdesc,
	.set_secdesc = smbconf_set_secdesc,
};
