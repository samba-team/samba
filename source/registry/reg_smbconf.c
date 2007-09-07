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

		if (registry_smbconf_valname_forbidden(regval_name(theval))) {
			DEBUG(1, ("smbconf_store_values: value '%s' forbidden "
			      "in registry.\n", valname));
			return False;
		}

		if (lp_parameter_is_valid(valname) &&
		    !lp_parameter_is_canonical(valname))
		{
			char *valstr;
			size_t len;
			const char *canon_valname;
			const char *canon_valstr;
			BOOL inverse;
			struct registry_value *value;
			WERROR err;
			DATA_BLOB value_data;
			TALLOC_CTX *mem_ctx;

			DEBUG(5, ("valid parameter '%s' given but it is a "
				  "synonym. going to canonicalize it.\n",
				  valname));

			mem_ctx = talloc_new(val);
			if (mem_ctx == NULL) {
				DEBUG(1, ("out of memory...\n"));
				return False;
			}

			err = registry_pull_value(mem_ctx, &value,
						  theval->type,
						  theval->data_p,
						  theval->size,
						  theval->size);
			if (!W_ERROR_IS_OK(err)) {
				TALLOC_FREE(mem_ctx);
				return False;
			}

			valstr = (value->v.sz.str);
			len = value->v.sz.len;
			if (valstr[len - 1] != '\0') {
				DEBUG(10, ("string is not '\\0'-terminated. "
				      "adding '\\0'.\n"));
				valstr = TALLOC_REALLOC_ARRAY(mem_ctx, valstr,
							      char, len + 1);
				if (valstr == NULL) {
					DEBUG(1, ("out of memory\n"));
					TALLOC_FREE(mem_ctx);
					return False;
				}
				valstr[len] = '\0';
				len++;
			}

			if (!lp_canonicalize_parameter(valname, &canon_valname,
						       &inverse))
			{
				DEBUG(5, ("Error: lp_canonicalize_parameter "
				      "failed after lp_parameter_is_valid. "
				      "This should not happen!\n"));
				TALLOC_FREE(mem_ctx);
				return False;
			}
			DEBUG(10, ("old value name: '%s', canonical value "
				   "name: '%s'\n", valname, canon_valname));
			if (inverse && lp_string_is_valid_boolean(valstr)) {
				lp_invert_boolean(valstr, &canon_valstr);
			} else {
				canon_valstr = valstr;
			}

			ZERO_STRUCTP(value);

			value->type = REG_SZ;
			value->v.sz.str = CONST_DISCARD(char *, canon_valstr);
			value->v.sz.len = strlen(canon_valstr) + 1;

			err = registry_push_value(mem_ctx, value, &value_data);
			if (!W_ERROR_IS_OK(err)) {
				DEBUG(10, ("error calling registry_push_value."
				      "\n"));
				TALLOC_FREE(mem_ctx);
				return False;
			}

			DEBUG(10, ("adding canonicalized parameter to "
				   "container.\n"));

			theval = regval_compose(mem_ctx, canon_valname,
						value->type,
						(char *)value_data.data,
						value_data.length);
			if (theval == NULL) {
				DEBUG(10, ("error composing registry value. "
					   "(no memory?)\n"));
				TALLOC_FREE(mem_ctx);
				return False;
			}
			res = regval_ctr_copyvalue(new_val_ctr, theval);
			if (res == 0) {
				DEBUG(10, ("error calling regval_ctr_addvalue. "
				      "(no memory?)\n"));
				TALLOC_FREE(mem_ctx);
				return False;
			}
			DEBUG(10, ("parameter added. container now has %d "
				   "values.\n", res));

			TALLOC_FREE(mem_ctx);
		} else {
			DEBUG(10, ("%s parameter found, "
				   "copying it to new container...\n",
				   (lp_parameter_is_valid(valname)?
				    "valid":"unknown")));
			res = regval_ctr_copyvalue(new_val_ctr, theval);
			if (res == 0) {
				DEBUG(10, ("error calling regval_ctr_copyvalue."
					   " (no memory?)\n"));
				return False;
			}
			DEBUG(10, ("parameter copied. container now has %d "
				   "values.\n", res));
		}
	}
	return regdb_ops.store_values(key, new_val_ctr);
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
