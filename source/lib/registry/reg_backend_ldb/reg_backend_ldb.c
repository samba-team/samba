/* 
   Unix SMB/CIFS implementation.
   Registry interface
   Copyright (C) Jelmer Vernooij					  2004.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/registry/common/registry.h"

static char *reg_path_to_ldb(TALLOC_CTX *mem_ctx, const char *path)
{
	char *ret = talloc_strdup(mem_ctx, "(dn=");
	char *begin = (char *)path;
	char *end = NULL;

	while(begin) {
		end = strchr(begin, '\\');
		if(end)end = '\0';
		if(end - begin != 0) ret = talloc_asprintf_append(mem_ctx, ret, "key=%s,", begin);
			
		if(end) {
			*end = '\\';
			begin = end+1;
		} else begin = NULL;
	}

	ret[strlen(ret)-1] = ')';
	return ret;
}

/* 
 * Saves the dn as private_data for every key/val
 */

static WERROR ldb_open_registry(REG_HANDLE *handle, const char *location, const char *credentials)
{
	struct ldb_context *c;
	c = ldb_connect(location, 0, NULL);

	if(!c) return WERR_FOOBAR;

	handle->backend_data = c;
	
	return WERR_OK;
}

static WERROR ldb_close_registry(REG_HANDLE *h) 
{
	ldb_close((struct ldb_context *)h->backend_data);
	return WERR_OK;
}

static WERROR ldb_fetch_subkeys(REG_KEY *k, int *count, REG_KEY ***subkeys)
{
	struct ldb_context *c = k->handle->backend_data;
	char *path;
	struct ldb_message **msg;
	char *ldap_path;
	TALLOC_CTX *mem_ctx = talloc_init("ldb_path");
	REG_KEY *key = NULL;
	ldap_path = reg_path_to_ldb(mem_ctx, reg_key_get_path(k));
	
	if(ldb_search(c, NULL, LDB_SCOPE_ONELEVEL, ldap_path, NULL,&msg) > 0) {
		key = reg_key_new_abs(reg_key_get_path(k), k->handle, ldap_path);
		talloc_steal(mem_ctx, key->mem_ctx, ldap_path);
		/* FIXME */
	}

	ldb_search_free(c, msg);
	talloc_destroy(mem_ctx);
	return WERR_OK;
}



static WERROR ldb_open_key(REG_HANDLE *h, const char *name, REG_KEY **key)
{
	struct ldb_context *c = h->backend_data;
	char *path;
	struct ldb_message **msg;
	char *ldap_path;
	TALLOC_CTX *mem_ctx = talloc_init("ldb_path");
	ldap_path = reg_path_to_ldb(mem_ctx, name);
	
	if(ldb_search(c, NULL, LDB_SCOPE_BASE, ldap_path, NULL,&msg) > 0) {
		*key = reg_key_new_abs(name, h, ldap_path);
		talloc_steal(mem_ctx, (*key)->mem_ctx, ldap_path);
		/* FIXME */
	}

	ldb_search_free(c, msg);
	talloc_destroy(mem_ctx);

	return WERR_OK;;
}

static struct registry_ops reg_backend_ldb = {
	.name = "ldb",
	.open_registry = ldb_open_registry,
	.close_registry = ldb_close_registry,
	.open_key = ldb_open_key,
	.fetch_subkeys = ldb_fetch_subkeys,
};

NTSTATUS registry_ldb_init(void)
{
	return register_backend("registry", &reg_backend_ldb);
}
