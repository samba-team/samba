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

static WERROR reg_dir_add_key(REG_KEY *parent, const char *name, uint32 access_mask, SEC_DESC *desc, REG_KEY **result)
{
	char *path;
	int ret;
	asprintf(&path, "%s%s\\%s", parent->handle->location, reg_key_get_path(parent), name);
	path = reg_path_win2unix(path);
	ret = mkdir(path, 0700);
	SAFE_FREE(path);
	if(ret == 0)return WERR_OK; /* FIXME */
	return WERR_INVALID_PARAM;
}

static WERROR reg_dir_del_key(REG_KEY *k)
{
	return (rmdir((char *)k->backend_data) == 0)?WERR_OK:WERR_GENERAL_FAILURE;
}

static WERROR reg_dir_open_key(REG_HANDLE *h, int hive, const char *name, REG_KEY **subkey)
{
	DIR *d;
	char *fullpath;
	REG_KEY *ret;
	TALLOC_CTX *mem_ctx;
	
	if(hive != 0) return WERR_NO_MORE_ITEMS;
	
	if(!name) {
		DEBUG(0, ("NULL pointer passed as directory name!"));
		return WERR_INVALID_PARAM;
	}

	
	mem_ctx = talloc_init("tmp");
	fullpath = talloc_asprintf(mem_ctx, "%s%s", h->location, name);
	fullpath = reg_path_win2unix(fullpath);
	
	d = opendir(fullpath);
	if(!d) {
		DEBUG(3,("Unable to open '%s': %s\n", fullpath, strerror(errno)));
		talloc_destroy(mem_ctx);
		return WERR_BADFILE;
	}
	closedir(d);
	ret = reg_key_new_abs(name, h, fullpath);
	talloc_steal(mem_ctx, ret->mem_ctx, fullpath);
	talloc_destroy(mem_ctx);
	*subkey = ret;
	return WERR_OK;
}

static WERROR reg_dir_fetch_subkeys(REG_KEY *k, int *count, REG_KEY ***r)
{
	struct dirent *e;
	int max = 200;
	char *fullpath = k->backend_data;
	REG_KEY **ar;
	DIR *d;
	(*count) = 0;
	ar = talloc(k->mem_ctx, sizeof(REG_KEY *) * max);

	d = opendir(fullpath);

	if(!d) return WERR_INVALID_PARAM;
	
	while((e = readdir(d))) {
		if( strcmp(e->d_name, ".") &&
		   strcmp(e->d_name, "..")) {
			struct stat stbuf;
			char *thispath;
			
			/* Check if file is a directory */
			asprintf(&thispath, "%s/%s", fullpath, e->d_name);
			stat(thispath, &stbuf);

			if(S_ISDIR(stbuf.st_mode)) {
				ar[(*count)] = reg_key_new_rel(e->d_name, k, NULL);
				ar[(*count)]->backend_data = talloc_strdup(ar[*count]->mem_ctx, thispath);
				if(ar[(*count)])(*count)++;

				if((*count) == max) {
					max+=200;
					ar = realloc(ar, sizeof(REG_KEY *) * max);
				}
			}

			SAFE_FREE(thispath);
		}
	}

	closedir(d);

	*r = ar;
	return WERR_OK;
}

static WERROR reg_dir_open(REG_HANDLE *h, const char *loc, const char *credentials) {
	if(!loc) return WERR_INVALID_PARAM;
	return WERR_OK;
}

static WERROR reg_dir_add_value(REG_KEY *p, const char *name, int type, void *data, int len)
{
	/* FIXME */
	return WERR_NOT_SUPPORTED;
}

static WERROR reg_dir_get_hive(REG_HANDLE *h, int hive, REG_KEY **key)
{
	if(hive != 0) return WERR_NO_MORE_ITEMS;
	*key = reg_key_new_abs("", h, NULL);
	(*key)->backend_data = talloc_strdup((*key)->mem_ctx, h->location);
	return WERR_OK;
}

static WERROR reg_dir_del_value(REG_VAL *v)
{
	/* FIXME*/
	return WERR_NOT_SUPPORTED;
}

static struct registry_ops reg_backend_dir = {
	.name = "dir",
	.open_registry = reg_dir_open,
	.open_key = reg_dir_open_key,
	.get_hive = reg_dir_get_hive,
	.fetch_subkeys = reg_dir_fetch_subkeys,
	.add_key = reg_dir_add_key,
	.del_key = reg_dir_del_key,
	.add_value = reg_dir_add_value,
	.del_value = reg_dir_del_value,
};

NTSTATUS registry_dir_init(void)
{
	return register_backend("registry", &reg_backend_dir);
}
