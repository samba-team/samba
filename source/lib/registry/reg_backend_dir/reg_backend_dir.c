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

static BOOL reg_dir_add_key(REG_KEY *parent, const char *name)
{
	char *path;
	int ret;
	asprintf(&path, "%s%s\\%s", parent->handle->location, reg_key_get_path(parent), name);
	path = reg_path_win2unix(path);
	ret = mkdir(path, 0700);
	free(path);
	return (ret == 0);
}

static BOOL reg_dir_del_key(REG_KEY *k)
{
	return (rmdir((char *)k->backend_data) == 0);
}

static REG_KEY *reg_dir_open_key(REG_HANDLE *h, const char *name)
{
	DIR *d;
	char *fullpath;
	if(!name) {
		DEBUG(0, ("NULL pointer passed as directory name!"));
		return NULL;
	}
	asprintf(&fullpath, "%s%s", h->location, name);
	fullpath = reg_path_win2unix(fullpath);
	
	d = opendir(fullpath);
	if(!d) {
		DEBUG(3,("Unable to open '%s': %s\n", fullpath, strerror(errno)));
		SAFE_FREE(fullpath);
		return NULL;
	}
	closedir(d);
	
	return reg_key_new_abs(name, h, fullpath);
}

static BOOL reg_dir_fetch_subkeys(REG_KEY *k, int *count, REG_KEY ***r)
{
	struct dirent *e;
	int max = 200;
	char *fullpath = k->backend_data;
	REG_KEY **ar;
	DIR *d;
	(*count) = 0;
	ar = malloc(sizeof(REG_KEY *) * max);

	d = opendir(fullpath);

	if(!d) return False;
	
	while((e = readdir(d))) {
		if(e->d_type == DT_DIR && 
		   strcmp(e->d_name, ".") &&
		   strcmp(e->d_name, "..")) {
			char *newfullpath;
			asprintf(&newfullpath, "%s/%s", fullpath, e->d_name);
			ar[(*count)] = reg_key_new_rel(e->d_name, k, newfullpath);
			if(ar[(*count)])(*count)++;

			if((*count) == max) {
				max+=200;
				ar = realloc(ar, sizeof(REG_KEY *) * max);
			}
		}
	}

	closedir(d);
	
	*r = ar;
	return True;
}

static BOOL reg_dir_open(REG_HANDLE *h, const char *loc, BOOL try) {
	if(!loc) return False;
	return True;
}

static void dir_free(REG_KEY *k) 
{
	free(k->backend_data);
}

static REG_VAL *reg_dir_add_value(REG_KEY *p, const char *name, int type, void *data, int len)
{
	REG_VAL *ret = reg_val_new(p, NULL);
	char *fullpath;
	FILE *fd;
	ret->name = name?strdup(name):NULL;
	fullpath = reg_path_win2unix(strdup(reg_val_get_path(ret)));
	
	fd = fopen(fullpath, "w+");
	
	/* FIXME */
	return NULL;
}

static BOOL reg_dir_del_value(REG_VAL *v)
{
	/* FIXME*/
	return False;
}

static REG_OPS reg_backend_dir = {
	.name = "dir",
	.open_registry = reg_dir_open,
	.open_key = reg_dir_open_key,
	.fetch_subkeys = reg_dir_fetch_subkeys,
	.add_key = reg_dir_add_key,
	.del_key = reg_dir_del_key,
	.add_value = reg_dir_add_value,
	.del_value = reg_dir_del_value,
	.free_key_backend_data = dir_free
};

NTSTATUS reg_dir_init(void)
{
	return register_backend("registry", &reg_backend_dir);
}
