/* 
   Unix SMB/CIFS implementation.
   Registry interface
   Copyright (C) Jelmer Vernooij					  2004.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "registry.h"
#include "system/dir.h"
#include "system/filesys.h"

static WERROR reg_dir_add_key(TALLOC_CTX *mem_ctx, const struct registry_key *parent, const char *name, uint32_t access_mask, struct security_descriptor *desc, struct registry_key **result)
{
	char *path;
	int ret;
	asprintf(&path, "%s%s\\%s", parent->hive->location, parent->path, name);
	path = reg_path_win2unix(path);
	ret = mkdir(path, 0700);
	SAFE_FREE(path);
	if(ret == 0)return WERR_OK; /* FIXME */
	return WERR_INVALID_PARAM;
}

static WERROR reg_dir_del_key(const struct registry_key *k, const char *name)
{
	char *child = talloc_asprintf(NULL, "%s/%s", (char *)k->backend_data, name);
	WERROR ret;

	if (rmdir(child) == 0) ret = WERR_OK; else ret = WERR_GENERAL_FAILURE;

	talloc_free(child);

	return ret;
}

static WERROR reg_dir_open_key(TALLOC_CTX *mem_ctx, const struct registry_key *p, const char *name, struct registry_key **subkey)
{
	DIR *d;
	char *fullpath, *unixpath;
	struct registry_key *ret;
	
	if(!name) {
		DEBUG(0, ("NULL pointer passed as directory name!"));
		return WERR_INVALID_PARAM;
	}

	
	fullpath = talloc_asprintf(mem_ctx, "%s/%s", (char *)p->backend_data, name);
	unixpath = reg_path_win2unix(fullpath);
	
	d = opendir(unixpath);
	if(!d) {
		DEBUG(3,("Unable to open '%s': %s\n", unixpath, strerror(errno)));
		return WERR_BADFILE;
	}
	closedir(d);
	ret = talloc(mem_ctx, struct registry_key);
	ret->hive = p->hive;
	ret->path = fullpath;
	ret->backend_data = unixpath;
	*subkey = ret;
	return WERR_OK;
}

static WERROR reg_dir_key_by_index(TALLOC_CTX *mem_ctx, const struct registry_key *k, int idx, struct registry_key **key)
{
	struct dirent *e;
	char *fullpath = k->backend_data;
	int i = 0;
	DIR *d;

	d = opendir(fullpath);

	if(!d) return WERR_INVALID_PARAM;
	
	while((e = readdir(d))) {
		if(!ISDOT(e->d_name) && !ISDOTDOT(e->d_name)) {
			struct stat stbuf;
			char *thispath;
			
			/* Check if file is a directory */
			asprintf(&thispath, "%s/%s", fullpath, e->d_name);
			stat(thispath, &stbuf);

			if(S_ISDIR(stbuf.st_mode)) {
				if(i == idx) {
					(*key) = talloc(mem_ctx, struct registry_key);
					(*key)->name = talloc_strdup(*key, e->d_name);
					(*key)->path = NULL;
					(*key)->backend_data = talloc_strdup(*key, thispath);
					SAFE_FREE(thispath);
					closedir(d);
					return WERR_OK;
				}
				i++;
			}

			SAFE_FREE(thispath);
		}
	}

	closedir(d);

	return WERR_NO_MORE_ITEMS;
}

static WERROR reg_dir_open(struct registry_hive *h, struct registry_key **key)
{
	if(!h->location) return WERR_INVALID_PARAM;

	*key = talloc(h, struct registry_key);
	(*key)->backend_data = talloc_strdup(*key, h->location);
	return WERR_OK;
}

static struct hive_operations reg_backend_dir = {
	.name = "dir",
	.open_hive = reg_dir_open,
	.open_key = reg_dir_open_key,
	.add_key = reg_dir_add_key,
	.del_key = reg_dir_del_key,
	.get_subkey_by_index = reg_dir_key_by_index
};

NTSTATUS registry_dir_init(void)
{
	return registry_register(&reg_backend_dir);
}
