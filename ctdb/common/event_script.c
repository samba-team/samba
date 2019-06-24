/*
   Low level event script handling

   Copyright (C) Amitay Isaacs  2017
   Copyright (C) Martin Schwenke  2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"
#include "system/dir.h"
#include "system/glob.h"

#include <talloc.h>

#include "common/event_script.h"

static int script_filter(const struct dirent *de)
{
	int ret;

	/* Match a script pattern */
	ret = fnmatch("[0-9][0-9].*.script", de->d_name, 0);
	if (ret == 0) {
		return 1;
	}

	return 0;
}

int event_script_get_list(TALLOC_CTX *mem_ctx,
			  const char *script_dir,
			  struct event_script_list **out)
{
	struct dirent **namelist = NULL;
	struct event_script_list *script_list = NULL;
	size_t ds_len;
	int count, ret;
	int i;

	count = scandir(script_dir, &namelist, script_filter, alphasort);
	if (count == -1) {
		ret = errno;
		goto done;
	}

	script_list = talloc_zero(mem_ctx, struct event_script_list);
	if (script_list == NULL) {
		goto nomem;
	}

	if (count == 0) {
		ret = 0;
		*out = script_list;
		goto done;
	}

	script_list->num_scripts = count;
	script_list->script = talloc_zero_array(script_list,
						struct event_script *,
						count);
	if (script_list->script == NULL) {
		goto nomem;
	}

	ds_len = strlen(".script");
	for (i = 0; i < count; i++) {
		struct event_script *s;
		struct stat statbuf;

		s = talloc_zero(script_list->script, struct event_script);
		if (s == NULL) {
			goto nomem;
		}

		script_list->script[i] = s;

		s->name = talloc_strndup(script_list->script,
					 namelist[i]->d_name,
					 strlen(namelist[i]->d_name) - ds_len);
		if (s->name == NULL) {
			goto nomem;
		}

		s->path = talloc_asprintf(script_list->script,
					  "%s/%s",
					  script_dir,
					  namelist[i]->d_name);
		if (s->path == NULL) {
			goto nomem;
		}

		ret = stat(s->path, &statbuf);
		if (ret == 0) {
			/*
			 * If ret != 0 this is either a dangling
			 * symlink or it has just disappeared.  Either
			 * way, it isn't executable.  See the note
			 * below about things that have disappeared.
			 */
			if (statbuf.st_mode & S_IXUSR) {
				s->enabled = true;
			}
		}
	}

	*out = script_list;
	ret = 0;
	goto done;

nomem:
	ret = ENOMEM;
	talloc_free(script_list);

done:
	if (namelist != NULL && count != -1) {
		for (i=0; i<count; i++) {
			free(namelist[i]);
		}
		free(namelist);
	}

	return ret;
}

int event_script_chmod(const char *script_dir,
		       const char *script_name,
		       bool enable)
{
	const char *dot_script = ".script";
	size_t ds_len = strlen(dot_script);
	size_t sn_len = strlen(script_name);
	DIR *dirp;
	struct dirent *de;
	char buf[PATH_MAX];
	const char *script_file;
	int ret, new_mode;
	char filename[PATH_MAX];
	struct stat st;
	bool found;
	ino_t found_inode;
	int fd = -1;

	/* Allow script_name to already have ".script" suffix */
	if (sn_len > ds_len &&
	    strcmp(&script_name[sn_len - ds_len], dot_script) == 0) {
		script_file = script_name;
	} else {
		ret = snprintf(buf, sizeof(buf), "%s.script", script_name);
		if (ret < 0 || (size_t)ret >= sizeof(buf)) {
			return ENAMETOOLONG;
		}
		script_file = buf;
	}

	dirp = opendir(script_dir);
	if (dirp == NULL) {
		return errno;
	}

	found = false;
	while ((de = readdir(dirp)) != NULL) {
		if (strcmp(de->d_name, script_file) == 0) {
			/* check for valid script names */
			ret = script_filter(de);
			if (ret == 0) {
				closedir(dirp);
				return EINVAL;
			}

			found = true;
			found_inode = de->d_ino;
			break;
		}
	}
	closedir(dirp);

	if (! found) {
		return ENOENT;
	}

	ret = snprintf(filename,
		       sizeof(filename),
		       "%s/%s",
		       script_dir,
		       script_file);
	if (ret < 0 || (size_t)ret >= sizeof(filename)) {
		return ENAMETOOLONG;
	}

	fd = open(filename, O_RDWR);
	if (fd == -1) {
		ret = errno;
		goto done;
	}

	ret = fstat(fd, &st);
	if (ret != 0) {
		ret = errno;
		goto done;
	}

	/*
	 * If the directory entry inode number doesn't match the one
	 * returned by fstat() then this is probably a symlink, so the
	 * caller should not be calling this function.  Note that this
	 * is a cheap sanity check to catch most programming errors.
	 * This doesn't cost any extra system calls but can still miss
	 * the unlikely case where the symlink is to a file on a
	 * different filesystem with the same inode number as the
	 * symlink.
	 */
	if (found && found_inode != st.st_ino) {
		ret = EINVAL;
		goto done;
	}

	if (enable) {
		new_mode = st.st_mode | (S_IXUSR | S_IXGRP | S_IXOTH);
	} else {
		new_mode = st.st_mode & ~(S_IXUSR | S_IXGRP | S_IXOTH);
	}

	ret = fchmod(fd, new_mode);
	if (ret != 0) {
		ret = errno;
		goto done;
	}

done:
	if (fd != -1) {
		close(fd);
	}
	return ret;
}
