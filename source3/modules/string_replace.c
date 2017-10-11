/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Volker Lendecke, 2005
 * Copyright (C) Aravind Srinivasan, 2009
 * Copyright (C) Guenter Kukkukk, 2013
 * Copyright (C) Ralph Boehme, 2017
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "string_replace.h"

#define MAP_SIZE        0xFF
#define MAP_NUM         0x101 /* max unicode charval / MAP_SIZE */
#define T_OFFSET(_v_)   ((_v_ % MAP_SIZE))
#define T_START(_v_)    (((_v_ / MAP_SIZE) * MAP_SIZE))
#define T_PICK(_v_)     ((_v_ / MAP_SIZE))

struct char_mappings {
	smb_ucs2_t entry[MAP_SIZE][2];
};

static bool build_table(struct char_mappings **cmaps, int value)
{
	int i;
	int start = T_START(value);

	(*cmaps) = talloc_zero(NULL, struct char_mappings);

	if (!*cmaps)
		return False;

	for (i = 0; i < MAP_SIZE;i++) {
		(*cmaps)->entry[i][vfs_translate_to_unix] = start + i;
		(*cmaps)->entry[i][vfs_translate_to_windows] = start + i;
	}

	return True;
}

static void set_tables(struct char_mappings **cmaps,
		       long unix_map,
		       long windows_map)
{
	int i;

	/* set unix -> windows */
	i = T_OFFSET(unix_map);
	cmaps[T_PICK(unix_map)]->entry[i][vfs_translate_to_windows] = windows_map;

	/* set windows -> unix */
	i = T_OFFSET(windows_map);
	cmaps[T_PICK(windows_map)]->entry[i][vfs_translate_to_unix] = unix_map;
}

static bool build_ranges(struct char_mappings **cmaps,
			 long unix_map,
			 long windows_map)
{

	if (!cmaps[T_PICK(unix_map)]) {
		if (!build_table(&cmaps[T_PICK(unix_map)], unix_map))
			return False;
	}

	if (!cmaps[T_PICK(windows_map)]) {
		if (!build_table(&cmaps[T_PICK(windows_map)], windows_map))
			return False;
	}

	set_tables(cmaps, unix_map, windows_map);

	return True;
}

struct char_mappings **string_replace_init_map(const char **mappings)
{
	int i;
	char *tmp;
	fstring mapping;
	long unix_map, windows_map;
	struct char_mappings **cmaps = NULL;

	if (mappings == NULL) {
		return NULL;
	}

	cmaps = TALLOC_ZERO(NULL, MAP_NUM * sizeof(struct char_mappings *));
	if (cmaps == NULL) {
		return NULL;
	}

	/*
	 * catia mappings are of the form :
	 * UNIX char (in 0xnn hex) : WINDOWS char (in 0xnn hex)
	 *
	 * multiple mappings are comma separated in smb.conf
	 */

	for (i = 0; mappings[i]; i++) {
		fstrcpy(mapping, mappings[i]);
		unix_map = strtol(mapping, &tmp, 16);
		if (unix_map == 0 && errno == EINVAL) {
			DEBUG(0, ("INVALID CATIA MAPPINGS - %s\n", mapping));
			continue;
		}
		windows_map = strtol(++tmp, NULL, 16);
		if (windows_map == 0 && errno == EINVAL) {
			DEBUG(0, ("INVALID CATIA MAPPINGS - %s\n", mapping));
			continue;
		}

		if (!build_ranges(cmaps, unix_map, windows_map)) {
			DEBUG(0, ("TABLE ERROR - CATIA MAPPINGS - %s\n", mapping));
			continue;
		}
	}

	return cmaps;
}

NTSTATUS string_replace_allocate(connection_struct *conn,
				 const char *name_in,
				 struct char_mappings **cmaps,
				 TALLOC_CTX *mem_ctx,
				 char **mapped_name,
				 enum vfs_translate_direction direction)
{
	static smb_ucs2_t *tmpbuf = NULL;
	smb_ucs2_t *ptr = NULL;
	struct char_mappings *map = NULL;
	size_t converted_size;
	bool ok;

	ok = push_ucs2_talloc(talloc_tos(), &tmpbuf, name_in,
			      &converted_size);
	if (!ok) {
		return map_nt_error_from_unix(errno);
	}

	for (ptr = tmpbuf; *ptr; ptr++) {
		if (*ptr == 0) {
			break;
		}
		if (cmaps == NULL) {
			continue;
		}
		map = cmaps[T_PICK((*ptr))];
		if (map == NULL) {
			/* nothing to do */
			continue;
		}

		*ptr = map->entry[T_OFFSET((*ptr))][direction];
	}

	ok = pull_ucs2_talloc(mem_ctx, mapped_name, tmpbuf,
			      &converted_size);
	TALLOC_FREE(tmpbuf);
	if (!ok) {
		return map_nt_error_from_unix(errno);
	}
	return NT_STATUS_OK;
}
