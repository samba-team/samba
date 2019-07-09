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

struct char_mappings **string_replace_init_map(TALLOC_CTX *mem_ctx,
					       const char **mappings)
{
	int i;
	char *tmp;
	fstring mapping;
	long unix_map, windows_map;
	struct char_mappings **cmaps = NULL;

	if (mappings == NULL) {
		return NULL;
	}

	cmaps = TALLOC_ZERO(mem_ctx, MAP_NUM * sizeof(struct char_mappings *));
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

const char *macos_string_replace_map =
	"0x01:0xf001,0x02:0xf002,0x03:0xf003,0x04:0xf004,"
	"0x05:0xf005,0x06:0xf006,0x07:0xf007,0x08:0xf008,"
	"0x09:0xf009,0x0a:0xf00a,0x0b:0xf00b,0x0c:0xf00c,"
	"0x0d:0xf00d,0x0e:0xf00e,0x0f:0xf00f,0x10:0xf010,"
	"0x11:0xf011,0x12:0xf012,0x13:0xf013,0x14:0xf014,"
	"0x15:0xf015,0x16:0xf016,0x17:0xf017,0x18:0xf018,"
	"0x19:0xf019,0x1a:0xf01a,0x1b:0xf01b,0x1c:0xf01c,"
	"0x1d:0xf01d,0x1e:0xf01e,0x1f:0xf01f,"
	"0x22:0xf020,0x2a:0xf021,0x3a:0xf022,0x3c:0xf023,"
	"0x3e:0xf024,0x3f:0xf025,0x5c:0xf026,0x7c:0xf027";
