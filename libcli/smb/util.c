/*
   Unix SMB/CIFS implementation.
   client file operations
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) James Myers 2003

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
#include "libcli/smb/smb_common.h"
#include "system/filesys.h"

/**
 Return a string representing a CIFS attribute for a file.
**/
char *attrib_string(TALLOC_CTX *mem_ctx, uint32_t attrib)
{
	int i, len;
	const struct {
		char c;
		uint16_t attr;
	} attr_strs[] = {
		{'V', FILE_ATTRIBUTE_VOLUME},
		{'D', FILE_ATTRIBUTE_DIRECTORY},
		{'A', FILE_ATTRIBUTE_ARCHIVE},
		{'H', FILE_ATTRIBUTE_HIDDEN},
		{'S', FILE_ATTRIBUTE_SYSTEM},
		{'N', FILE_ATTRIBUTE_NORMAL},
		{'R', FILE_ATTRIBUTE_READONLY},
		{'d', FILE_ATTRIBUTE_DEVICE},
		{'t', FILE_ATTRIBUTE_TEMPORARY},
		{'s', FILE_ATTRIBUTE_SPARSE},
		{'r', FILE_ATTRIBUTE_REPARSE_POINT},
		{'c', FILE_ATTRIBUTE_COMPRESSED},
		{'o', FILE_ATTRIBUTE_OFFLINE},
		{'n', FILE_ATTRIBUTE_NONINDEXED},
		{'e', FILE_ATTRIBUTE_ENCRYPTED}
	};
	char *ret;

	ret = talloc_array(mem_ctx, char, ARRAY_SIZE(attr_strs)+1);
	if (!ret) {
		return NULL;
	}

	for (len=i=0; i<ARRAY_SIZE(attr_strs); i++) {
		if (attrib & attr_strs[i].attr) {
			ret[len++] = attr_strs[i].c;
		}
	}

	ret[len] = 0;

	talloc_set_name_const(ret, ret);

	return ret;
}

/****************************************************************************
 Map standard UNIX permissions onto wire representations.
****************************************************************************/

uint32_t unix_perms_to_wire(mode_t perms)
{
        unsigned int ret = 0;

        ret |= ((perms & S_IXOTH) ?  UNIX_X_OTH : 0);
        ret |= ((perms & S_IWOTH) ?  UNIX_W_OTH : 0);
        ret |= ((perms & S_IROTH) ?  UNIX_R_OTH : 0);
        ret |= ((perms & S_IXGRP) ?  UNIX_X_GRP : 0);
        ret |= ((perms & S_IWGRP) ?  UNIX_W_GRP : 0);
        ret |= ((perms & S_IRGRP) ?  UNIX_R_GRP : 0);
        ret |= ((perms & S_IXUSR) ?  UNIX_X_USR : 0);
        ret |= ((perms & S_IWUSR) ?  UNIX_W_USR : 0);
        ret |= ((perms & S_IRUSR) ?  UNIX_R_USR : 0);
#ifdef S_ISVTX
        ret |= ((perms & S_ISVTX) ?  UNIX_STICKY : 0);
#endif
#ifdef S_ISGID
        ret |= ((perms & S_ISGID) ?  UNIX_SET_GID : 0);
#endif
#ifdef S_ISUID
        ret |= ((perms & S_ISUID) ?  UNIX_SET_UID : 0);
#endif
        return ret;
}

/****************************************************************************
 Map wire permissions to standard UNIX.
****************************************************************************/

mode_t wire_perms_to_unix(uint32_t perms)
{
        mode_t ret = (mode_t)0;

        ret |= ((perms & UNIX_X_OTH) ? S_IXOTH : 0);
        ret |= ((perms & UNIX_W_OTH) ? S_IWOTH : 0);
        ret |= ((perms & UNIX_R_OTH) ? S_IROTH : 0);
        ret |= ((perms & UNIX_X_GRP) ? S_IXGRP : 0);
        ret |= ((perms & UNIX_W_GRP) ? S_IWGRP : 0);
        ret |= ((perms & UNIX_R_GRP) ? S_IRGRP : 0);
        ret |= ((perms & UNIX_X_USR) ? S_IXUSR : 0);
        ret |= ((perms & UNIX_W_USR) ? S_IWUSR : 0);
        ret |= ((perms & UNIX_R_USR) ? S_IRUSR : 0);
#ifdef S_ISVTX
        ret |= ((perms & UNIX_STICKY) ? S_ISVTX : 0);
#endif
#ifdef S_ISGID
        ret |= ((perms & UNIX_SET_GID) ? S_ISGID : 0);
#endif
#ifdef S_ISUID
        ret |= ((perms & UNIX_SET_UID) ? S_ISUID : 0);
#endif
        return ret;
}

/****************************************************************************
 Return the file type from the wire filetype for UNIX extensions.
****************************************************************************/

mode_t unix_filetype_from_wire(uint32_t wire_type)
{
	switch (wire_type) {
		case UNIX_TYPE_FILE:
			return S_IFREG;
		case UNIX_TYPE_DIR:
			return S_IFDIR;
#ifdef S_IFLNK
		case UNIX_TYPE_SYMLINK:
			return S_IFLNK;
#endif
#ifdef S_IFCHR
		case UNIX_TYPE_CHARDEV:
			return S_IFCHR;
#endif
#ifdef S_IFBLK
		case UNIX_TYPE_BLKDEV:
			return S_IFBLK;
#endif
#ifdef S_IFIFO
		case UNIX_TYPE_FIFO:
			return S_IFIFO;
#endif
#ifdef S_IFSOCK
		case UNIX_TYPE_SOCKET:
			return S_IFSOCK;
#endif
		default:
			return (mode_t)0;
	}
}

bool smb_buffer_oob(uint32_t bufsize, uint32_t offset, uint32_t length)
{
	if ((offset + length < offset) || (offset + length < length)) {
		/* wrap */
		return true;
	}
	if ((offset > bufsize) || (offset + length > bufsize)) {
		/* overflow */
		return true;
	}
	return false;
}
