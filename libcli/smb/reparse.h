/*
 * Unix SMB/CIFS implementation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __UTIL_REPARSE_H__
#define __UTIL_REPARSE_H__

#include <talloc.h>
#include "replace.h"
#include "libcli/smb/reparse_symlink.h"
#include "libcli/util/ntstatus.h"

struct nfs_reparse_data_buffer {
	uint64_t type;

	union {
		char *lnk_target; /* NFS_SPECFILE_LNK */
		struct {
			uint32_t major;
			uint32_t minor;
		} dev; /* NFS_SPECFILE_[CHR|BLK] */

		/* NFS_SPECFILE_[FIFO|SOCK] have no data */
	} data;
};

struct reparse_data_buffer {
	uint32_t tag;

	union {
		/* IO_REPARSE_TAG_NFS */
		struct nfs_reparse_data_buffer nfs;

		/* IO_REPARSE_TAG_SYMLINK */
		struct symlink_reparse_struct lnk;

		/* Unknown reparse tag */
		struct {
			uint16_t length;
			uint16_t reserved;
			uint8_t *data;
		} raw;

	} parsed;
};

NTSTATUS reparse_data_buffer_parse(TALLOC_CTX *mem_ctx,
				   struct reparse_data_buffer *dst,
				   const uint8_t *buf,
				   size_t buflen);
char *reparse_data_buffer_str(TALLOC_CTX *mem_ctx,
			      const struct reparse_data_buffer *dst);

#endif
