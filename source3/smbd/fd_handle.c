/*
   Unix SMB/CIFS implementation.
   fd_handle structure handling
   Copyright (C) Ralph Boehme 2020

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
#include "fd_handle.h"

struct fd_handle {
	size_t ref_count;
	int fd;
	uint64_t position_information;
	off_t pos;
	uint64_t gen_id;
};

static int fd_handle_destructor(struct fd_handle *fh)
{
	SMB_ASSERT((fh->fd == -1) || (fh->fd == AT_FDCWD));
	return 0;
}

struct fd_handle *fd_handle_create(TALLOC_CTX *mem_ctx)
{
	struct fd_handle *fh = NULL;

	fh = talloc(mem_ctx, struct fd_handle);
	if (fh == NULL) {
		return NULL;
	}
	*fh = (struct fd_handle) { .fd = -1, };

	talloc_set_destructor(fh, fd_handle_destructor);

	return fh;
}

size_t fh_get_refcount(struct fd_handle *fh)
{
	return fh->ref_count;
}

void fh_set_refcount(struct fd_handle *fh, size_t ref_count)
{
	fh->ref_count = ref_count;
}

uint64_t fh_get_position_information(struct fd_handle *fh)
{
	return fh->position_information;
}

void fh_set_position_information(struct fd_handle *fh, uint64_t posinfo)
{
	fh->position_information = posinfo;
}

off_t fh_get_pos(struct fd_handle *fh)
{
	return fh->pos;
}

void fh_set_pos(struct fd_handle *fh, off_t pos)
{
	fh->pos = pos;
}

uint64_t fh_get_gen_id(struct fd_handle *fh)
{
	return fh->gen_id;
}

void fh_set_gen_id(struct fd_handle *fh, uint64_t gen_id)
{
	fh->gen_id = gen_id;
}

/****************************************************************************
 Helper functions for working with fsp->fh->fd
****************************************************************************/

int fsp_get_io_fd(const struct files_struct *fsp)
{
	if (fsp->fsp_flags.is_pathref) {
		DBG_ERR("fsp [%s] is a path referencing fsp\n",
			fsp_str_dbg(fsp));
#ifdef DEVELOPER
		smb_panic("fsp is a pathref");
#endif
		return -1;
	}

	return fsp->fh->fd;
}

int fsp_get_pathref_fd(const struct files_struct *fsp)
{
	return fsp->fh->fd;
}

void fsp_set_fd(struct files_struct *fsp, int fd)
{
	/*
	 * Deliberately allow setting an fd if the existing fd is the
	 * same. This happens if a VFS module assigns the fd to
	 * fsp->fh->fd in its openat VFS function. The canonical place
	 * where the assignment is done is in fd_open(), but some VFS
	 * modules do it anyway.
	 */

	SMB_ASSERT(fsp->fh->fd == -1 ||
		   fsp->fh->fd == fd ||
		   fd == -1 ||
		   fd == AT_FDCWD);

	fsp->fh->fd = fd;
}
