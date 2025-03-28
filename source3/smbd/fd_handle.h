/*
   Unix SMB/CIFS implementation.
   Files handle structure handling
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

#ifndef FD_HANDLE_H
#define FD_HANDLE_H

#include "replace.h"
#include <talloc.h>

struct fd_handle;

struct fd_handle *fd_handle_create(TALLOC_CTX *mem_ctx);

size_t fh_get_refcount(struct fd_handle *fh);
void fh_set_refcount(struct fd_handle *fh, size_t ref_count);

uint64_t fh_get_position_information(struct fd_handle *fh);
void fh_set_position_information(struct fd_handle *fh, uint64_t posinfo);

off_t fh_get_pos(struct fd_handle *fh);
void fh_set_pos(struct fd_handle *fh, off_t pos);

uint64_t fh_get_gen_id(struct fd_handle *fh);
void fh_set_gen_id(struct fd_handle *fh, uint64_t gen_id);

int fsp_get_io_fd(const struct files_struct *fsp);
int fsp_get_pathref_fd(const struct files_struct *fsp);
void fsp_set_fd(struct files_struct *fsp, int fd);

#endif
