/*
 * Unix SMB/CIFS implementation.
 *
 * SMB2 Posix context handling
 *
 * Copyright (C) Jeremy Allison 2019
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

#ifndef _LIBCLI_SMB_SMB2_POSIX_H_
#define _LIBCLI_SMB_SMB2_POSIX_H_

#include "replace.h"
#include "system/filesys.h"
#include <talloc.h>
#include "libcli/smb/smb2_create_blob.h"
#include "libcli/smb/smb_util.h"

NTSTATUS make_smb2_posix_create_ctx(
	TALLOC_CTX *mem_ctx,
	struct smb2_create_blobs **crb,
	mode_t mode);

#endif /* _LIBCLI_SMB_SMB2_POSIX_H_ */
