/*
 * Unix SMB/CIFS implementation.
 * Utility functions for reparse points.
 *
 * Copyright (C) Jeremy Allison 2018
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

#include "includes.h"
#include "util_reparse.h"
#include "libcli/smb/reparse.h"

NTSTATUS fsctl_get_reparse_point(struct files_struct *fsp,
				 TALLOC_CTX *mem_ctx,
				 uint32_t *_reparse_tag,
				 uint8_t **_out_data,
				 uint32_t max_out_len,
				 uint32_t *_out_len)
{
	DBG_DEBUG("Called on %s\n", fsp_str_dbg(fsp));
	return NT_STATUS_NOT_A_REPARSE_POINT;
}

NTSTATUS fsctl_set_reparse_point(struct files_struct *fsp,
				 TALLOC_CTX *mem_ctx,
				 const uint8_t *in_data,
				 uint32_t in_len)
{
	uint32_t reparse_tag;
	const uint8_t *reparse_data = NULL;
	size_t reparse_data_length;
	NTSTATUS status;

	DBG_DEBUG("Called on %s\n", fsp_str_dbg(fsp));

	status = reparse_buffer_check(in_data,
				      in_len,
				      &reparse_tag,
				      &reparse_data,
				      &reparse_data_length);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("check_reparse_data_buffer failed: %s\n",
			  nt_errstr(status));
		return status;
	}

	DBG_DEBUG("reparse tag=%" PRIX32 ", length=%zu\n",
		  reparse_tag,
		  reparse_data_length);

	return NT_STATUS_NOT_A_REPARSE_POINT;
}

NTSTATUS fsctl_del_reparse_point(struct files_struct *fsp,
				 TALLOC_CTX *mem_ctx,
				 const uint8_t *in_data,
				 uint32_t in_len)
{
	DBG_DEBUG("Called on %s\n", fsp_str_dbg(fsp));
	return NT_STATUS_NOT_A_REPARSE_POINT;
}
