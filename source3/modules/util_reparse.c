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

NTSTATUS fsctl_get_reparse_point(struct files_struct *fsp,
				 TALLOC_CTX *mem_ctx,
				 char **out_data,
				 uint32_t max_out_len,
				 uint32_t *out_len)
{
	DBG_DEBUG("Called on %s\n", fsp_str_dbg(fsp));
	return NT_STATUS_NOT_A_REPARSE_POINT;
}

static NTSTATUS check_reparse_data_buffer(
	const uint8_t *in_data, size_t in_len)
{
	uint16_t reparse_data_length;

	if (in_len == 0) {
		DBG_DEBUG("in_len=0\n");
		return NT_STATUS_INVALID_BUFFER_SIZE;
	}
	if (in_len < 8) {
		DBG_DEBUG("in_len=%zu\n", in_len);
		return NT_STATUS_IO_REPARSE_DATA_INVALID;
	}

	reparse_data_length = PULL_LE_U16(in_data, 4);

	if (reparse_data_length != (in_len - 8)) {
		DBG_DEBUG("in_len=%zu, reparse_data_length=%"PRIu16"\n",
			  in_len,
			  reparse_data_length);
		return NT_STATUS_IO_REPARSE_DATA_INVALID;
	}

	return NT_STATUS_OK;
}

NTSTATUS fsctl_set_reparse_point(struct files_struct *fsp,
				 TALLOC_CTX *mem_ctx,
				 const uint8_t *in_data,
				 uint32_t in_len)
{
	NTSTATUS status;

	DBG_DEBUG("Called on %s\n", fsp_str_dbg(fsp));

	status = check_reparse_data_buffer(in_data, in_len);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

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
