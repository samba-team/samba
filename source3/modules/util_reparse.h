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

#ifndef __UTIL_REPARSE_H__
#define __UTIL_REPARSE_H__

NTSTATUS fsctl_get_reparse_point(struct files_struct *fsp,
				 TALLOC_CTX *ctx,
				 char **out_data,
				 uint32_t max_out_len,
				 uint32_t *out_len);

NTSTATUS fsctl_set_reparse_point(struct files_struct *fsp,
				 TALLOC_CTX *ctx,
				 const uint8_t *in_data,
				 uint32_t in_len);

NTSTATUS fsctl_del_reparse_point(struct files_struct *fsp,
				 TALLOC_CTX *ctx,
				 const uint8_t *in_data,
				 uint32_t in_len);

#endif /* __UTIL_REPARSE_H__ */
