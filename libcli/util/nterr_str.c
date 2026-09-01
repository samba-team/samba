/*
 *  Unix SMB/CIFS implementation.
 *
 *  NT error string-to-code lookup (nt_status_string_to_code).
 *
 *  Copyright (C) Luke Kenneth Casson Leighton 1997-2001.
 *  Copyright (C) Andrew Bartlett
 *  Copyright (C) Andrew Tridgell
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "nterr_private.h"
#undef strcasecmp

#include "nterr_gen_str.c"

/*****************************************************************************
 Returns the NT_STATUS constant matching the string supplied (as an NTSTATUS)
 *****************************************************************************/

NTSTATUS nt_status_string_to_code(const char *nt_status_str)
{
	int idx = 0;

	while (special_nt_errs[idx].nt_errstr != NULL) {
		if (strcasecmp(special_nt_errs[idx].nt_errstr,
			       nt_status_str) == 0)
		{
			return special_nt_errs[idx].nt_errcode;
		}
		idx++;
	}

	idx = 0;

	while (nt_errs[idx].nt_errstr != NULL) {
		if (strcasecmp(nt_errs[idx].nt_errstr, nt_status_str) == 0) {
			return nt_errs[idx].nt_errcode;
		}
		idx++;
	}

	return NT_STATUS_UNSUCCESSFUL;
}
