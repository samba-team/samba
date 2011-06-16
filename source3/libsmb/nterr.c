/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Luke Kenneth Casson Leighton 1997-2001.
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

/* NT error codes.  please read nterr.h */

#include "includes.h"

extern const nt_err_code_struct nt_errs[];
extern const nt_err_code_struct nt_err_desc[];

#include "smb_ldap.h"
#undef strcasecmp

/*****************************************************************************
 Returns an NT error message.  not amazingly helpful, but better than a number.
 *****************************************************************************/

const char *nt_errstr(NTSTATUS nt_code)
{
	int idx = 0;
	char *result;

	if (NT_STATUS_IS_DOS(nt_code)) {
		return smb_dos_err_name(NT_STATUS_DOS_CLASS(nt_code),
					NT_STATUS_DOS_CODE(nt_code));
	}

	while (nt_errs[idx].nt_errstr != NULL) {
		if (NT_STATUS_V(nt_errs[idx].nt_errcode) ==
		    NT_STATUS_V(nt_code)) {
			return nt_errs[idx].nt_errstr;
		}
		idx++;
	}

	result = talloc_asprintf(talloc_tos(), "NT code 0x%08x",
				 NT_STATUS_V(nt_code));
	SMB_ASSERT(result != NULL);
	return result;
}

