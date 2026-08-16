/*
   Unix SMB/CIFS implementation.
   Authentication utility functions

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017

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
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_auth.h"
#include "auth_util.h"

struct auth_session_info *copy_session_info(TALLOC_CTX *mem_ctx,
					    const struct auth_session_info *src)
{
	struct auth_session_info *dst = NULL;
	enum ndr_err_code ndr_err;

	dst = talloc(mem_ctx, struct auth_session_info);
	if (dst == NULL) {
		DBG_ERR("talloc failed\n");
		return NULL;
	}

	ndr_err = ndr_deepcopy_struct(auth_session_info, src, dst, dst);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("ndr_deepcopy_struct failed: %s\n",
			ndr_errstr(ndr_err));
		TALLOC_FREE(dst);
		return NULL;
	}

	return dst;
}
