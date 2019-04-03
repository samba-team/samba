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

#ifndef __AUTH_AUTH_UTIL_H__
#define __AUTH_AUTH_UTIL_H__

#include "replace.h"
#include <talloc.h>
#include "librpc/gen_ndr/auth.h"

struct auth_session_info *copy_session_info(
	TALLOC_CTX *mem_ctx,
	const struct auth_session_info *src);

#endif
