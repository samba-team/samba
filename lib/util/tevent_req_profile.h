/*
 * Unix SMB/CIFS implementation.
 *
 * Helpers around tevent_req_profile
 *
 * Copyright (C) Volker Lendecke 2018
 *
 *   ** NOTE! The following LGPL license applies to the tevent
 *   ** library. This does NOT imply that all of Samba is released
 *   ** under the LGPL
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIB_UTIL_TEVENT_REQ_PROFILE_UNPACK
#define __LIB_UTIL_TEVENT_REQ_PROFILE_UNPACK

#include "replace.h"
#include <tevent.h>

char *tevent_req_profile_string(TALLOC_CTX *mem_ctx,
				const struct tevent_req_profile *profile,
				unsigned indent,
				unsigned max_indent);
ssize_t tevent_req_profile_pack(
	const struct tevent_req_profile *profile,
	uint8_t *buf,
	size_t buflen);
ssize_t tevent_req_profile_unpack(
	const uint8_t *buf,
	size_t buflen,
	TALLOC_CTX *mem_ctx,
	struct tevent_req_profile **p_profile);

#endif
