/*
 * Unix SMB/CIFS implementation.
 * Net_sam_logon info3 helpers
 * Copyright (C) Alexander Bokovoy              2002.
 * Copyright (C) Andrew Bartlett                2002.
 * Copyright (C) Gerald Carter			2003.
 * Copyright (C) Tim Potter			2003.
 * Copyright (C) Guenther Deschner		2008.
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

#ifndef __LIBSMB_SAMLOGON_CACHE_H__
#define __LIBSMB_SAMLOGON_CACHE_H__

#include "replace.h"
#include <talloc.h>

struct dom_sid;
struct netr_SamInfo3;

bool netsamlogon_cache_init(void);
void netsamlogon_clear_cached_user(const struct dom_sid *user_sid);
bool netsamlogon_cache_store(const char *username,
			     struct netr_SamInfo3 *info3);
struct netr_SamInfo3 *netsamlogon_cache_get(TALLOC_CTX *mem_ctx,
					    const struct dom_sid *user_sid);
bool netsamlogon_cache_have(const struct dom_sid *sid);
int netsamlog_cache_for_all(int (*cb)(const char *sid_str,
				      time_t when_cached,
				      struct netr_SamInfo3 *,
				      void *private_data),
			    void *private_data);

#endif
