/*
 * Unix SMB/CIFS implementation.
 * Utils for caching sid2name and name2sid
 * Copyright (C) Volker Lendecke 2017
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

#ifndef __LIB_NAMEMAP_CACHE_H__
#define __LIB_NAMEMAP_CACHE_H__

#include "lib/util/time.h"
#include "lib/util/data_blob.h"
#include "librpc/gen_ndr/lsa.h"

bool namemap_cache_set_sid2name(const struct dom_sid *sid,
				const char *domain, const char *name,
				enum lsa_SidType type, time_t timeout);
bool namemap_cache_set_name2sid(const char *domain, const char *name,
				const struct dom_sid *sid,
				enum lsa_SidType type,
				time_t timeout);
bool namemap_cache_find_sid(const struct dom_sid *sid,
			    void (*fn)(const char *domain,
				       const char *name,
				       enum lsa_SidType type,
				       bool expired,
				       void *private_data),
			    void *private_data);
bool namemap_cache_find_name(const char *domain,
			     const char *name,
			     void (*fn)(const struct dom_sid *sid,
					enum lsa_SidType type,
					bool expired,
					void *private_data),
			     void *private_data);

#endif
