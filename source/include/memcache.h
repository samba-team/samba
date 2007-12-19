/*
   Unix SMB/CIFS implementation.
   In-memory cache
   Copyright (C) Volker Lendecke 2005-2007

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

#ifndef __MEMCACHE_H__
#define __MEMCACHE_H__

#include "includes.h"

struct memcache;

enum memcache_number {
	STAT_CACHE,
	UID_SID_CACHE,
	SID_UID_CACHE,
	GID_SID_CACHE,
	SID_GID_CACHE,
	GETWD_CACHE,
	GETPWNAM_CACHE,
	MANGLE_HASH2_CACHE
};

struct memcache *memcache_init(TALLOC_CTX *mem_ctx, size_t max_size);

void memcache_add(struct memcache *cache, enum memcache_number n,
		  DATA_BLOB key, DATA_BLOB value);

void memcache_delete(struct memcache *cache, enum memcache_number n,
		     DATA_BLOB key);

bool memcache_lookup(struct memcache *cache, enum memcache_number n,
		     DATA_BLOB key, DATA_BLOB *value);

void memcache_flush(struct memcache *cache, enum memcache_number n);

#endif
