/*
 * Unix SMB/CIFS implementation.
 *
 * Generic, persistent and shared between processes cache mechanism for use
 * by various parts of the Samba code
 *
 * Copyright (C) Rafal Szczesniak    2002
 * Copyright (C) Volker Lendecke     2009
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

#ifndef __LIB_GENCACHE_H__
#define __LIB_GENCACHE_H__

#include "replace.h"
#include "system/time.h"
#include "lib/util/data_blob.h"

bool gencache_set(const char *keystr, const char *value, time_t timeout);
bool gencache_del(const char *keystr);
bool gencache_get(const char *keystr, TALLOC_CTX *mem_ctx, char **value,
		  time_t *ptimeout);

/*
 * This might look like overkill, but namemap_cache.c shows it's
 * necessary :-)
 */
struct gencache_timeout;
bool gencache_timeout_expired(const struct gencache_timeout *t);

bool gencache_parse(const char *keystr,
		    void (*parser)(const struct gencache_timeout *timeout,
				   DATA_BLOB blob,
				   void *private_data),
		    void *private_data);
bool gencache_get_data_blob(const char *keystr, TALLOC_CTX *mem_ctx,
			    DATA_BLOB *blob,
			    time_t *timeout, bool *was_expired);
bool gencache_set_data_blob(const char *keystr, DATA_BLOB blob,
			    time_t timeout);
void gencache_iterate_blobs(void (*fn)(const char *key, DATA_BLOB value,
				       time_t timeout, void *private_data),
			    void *private_data, const char *pattern);
void gencache_iterate(void (*fn)(const char* key, const char *value,
				 time_t timeout, void* dptr),
                      void* data, const char* keystr_pattern);

#endif
