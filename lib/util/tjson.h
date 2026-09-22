/*
 * Talloc wrapper for jansson JSON objects
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

#ifndef _LIB_UTIL_TJSON_H_
#define _LIB_UTIL_TJSON_H_

#include <talloc.h>
#include "lib/util/attr.h"

#ifdef HAVE_JANSSON

#include <jansson.h>

struct tjson;

_WARN_UNUSED_RESULT_ struct tjson *tjson_new_object(TALLOC_CTX *mem_ctx);
_WARN_UNUSED_RESULT_ struct tjson *tjson_new_array(TALLOC_CTX *mem_ctx);

_WARN_UNUSED_RESULT_ struct tjson *tjson_wrap(TALLOC_CTX *mem_ctx,
					      json_t **root);
_WARN_UNUSED_RESULT_ json_t *tjson_unwrap(struct tjson **pobject);

_WARN_UNUSED_RESULT_ bool tjson_has_error(struct tjson *object);

void tjson_add_int(struct tjson *object, const char *name, json_int_t value);
void tjson_add_bool(struct tjson *object, const char *name, bool value);
void tjson_add_string(struct tjson *object,
		      const char *name,
		      const char *value);
void tjson_add_stringn(struct tjson *object,
		       const char *name,
		       const char *value,
		       size_t len);
void tjson_add_object(struct tjson *object,
		      const char *name,
		      struct tjson **pvalue);
void tjson_add_time(struct tjson *object,
		    const char *name,
		    const struct timeval tv);
void tjson_add_timestamp(struct tjson *object);

_WARN_UNUSED_RESULT_ char *tjson_to_string(TALLOC_CTX *mem_ctx,
					   struct tjson *object);
_WARN_UNUSED_RESULT_ char *tjson_to_string_flags(TALLOC_CTX *mem_ctx,
						 struct tjson *object,
						 size_t flags);

#endif /* HAVE_JANSSON */

#endif
