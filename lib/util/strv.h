/*
 * String Vector functions modeled after glibc argv_* functions
 *
 * Copyright Volker Lendecke <vl@samba.org> 2014
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

#ifndef _STRV_H_
#define _STRV_H_

#include "talloc.h"

int strv_add(TALLOC_CTX *mem_ctx, char **strv, const char *string);
int strv_addn(TALLOC_CTX *mem_ctx, char **strv, const char *src, size_t srclen);
int strv_append(TALLOC_CTX *mem_ctx, char **strv, const char *src);
char *strv_next(char *strv, const char *entry);
const char *strv_len_next(const char *strv, size_t strv_len,
			  const char *entry);
char *strv_find(char *strv, const char *entry);
size_t strv_count(char *strv);
void strv_delete(char **strv, char *entry);
char * const *strv_to_env(TALLOC_CTX *mem_ctx, char *strv);

#endif
