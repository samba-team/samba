/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Jelmer Vernooij 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/locale.h"

/**
  return the number of elements in a string list
*/
_PUBLIC_ size_t str_list_length(const char **list)
{
	size_t ret;
	for (ret=0;list && list[ret];ret++) /* noop */ ;
	return ret;
}


/**
  add an entry to a string list
*/
_PUBLIC_ const char **str_list_add(const char **list, const char *s)
{
	size_t len = str_list_length(list);
	const char **ret;

	ret = talloc_realloc(NULL, list, const char *, len+2);
	if (ret == NULL) return NULL;

	ret[len] = talloc_strdup(ret, s);
	if (ret[len] == NULL) return NULL;

	ret[len+1] = NULL;

	return ret;
}
