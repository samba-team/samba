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
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SAMBA_UTIL_STRLIST_H
#define _SAMBA_UTIL_STRLIST_H

#include <talloc.h>

/* separators for lists */
#ifndef LIST_SEP
#define LIST_SEP " \t,\n\r"
#endif

/**
  build an empty (only NULL terminated) list of strings (for expansion with str_list_add() etc)
*/
char **str_list_make_empty(TALLOC_CTX *mem_ctx);

/**
  place the only element 'entry' into a new, NULL terminated string list
*/
char **str_list_make_single(TALLOC_CTX *mem_ctx,
			    const char *entry);

/**
  build a null terminated list of strings from a input string and a
  separator list. The separator list must contain characters less than
  or equal to 0x2f for this to work correctly on multi-byte strings
*/
char **str_list_make(TALLOC_CTX *mem_ctx, const char *string,
		     const char *sep);

/**
 * build a null terminated list of strings from an argv-like input string
 * Entries are separated by spaces and can be enclosed by quotes.
 * Does NOT support escaping
 */
char **str_list_make_shell(TALLOC_CTX *mem_ctx, const char *string,
			   const char *sep);

/**
 * join a list back to one string
 */
char *str_list_join(TALLOC_CTX *mem_ctx, const char **list,
		    char separator);

/** join a list back to one (shell-like) string; entries
 * separated by spaces, using quotes where necessary */
char *str_list_join_shell(TALLOC_CTX *mem_ctx, const char **list,
			  char sep);

/**
  return the number of elements in a string list
*/
size_t str_list_length(const char * const *list);

/**
  copy a string list
*/
char **str_list_copy(TALLOC_CTX *mem_ctx, const char **list);

/**
   Return true if all the elements of the list match exactly.
 */
bool str_list_equal(const char * const *list1,
		    const char * const *list2);

/**
  add an entry to a string list
*/
const char **str_list_add(const char **list, const char *s);

/**
  remove an entry from a string list
*/
void str_list_remove(const char **list, const char *s);

/**
  return true if a string is in a list
*/
bool str_list_check(const char **list, const char *s);

/**
  return true if a string is in a list, case insensitively
*/
bool str_list_check_ci(const char **list, const char *s);
/**
  append one list to another - expanding list1
*/
const char **str_list_append(const char **list1,
			     const char * const *list2);

/**
 remove duplicate elements from a list
*/
const char **str_list_unique(const char **list);

/*
  very useful when debugging complex list related code
 */
void str_list_show(const char **list);


/**
  append one list to another - expanding list1
  this assumes the elements of list2 are const pointers, so we can re-use them
*/
const char **str_list_append_const(const char **list1,
				   const char **list2);

/**
   Add a string to an array of strings.

   num should be a pointer to an integer that holds the current
   number of elements in strings. It will be updated by this function.
 */
bool add_string_to_array(TALLOC_CTX *mem_ctx,
			 const char *str, const char ***strings, size_t *num);

/**
  add an entry to a string list
  this assumes s will not change
*/
const char **str_list_add_const(const char **list, const char *s);

/**
  copy a string list
  this assumes list will not change
*/
const char **str_list_copy_const(TALLOC_CTX *mem_ctx,
				 const char **list);

#endif /* _SAMBA_UTIL_STRLIST_H */
