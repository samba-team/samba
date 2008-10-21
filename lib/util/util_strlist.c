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

#include "includes.h"
#include "system/locale.h"

#undef strcasecmp

/**
 * @file
 * @brief String list manipulation
 */

/**
  build a null terminated list of strings from a input string and a
  separator list. The separator list must contain characters less than
  or equal to 0x2f for this to work correctly on multi-byte strings
*/
_PUBLIC_ char **str_list_make(TALLOC_CTX *mem_ctx, const char *string, const char *sep)
{
	int num_elements = 0;
	char **ret = NULL;

	if (sep == NULL) {
		sep = LIST_SEP;
	}

	ret = talloc_array(mem_ctx, char *, 1);
	if (ret == NULL) {
		return NULL;
	}

	while (string && *string) {
		size_t len = strcspn(string, sep);
		char **ret2;
		
		if (len == 0) {
			string += strspn(string, sep);
			continue;
		}

		ret2 = talloc_realloc(mem_ctx, ret, char *, num_elements+2);
		if (ret2 == NULL) {
			talloc_free(ret);
			return NULL;
		}
		ret = ret2;

		ret[num_elements] = talloc_strndup(ret, string, len);
		if (ret[num_elements] == NULL) {
			talloc_free(ret);
			return NULL;
		}

		num_elements++;
		string += len;
	}

	ret[num_elements] = NULL;

	return ret;
}

/**
 * build a null terminated list of strings from an argv-like input string 
 * Entries are seperated by spaces and can be enclosed by quotes. 
 * Does NOT support escaping
 */
_PUBLIC_ const char **str_list_make_shell(TALLOC_CTX *mem_ctx, const char *string, const char *sep)
{
	int num_elements = 0;
	const char **ret = NULL;

	ret = talloc_array(mem_ctx, const char *, 1);
	if (ret == NULL) {
		return NULL;
	}

	if (sep == NULL)
		sep = " \t\n\r";

	while (string && *string) {
		size_t len = strcspn(string, sep);
		char *element;
		const char **ret2;
		
		if (len == 0) {
			string += strspn(string, sep);
			continue;
		}

		if (*string == '\"') {
			string++;
			len = strcspn(string, "\"");
			element = talloc_strndup(ret, string, len);
			string += len + 1;
		} else {
			element = talloc_strndup(ret, string, len);
			string += len;
		}

		if (element == NULL) {
			talloc_free(ret);
			return NULL;
		}

		ret2 = talloc_realloc(mem_ctx, ret, const char *, num_elements+2);
		if (ret2 == NULL) {
			talloc_free(ret);
			return NULL;
		}
		ret = ret2;

		ret[num_elements] = element;	

		num_elements++;
	}

	ret[num_elements] = NULL;

	return ret;

}

/**
 * join a list back to one string 
 */
_PUBLIC_ char *str_list_join(TALLOC_CTX *mem_ctx, const char **list, char seperator)
{
	char *ret = NULL;
	int i;
	
	if (list[0] == NULL)
		return talloc_strdup(mem_ctx, "");

	ret = talloc_strdup(mem_ctx, list[0]);

	for (i = 1; list[i]; i++) {
		ret = talloc_asprintf_append_buffer(ret, "%c%s", seperator, list[i]);
	}

	return ret;
}

/** join a list back to one (shell-like) string; entries 
 * seperated by spaces, using quotes where necessary */
_PUBLIC_ char *str_list_join_shell(TALLOC_CTX *mem_ctx, const char **list, char sep)
{
	char *ret = NULL;
	int i;
	
	if (list[0] == NULL)
		return talloc_strdup(mem_ctx, "");

	if (strchr(list[0], ' ') || strlen(list[0]) == 0) 
		ret = talloc_asprintf(mem_ctx, "\"%s\"", list[0]);
	else 
		ret = talloc_strdup(mem_ctx, list[0]);

	for (i = 1; list[i]; i++) {
		if (strchr(list[i], ' ') || strlen(list[i]) == 0) 
			ret = talloc_asprintf_append_buffer(ret, "%c\"%s\"", sep, list[i]);
		else 
			ret = talloc_asprintf_append_buffer(ret, "%c%s", sep, list[i]);
	}

	return ret;
}

/**
  return the number of elements in a string list
*/
_PUBLIC_ size_t str_list_length(const char * const*list)
{
	size_t ret;
	for (ret=0;list && list[ret];ret++) /* noop */ ;
	return ret;
}


/**
  copy a string list
*/
_PUBLIC_ char **str_list_copy(TALLOC_CTX *mem_ctx, const char **list)
{
	int i;
	char **ret;

	if (list == NULL)
		return NULL;
	
	ret = talloc_array(mem_ctx, char *, str_list_length(list)+1);
	if (ret == NULL) 
		return NULL;

	for (i=0;list && list[i];i++) {
		ret[i] = talloc_strdup(ret, list[i]);
		if (ret[i] == NULL) {
			talloc_free(ret);
			return NULL;
		}
	}
	ret[i] = NULL;
	return ret;
}

/**
   Return true if all the elements of the list match exactly.
 */
_PUBLIC_ bool str_list_equal(const char **list1, const char **list2)
{
	int i;
	
	if (list1 == NULL || list2 == NULL) {
		return (list1 == list2); 
	}
	
	for (i=0;list1[i] && list2[i];i++) {
		if (strcmp(list1[i], list2[i]) != 0) {
			return false;
		}
	}
	if (list1[i] || list2[i]) {
		return false;
	}
	return true;
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

/**
  remove an entry from a string list
*/
_PUBLIC_ void str_list_remove(const char **list, const char *s)
{
	int i;

	for (i=0;list[i];i++) {
		if (strcmp(list[i], s) == 0) break;
	}
	if (!list[i]) return;

	for (;list[i];i++) {
		list[i] = list[i+1];
	}
}


/**
  return true if a string is in a list
*/
_PUBLIC_ bool str_list_check(const char **list, const char *s)
{
	int i;

	for (i=0;list[i];i++) {
		if (strcmp(list[i], s) == 0) return true;
	}
	return false;
}

/**
  return true if a string is in a list, case insensitively
*/
_PUBLIC_ bool str_list_check_ci(const char **list, const char *s)
{
	int i;

	for (i=0;list[i];i++) {
		if (strcasecmp(list[i], s) == 0) return true;
	}
	return false;
}


