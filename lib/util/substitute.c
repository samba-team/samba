/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce      2001-2002
   Copyright (C) Martin Pool     2003
   Copyright (C) James Peach	 2005
   
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

#include "replace.h"
#include "system/locale.h"
#include "debug.h"
#ifndef SAMBA_UTIL_CORE_ONLY
#include "lib/util/fault.h"
#include "lib/util/talloc_stack.h"
#include "charset/charset.h"
#else
#include "charset_compat.h"
#endif
#include "substitute.h"

/**
 * @file
 * @brief Substitute utilities.
 **/

static inline
char mask_unsafe_character(char in,
			   bool is_last,
			   bool allow_trailing_dollar,
			   const char *unsafe_characters,
			   char safe_out)
{
	const char *unsafe = NULL;

	if (unsafe_characters == NULL) {
		return in;
	}

	/* allow a trailing $ (as in machine accounts) */
	if (allow_trailing_dollar && is_last && in == '$') {
		return in;
	}

	if (iscntrl(in)) {
		return safe_out;
	}

	unsafe = strchr(unsafe_characters, in);
	if (unsafe != NULL) {
		return safe_out;
	}

	/* ok */
	return in;
}

/**
 Substitute a string for a pattern in another string. Make sure there is
 enough room!

 This routine looks for pattern in s and replaces it with
 insert. It may do multiple replacements or just one.

 Any of STRING_SUB_UNSAFE_CHARACTERS and any character
 caught by calling iscntrl() in the insert string are replaced with _

 if len==0 then the string cannot be extended. This is different from the old
 use of len==0 which was for no length checks to be done.
**/

void string_sub(char *s, const char *pattern, const char *insert, size_t len)
{
	const char *unsafe_characters = STRING_SUB_UNSAFE_CHARACTERS;
	char safe_character = '_';
	char *p;
	size_t ls, lp, li, i;

	if (!insert || !pattern || !*pattern || !s)
		return;

	ls = strlen(s);
	lp = strlen(pattern);
	li = strlen(insert);

	if (len == 0)
		len = ls + 1; /* len is number of *bytes* */

	while (lp <= ls && (p = strstr_m(s,pattern))) {
		if (ls + li - lp >= len) {
			DBG_ERR("ERROR: string overflow by "
				"%zu in string_sub(%.50s, %zu)\n",
				ls + li - lp + 1 - len,
				pattern,
				len);
			break;
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		for (i=0;i<li;i++) {
			/*
			 * Without allow_trailing_dollar we don't
			 * need to calculate is_last...
			 */
			const bool is_last = false;
			const bool allow_trailing_dollar = false;

			p[i] = mask_unsafe_character(insert[i],
						     is_last,
						     allow_trailing_dollar,
						     unsafe_characters,
						     safe_character);
		}
		s = p + li;
		ls = ls + li - lp;
	}
}

/**
 Similar to string_sub() but allows for any character to be substituted. 
 Use with caution!
 if len==0 then the string cannot be extended. This is different from the old
 use of len==0 which was for no length checks to be done.
**/

_PUBLIC_ void all_string_sub(char *s,const char *pattern,const char *insert, size_t len)
{
	char *p;
	size_t ls,lp,li;

	if (!insert || !pattern || !s)
		return;

	ls = strlen(s);
	lp = strlen(pattern);
	li = strlen(insert);

	if (!*pattern)
		return;

	if (len == 0)
		len = ls + 1; /* len is number of *bytes* */

	while (lp <= ls && (p = strstr_m(s,pattern))) {
		if (ls + li - lp >= len) {
			DBG_ERR("ERROR: string overflow by "
				"%zu in all_string_sub(%.50s, %zu)\n",
				ls + li - lp + 1 - len,
				pattern,
				len);
			break;
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		memcpy(p, insert, li);
		s = p + li;
		ls = ls + li - lp;
	}
}

/*
 * Internal guts of talloc_string_sub and talloc_all_string_sub.
 * talloc version of string_sub2.
 */

bool realloc_string_sub_raw(char **_string,
			    const char *pattern,
			    const char *insert,
			    bool replace_once,
			    bool allow_trailing_dollar,
			    const char *unsafe_characters,
			    char safe_character)
{
	char *p = NULL;
	char *s = NULL;
	char *string = NULL;
	ssize_t ls,lp,li,ld, i;

	if (!insert || !pattern || !*pattern || !_string|| !*_string) {
		return false;
	}

	s = string = *_string;

	ls = (ssize_t)strlen(s);
	lp = (ssize_t)strlen(pattern);
	li = (ssize_t)strlen(insert);
	ld = li - lp;

	while ((p = strstr_m(s,pattern))) {
		if (ld > 0) {
			ptrdiff_t offset = PTR_DIFF(s,string);
			string = talloc_realloc(NULL, string, char, ls + ld + 1);
			if (!string) {
				DBG_ERR("out of memory(realloc)!\n");
				return false;
			}
			*_string = string;
			p = string + offset + (p - s);
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		for (i=0; i < li; i++) {
			bool is_last = (i == li - 1);

			p[i] = mask_unsafe_character(insert[i],
						     is_last,
						     allow_trailing_dollar,
						     unsafe_characters,
						     safe_character);
		}
		s = p + li;
		ls += ld;

		if (replace_once) {
			break;
		}
	}
	return true;
}

char *talloc_string_sub2(TALLOC_CTX *mem_ctx,
			 const char *src,
			 const char *pattern,
			 const char *insert,
			 bool remove_unsafe_characters,
			 bool replace_once,
			 bool allow_trailing_dollar)
{
	const char *unsafe_characters = NULL;
	char safe_character = '\0';
	char *string = NULL;
	bool ok;

	if (!insert || !pattern || !*pattern || !src) {
		return NULL;
	}

	if (remove_unsafe_characters) {
		unsafe_characters = STRING_SUB_UNSAFE_CHARACTERS;
		safe_character = '_';
	}

	string = talloc_strdup(mem_ctx, src);
	if (string == NULL) {
		DBG_ERR("out of memory, talloc_strdup(src)!\n");
		return NULL;
	}

	ok = realloc_string_sub_raw(&string,
				    pattern,
				    insert,
				    replace_once,
				    allow_trailing_dollar,
				    unsafe_characters,
				    safe_character);
	if (!ok) {
		TALLOC_FREE(string);
		DBG_ERR("out of memory, realloc_string_sub_raw()!\n");
		return NULL;
	}

	return string;
}

/* Same as string_sub, but returns a talloc'ed string */

char *talloc_string_sub(TALLOC_CTX *mem_ctx,
			const char *src,
			const char *pattern,
			const char *insert)
{
	return talloc_string_sub2(mem_ctx, src, pattern, insert,
			true, false, false);
}

char *talloc_all_string_sub(TALLOC_CTX *ctx,
				const char *src,
				const char *pattern,
				const char *insert)
{
	return talloc_string_sub2(ctx, src, pattern, insert,
			false, false, false);
}

#ifndef SAMBA_UTIL_CORE_ONLY

bool talloc_string_sub_mixed_quoting(const char *full_cmd, char variable_char)
{
	/*
	 * Try to make sure talloc_string_sub_unsafe()
	 * won't return NULL, instead talloc_stackframe_pool()
	 * would panic
	 */
	size_t cmd_len = full_cmd != NULL ? strlen(full_cmd) : 0;
	size_t pool_size = 512 + cmd_len;
	TALLOC_CTX *frame = talloc_stackframe_pool(pool_size);
	char *cmd = NULL;
	bool modified = false;
	bool masked = false;
	bool mixed_fallback = false;

	cmd = talloc_string_sub_unsafe(frame,
				       full_cmd,
				       variable_char,
				       "U",  /* unsafe_value */
				       "'\"%", /* unsafe_characters */
				       '_',    /* safe_character */
				       "F",  /* fallback_value */
				       &modified,
				       &masked,
				       &mixed_fallback);
	if (cmd == NULL) {
		mixed_fallback = false;
	}
	TALLOC_FREE(frame);
	return mixed_fallback;
}

char *talloc_string_sub_unsafe(TALLOC_CTX *mem_ctx,
			       const char *orig_cmd,
			       char variable_char,
			       const char *unsafe_value,
			       const char *unsafe_characters,
			       char safe_character,
			       const char *fallback_value,
			       bool *_modified,
			       bool *_masked,
			       bool *_mixed_fallback)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char variable[3] =
		{ '%', variable_char, '\0' };
	const char variable_s_quoted[5] =
		{ '\'', '%', variable_char, '\'', '\0' };
	const char variable_d_quoted[5] =
		{ '"', '%', variable_char, '"', '\0' };
	char *cmd = NULL;
	char *masked_value = NULL;
	char *quoted_value = NULL;
	bool has_s_quotes;
	bool has_d_quotes;
	bool has_variable;
	bool has_variable_s_quoted;
	bool has_variable_d_quoted;
	bool modified = false;
	bool masked = false;
	bool mixed_fallback = false;
	bool ok;

	/*
	 * The unsafe_characters argument should contain
	 * single and double quotes.
	 * Otherwise We can't safely handle this.
	 */
	SMB_ASSERT(unsafe_characters != NULL);
	SMB_ASSERT(strchr(unsafe_characters, '\'') != NULL);
	SMB_ASSERT(strchr(unsafe_characters, '"') != NULL);
	SMB_ASSERT(strchr(unsafe_characters, '%') != NULL);

	cmd = talloc_strdup(mem_ctx, orig_cmd);
	if (cmd == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}
	cmd = talloc_steal(frame, cmd);

	has_variable = strstr(orig_cmd, variable) != NULL;
	if (!has_variable) {
		/*
		 * Nothing to do...
		 */
		goto done;
	}
	modified = true;

	/*
	 * Replace all unsafe characters as well as control
	 * characters.
	 *
	 * Note that we start with masked_value = "%u"
	 * and then replace "%u" with unsafe_value,
	 * as a result we have a masked version of
	 * unsafe_value.
	 *
	 * And don't allow option injected like
	 *
	 * '-h value'
	 * '--help value'
	 *
	 */
	masked_value = talloc_strdup(frame, variable);
	if (masked_value == NULL) {
		goto nomem;
	}
	ok = realloc_string_sub_raw(&masked_value,
				    variable,
				    unsafe_value,
				    false, /* replace_once */
				    false, /* allow_trailing_dollar */
				    unsafe_characters,
				    safe_character);
	if (!ok) {
		goto nomem;
	}
	if (masked_value[0] == '-') {
		masked_value[0] = safe_character;
	}
	masked = strcmp(masked_value, unsafe_value) != 0;

retry:

	has_s_quotes = strchr(cmd, '\'') != NULL;
	has_d_quotes = strchr(cmd, '"') != NULL;
	has_variable = strstr(cmd, variable) != NULL;
	has_variable_s_quoted = strstr(cmd, variable_s_quoted) != NULL;
	has_variable_d_quoted = strstr(cmd, variable_d_quoted) != NULL;

	if (has_variable_s_quoted) {
		/*
		 * In smb.conf we have something like
		 *
		 * some script = /usr/bin/script '%u'
		 *
		 * It is safe to replace '%u' (or '%J' etc, depending
		 * on variable_char) with '<masked_value>' if
		 * masked_value does not contain single quotes. We
		 * have checked that.
		 */

		if (quoted_value == NULL) {
			quoted_value = talloc_asprintf(frame, "'%s'",
						       masked_value);
			if (quoted_value == NULL) {
				goto nomem;
			}
		}

		ok = realloc_string_sub_raw(&cmd,
					    variable_s_quoted,
					    quoted_value,
					    false, /* replace_once */
					    false, /* allow_trailing_dollar */
					    NULL,  /* unsafe_characters */
					    '\0'); /* safe_character */
		if (!ok) {
			goto nomem;
		}

		goto retry;
	}

	if (has_variable_d_quoted && !has_s_quotes) {
		/*
		 * replace the "%u"
		 *
		 * some script = /usr/bin/script "%u"
		 *
		 * with '%u' and try the '%u' -> 'variable' substitution
		 * again.
		 */

		ok = realloc_string_sub_raw(&cmd,
					    variable_d_quoted,
					    variable_s_quoted,
					    false, /* replace_once */
					    false, /* allow_trailing_dollar */
					    NULL,  /* unsafe_characters */
					    '\0'); /* safe_character */
		if (!ok) {
			goto nomem;
		}

		goto retry;
	}

	if (has_variable && !has_s_quotes && !has_d_quotes) {
		/*
		 * In this case:
		 *
		 * some script = /usr/bin/script %u
		 *
		 * we can safely substitute %u -> '%u' and try the
		 * single quote test again.
		 */

		ok = realloc_string_sub_raw(&cmd,
					    variable,
					    variable_s_quoted,
					    false, /* replace_once */
					    false, /* allow_trailing_dollar */
					    NULL,  /* unsafe_characters */
					    '\0'); /* safe_character */
		if (!ok) {
			goto nomem;
		}

		goto retry;
	}

	if (has_variable) {
		/*
		 * There are single or double quotes, but not tightly
		 * bound around a %u.
		 *
		 * Or there's a mix of single and double quotes.
		 *
		 * We just use a generic fallback value.
		 * and let the caller warn about this
		 * and give the admin a hind to fix the smb.conf
		 * option.
		 */
		mixed_fallback = true;

		ok = realloc_string_sub_raw(&cmd,
					    variable,
					    fallback_value,
					    false, /* replace_once */
					    false, /* allow_trailing_dollar */
					    NULL,  /* unsafe_characters */
					    '\0'); /* safe_character */
		if (!ok) {
			goto nomem;
		}
	}

done:
	*_modified = modified;
	*_masked = masked;
	*_mixed_fallback = mixed_fallback;
	cmd = talloc_steal(mem_ctx, cmd);
	TALLOC_FREE(frame);
	return cmd;

nomem:
	*_modified = false;
	*_masked = false;
	*_mixed_fallback = false;
	TALLOC_FREE(frame);
	return NULL;
}
#endif /* ! SAMBA_UTIL_CORE_ONLY */
