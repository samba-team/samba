/*
   Unix SMB/CIFS implementation.

   Functions to create reasonable random numbers for crypto use.

   Copyright (C) Jeremy Allison 2001

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

/**
 * @file
 * @brief Random number generation
 */

/**
  generate a single random uint32_t
**/
_PUBLIC_ uint32_t generate_random(void)
{
	uint8_t v[4];
	generate_random_buffer(v, 4);
	return IVAL(v, 0);
}

/**
  @brief generate a random uint64
**/
_PUBLIC_ uint64_t generate_random_u64(void)
{
	uint8_t v[8];
	generate_random_buffer(v, 8);
	return BVAL(v, 0);
}

static struct generate_unique_u64_state {
	uint64_t next_value;
	int pid;
} generate_unique_u64_state;

_PUBLIC_ uint64_t generate_unique_u64(uint64_t veto_value)
{
	int pid = getpid();

	if (unlikely(pid != generate_unique_u64_state.pid)) {
		generate_unique_u64_state = (struct generate_unique_u64_state) {
			.pid = pid,
			.next_value = veto_value,
		};
	}

	while (unlikely(generate_unique_u64_state.next_value == veto_value)) {
		generate_nonce_buffer(
				(void *)&generate_unique_u64_state.next_value,
				sizeof(generate_unique_u64_state.next_value));
	}

	return generate_unique_u64_state.next_value++;
}

/**
  Microsoft composed the following rules (among others) for quality
  checks. This is an abridgment from
  http://msdn.microsoft.com/en-us/subscriptions/cc786468%28v=ws.10%29.aspx:

  Passwords must contain characters from three of the following five
  categories:

   - Uppercase characters of European languages (A through Z, with
     diacritic marks, Greek and Cyrillic characters)
   - Lowercase characters of European languages (a through z, sharp-s,
     with diacritic marks, Greek and Cyrillic characters)
   - Base 10 digits (0 through 9)
   - Nonalphanumeric characters: ~!@#$%^&*_-+=`|\(){}[]:;"'<>,.?/
   - Any Unicode character that is categorized as an alphabetic character
     but is not uppercase or lowercase. This includes Unicode characters
     from Asian languages.

 Note: for now do not check if the unicode category is
       alphabetic character
**/
_PUBLIC_ bool check_password_quality(const char *pwd)
{
	size_t ofs = 0;
	size_t num_chars = 0;
	size_t num_digits = 0;
	size_t num_upper = 0;
	size_t num_lower = 0;
	size_t num_nonalpha = 0;
	size_t num_unicode = 0;
	size_t num_categories = 0;

	if (pwd == NULL) {
		return false;
	}

	while (true) {
		const char *s = &pwd[ofs];
		size_t len = 0;
		codepoint_t c;

		c = next_codepoint(s, &len);
		if (c == INVALID_CODEPOINT) {
			return false;
		} else if (c == 0) {
			break;
		}
		ofs += len;
		num_chars += 1;

		if (len == 1) {
			const char *na = "~!@#$%^&*_-+=`|\\(){}[]:;\"'<>,.?/";

			if (isdigit(c)) {
				num_digits += 1;
				continue;
			}

			if (isupper(c)) {
				num_upper += 1;
				continue;
			}

			if (islower(c)) {
				num_lower += 1;
				continue;
			}

			if (strchr(na, c)) {
				num_nonalpha += 1;
				continue;
			}

			/*
			 * the rest does not belong to
			 * a category.
			 */
			continue;
		}

		if (isupper_m(c)) {
			num_upper += 1;
			continue;
		}

		if (islower_m(c)) {
			num_lower += 1;
			continue;
		}

		/*
		 * Note: for now do not check if the unicode category is
		 *       alphabetic character
		 *
		 * We would have to import the details from
		 * ftp://ftp.unicode.org/Public/6.3.0/ucd/UnicodeData-6.3.0d1.txt
		 */
		num_unicode += 1;
		continue;
	}

	if (num_digits > 0) {
		num_categories += 1;
	}
	if (num_upper > 0) {
		num_categories += 1;
	}
	if (num_lower > 0) {
		num_categories += 1;
	}
	if (num_nonalpha > 0) {
		num_categories += 1;
	}
	if (num_unicode > 0) {
		num_categories += 1;
	}

	if (num_categories >= 3) {
		return true;
	}

	return false;
}

/**
 Use the random number generator to generate a random string.
**/

_PUBLIC_ char *generate_random_str_list(TALLOC_CTX *mem_ctx, size_t len, const char *list)
{
	size_t i;
	size_t list_len = strlen(list);

	char *retstr = talloc_array(mem_ctx, char, len + 1);
	if (!retstr) return NULL;

	generate_secret_buffer((uint8_t *)retstr, len);
	for (i = 0; i < len; i++) {
		retstr[i] = list[retstr[i] % list_len];
	}
	retstr[i] = '\0';

	return retstr;
}

/**
 * Generate a random text string consisting of the specified length.
 * The returned string will be allocated.
 *
 * Characters used are: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_-#.,
 */

_PUBLIC_ char *generate_random_str(TALLOC_CTX *mem_ctx, size_t len)
{
	char *retstr;
	const char *c_list = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_-#.,";

again:
	retstr = generate_random_str_list(mem_ctx, len, c_list);
	if (!retstr) return NULL;

	/* we need to make sure the random string passes basic quality tests
	   or it might be rejected by windows as a password */
	if (len >= 7 && !check_password_quality(retstr)) {
		talloc_free(retstr);
		goto again;
	}

	return retstr;
}

/**
 * Generate a random text password (based on printable ascii characters).
 */

_PUBLIC_ char *generate_random_password(TALLOC_CTX *mem_ctx, size_t min, size_t max)
{
	char *retstr;
	/* This list does not include { or } because they cause
	 * problems for our provision (it can create a substring
	 * ${...}, and for Fedora DS (which treats {...} at the start
	 * of a stored password as special
	 *  -- Andrew Bartlett 2010-03-11
	 */
	const char *c_list = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_-#.,@$%&!?:;<=>()[]~";
	size_t len = max;
	size_t diff;

	if (min > max) {
		errno = EINVAL;
		return NULL;
	}

	diff = max - min;

	if (diff > 0 ) {
		size_t tmp;

		generate_secret_buffer((uint8_t *)&tmp, sizeof(tmp));

		tmp %= diff;

		len = min + tmp;
	}

again:
	retstr = generate_random_str_list(mem_ctx, len, c_list);
	if (!retstr) return NULL;

	/* we need to make sure the random string passes basic quality tests
	   or it might be rejected by windows as a password */
	if (len >= 7 && !check_password_quality(retstr)) {
		talloc_free(retstr);
		goto again;
	}

	return retstr;
}

/**
 * Generate a random machine password (based on random utf16 characters,
 * converted to utf8). min must be at least 14, max must be at most 255.
 *
 * If 'unix charset' is not utf8, the password consist of random ascii
 * values!
 */

_PUBLIC_ char *generate_random_machine_password(TALLOC_CTX *mem_ctx, size_t min, size_t max)
{
	TALLOC_CTX *frame = NULL;
	struct generate_random_machine_password_state {
		uint8_t password_buffer[256 * 2];
		uint8_t tmp;
	} *state;
	char *new_pw = NULL;
	size_t len = max;
	char *utf8_pw = NULL;
	size_t utf8_len = 0;
	char *unix_pw = NULL;
	size_t unix_len = 0;
	size_t diff;
	size_t i;
	bool ok;
	int cmp;

	if (max > 255) {
		errno = EINVAL;
		return NULL;
	}

	if (min < 14) {
		errno = EINVAL;
		return NULL;
	}

	if (min > max) {
		errno = EINVAL;
		return NULL;
	}

	frame = talloc_stackframe_pool(2048);
	state = talloc_zero(frame, struct generate_random_machine_password_state);

	diff = max - min;

	if (diff > 0) {
		size_t tmp;

		generate_secret_buffer((uint8_t *)&tmp, sizeof(tmp));

		tmp %= diff;

		len = min + tmp;
	}

	/*
	 * Create a random machine account password
	 * We create a random buffer and convert that to utf8.
	 * This is similar to what windows is doing.
	 *
	 * In future we may store the raw random buffer,
	 * but for now we need to pass the password as
	 * char pointer through some layers.
	 *
	 * As most kerberos keys are derived from the
	 * utf8 password we need to fallback to
	 * ASCII passwords if "unix charset" is not utf8.
	 */
	generate_secret_buffer(state->password_buffer, len * 2);
	for (i = 0; i < len; i++) {
		size_t idx = i*2;
		uint16_t c;

		/*
		 * both MIT krb5 and HEIMDAL only
		 * handle codepoints up to 0xffff.
		 *
		 * It means we need to avoid
		 * 0xD800 - 0xDBFF (high surrogate)
		 * and
		 * 0xDC00 - 0xDFFF (low surrogate)
		 * in the random utf16 data.
		 *
		 * 55296 0xD800 0154000 0b1101100000000000
		 * 57343 0xDFFF 0157777 0b1101111111111111
		 * 8192  0x2000  020000   0b10000000000000
		 *
		 * The above values show that we can check
		 * for 0xD800 and just add 0x2000 to avoid
		 * the surrogate ranges.
		 *
		 * The rest will be handled by CH_UTF16MUNGED
		 * see utf16_munged_pull().
		 */
		c = SVAL(state->password_buffer, idx);
		if (c & 0xD800) {
			c |= 0x2000;
		}
		SSVAL(state->password_buffer, idx, c);
	}
	ok = convert_string_talloc(frame,
				   CH_UTF16MUNGED, CH_UTF8,
				   state->password_buffer, len * 2,
				   (void *)&utf8_pw, &utf8_len);
	if (!ok) {
		DEBUG(0, ("%s: convert_string_talloc() failed\n",
			  __func__));
		TALLOC_FREE(frame);
		return NULL;
	}

	ok = convert_string_talloc(frame,
				   CH_UTF16MUNGED, CH_UNIX,
				   state->password_buffer, len * 2,
				   (void *)&unix_pw, &unix_len);
	if (!ok) {
		goto ascii_fallback;
	}

	if (utf8_len != unix_len) {
		goto ascii_fallback;
	}

	cmp = memcmp((const uint8_t *)utf8_pw,
		     (const uint8_t *)unix_pw,
		     utf8_len);
	if (cmp != 0) {
		goto ascii_fallback;
	}

	new_pw = talloc_strdup(mem_ctx, utf8_pw);
	if (new_pw == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}
	talloc_set_name_const(new_pw, __func__);
	TALLOC_FREE(frame);
	return new_pw;

ascii_fallback:
	for (i = 0; i < len; i++) {
		/*
		 * truncate to ascii
		 */
		state->tmp = state->password_buffer[i] & 0x7f;
		if (state->tmp == 0) {
			state->tmp = state->password_buffer[i] >> 1;
		}
		if (state->tmp == 0) {
			state->tmp = 0x01;
		}
		state->password_buffer[i] = state->tmp;
	}
	state->password_buffer[i] = '\0';

	new_pw = talloc_strdup(mem_ctx, (const char *)state->password_buffer);
	if (new_pw == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}
	talloc_set_name_const(new_pw, __func__);
	TALLOC_FREE(frame);
	return new_pw;
}

/**
 * Generate an array of unique text strings all of the same length.
 * The returned string will be allocated.
 * Returns NULL if the number of unique combinations cannot be created.
 *
 * Characters used are: abcdefghijklmnopqrstuvwxyz0123456789+_-#.,
 */
_PUBLIC_ char** generate_unique_strs(TALLOC_CTX *mem_ctx, size_t len,
				     uint32_t num)
{
	const char *c_list = "abcdefghijklmnopqrstuvwxyz0123456789+_-#.,";
	const unsigned c_size = 42;
	size_t i, j;
	unsigned rem;
	char ** strs = NULL;

	if (num == 0 || len == 0)
		return NULL;

	strs = talloc_array(mem_ctx, char *, num);
	if (strs == NULL) return NULL;

	for (i = 0; i < num; i++) {
		char *retstr = (char *)talloc_size(strs, len + 1);
		if (retstr == NULL) {
			talloc_free(strs);
			return NULL;
		}
		rem = i;
		for (j = 0; j < len; j++) {
			retstr[j] = c_list[rem % c_size];
			rem = rem / c_size;
		}
		retstr[j] = 0;
		strs[i] = retstr;
		if (rem != 0) {
			/* we were not able to fit the number of
			 * combinations asked for in the length
			 * specified */
			DEBUG(0,(__location__ ": Too many combinations %u for length %u\n",
				 num, (unsigned)len));

			talloc_free(strs);
			return NULL;
		}
	}

	return strs;
}
