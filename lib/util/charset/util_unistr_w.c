/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jeremy Allison 2005

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

/* Copy into a smb_ucs2_t from a possibly unaligned buffer. Return the copied smb_ucs2_t */
#define COPY_UCS2_CHAR(dest,src) (((unsigned char *)(dest))[0] = ((const unsigned char *)(src))[0],\
				((unsigned char *)(dest))[1] = ((const unsigned char *)(src))[1], (dest))


/* return an ascii version of a ucs2 character */
#define UCS2_TO_CHAR(c) (((c) >> UCS2_SHIFT) & 0xff)

static int strncmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b, size_t len);

/*******************************************************************
 Count the number of two-byte pairs in a UTF16 string.
********************************************************************/

size_t strlen_w(const smb_ucs2_t *src)
{
	size_t len;
	smb_ucs2_t c;

	for(len = 0; *(COPY_UCS2_CHAR(&c,src)); src++, len++) {
		;
	}

	return len;
}

/*******************************************************************
 Count up to max number of characters in a smb_ucs2_t string.
********************************************************************/

size_t strnlen_w(const smb_ucs2_t *src, size_t max)
{
	size_t len;
	smb_ucs2_t c;

	for(len = 0; (len < max) && *(COPY_UCS2_CHAR(&c,src)); src++, len++) {
		;
	}

	return len;
}

/*******************************************************************
 Wide strchr().
********************************************************************/

smb_ucs2_t *strchr_w(const smb_ucs2_t *s, smb_ucs2_t c)
{
	smb_ucs2_t cp;
	while (*(COPY_UCS2_CHAR(&cp,s))) {
		if (c == cp) {
			return discard_const_p(smb_ucs2_t, s);
		}
		s++;
	}
	if (c == cp) {
		return discard_const_p(smb_ucs2_t, s);
	}

	return NULL;
}

smb_ucs2_t *strchr_wa(const smb_ucs2_t *s, char c)
{
	return strchr_w(s, UCS2_CHAR(c));
}

/*******************************************************************
 Wide strrchr().
********************************************************************/

smb_ucs2_t *strrchr_w(const smb_ucs2_t *s, smb_ucs2_t c)
{
	smb_ucs2_t cp;
	const smb_ucs2_t *p = s;
	int len = strlen_w(s);

	if (len == 0) {
		return NULL;
	}
	p += (len - 1);
	do {
		if (c == *(COPY_UCS2_CHAR(&cp,p))) {
			return discard_const_p(smb_ucs2_t, p);
		}
	} while (p-- != s);
	return NULL;
}

/*******************************************************************
 Wide version of strrchr that returns after doing strrchr 'n' times.
********************************************************************/

smb_ucs2_t *strnrchr_w(const smb_ucs2_t *s, smb_ucs2_t c, unsigned int n)
{
	smb_ucs2_t cp;
	const smb_ucs2_t *p = s;
	int len = strlen_w(s);

	if (len == 0 || !n) {
		return NULL;
	}
	p += (len - 1);
	do {
		if (c == *(COPY_UCS2_CHAR(&cp,p))) {
			n--;
		}

		if (!n) {
			return discard_const_p(smb_ucs2_t, p);
		}
	} while (p-- != s);
	return NULL;
}

/*******************************************************************
 Wide strstr().
********************************************************************/

smb_ucs2_t *strstr_w(const smb_ucs2_t *s, const smb_ucs2_t *ins)
{
	const smb_ucs2_t *r;
	size_t inslen;

	if (!s || !*s || !ins || !*ins) {
		return NULL;
	}

	inslen = strlen_w(ins);
	r = s;

	while ((r = strchr_w(r, *ins))) {
		if (strncmp_w(r, ins, inslen) == 0) {
			return discard_const_p(smb_ucs2_t, r);
		}
		r++;
	}

	return NULL;
}

/*******************************************************************
 Convert a string to lower case.
 return True if any char is converted

 This is unsafe for any string involving a UTF16 character
********************************************************************/

bool strlower_w(smb_ucs2_t *s)
{
	smb_ucs2_t cp;
	bool ret = false;

	while (*(COPY_UCS2_CHAR(&cp,s))) {
		smb_ucs2_t v = tolower_m(cp);
		if (v != cp) {
			(void)COPY_UCS2_CHAR(s,&v);
			ret = true;
		}
		s++;
	}
	return ret;
}

/*******************************************************************
 Convert a string to upper case.
 return True if any char is converted

 This is unsafe for any string involving a UTF16 character
********************************************************************/

bool strupper_w(smb_ucs2_t *s)
{
	smb_ucs2_t cp;
	bool ret = false;
	while (*(COPY_UCS2_CHAR(&cp,s))) {
		smb_ucs2_t v = toupper_m(cp);
		if (v != cp) {
			(void)COPY_UCS2_CHAR(s,&v);
			ret = true;
		}
		s++;
	}
	return ret;
}

static int strncmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b, size_t len)
{
	smb_ucs2_t cpa, cpb;
	size_t n = 0;

	while ((n < len) && (*(COPY_UCS2_CHAR(&cpb,b))) && (*(COPY_UCS2_CHAR(&cpa,a)) == cpb)) {
		a++;
		b++;
		n++;
	}
	return (len - n)?(*(COPY_UCS2_CHAR(&cpa,a)) - *(COPY_UCS2_CHAR(&cpb,b))):0;
}

/*
  The *_wa() functions take a combination of 7 bit ascii
  and wide characters They are used so that you can use string
  functions combining C string constants with ucs2 strings

  The char* arguments must NOT be multibyte - to be completely sure
  of this only pass string constants */

int strcmp_wa(const smb_ucs2_t *a, const char *b)
{
	smb_ucs2_t cp = 0;

	while (*b && *(COPY_UCS2_CHAR(&cp,a)) == UCS2_CHAR(*b)) {
		a++;
		b++;
	}
	return (*(COPY_UCS2_CHAR(&cp,a)) - UCS2_CHAR(*b));
}

smb_ucs2_t toupper_w(smb_ucs2_t v)
{
	smb_ucs2_t ret;
	/* LE to native. */
	codepoint_t cp = SVAL(&v,0);
	cp = toupper_m(cp);
	/* native to LE. */
	SSVAL(&ret,0,cp);
	return ret;
}
