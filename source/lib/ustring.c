/* 
   Dynamic Unicode Strings
   Copyright (C) Elrond                            2000

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "ustring.h"

#define g_free(x) safe_free(x)


#define INITIAL_SIZE 32


UString *ustring_new(const char *init)
{
	UString *str;

	str = g_new(UString, 1);
	if (str == NULL)
	{
		return str;
	}
	str->len = 0;
	str->alloc = INITIAL_SIZE;
	str->str = g_new(uint16, str->alloc);
	if(str->str == NULL)
	{
		g_free(str);
		return NULL;
	}
	str->str[0] = 0;

	if (init)
	{
		ustring_assign_ascii_str(str, init);
	}

	return str;
}

void ustring_free(UString *str)
{
	if (! str)
	{
		return;
	}
	g_free(str->str);
	g_free(str);
}

static size_t nearest_pow(size_t n)
{
	size_t i = 1;
	while (i < n)
	{
		i *= 2;
	}
	return i;
}

UString *ustring_grow(UString *str, size_t new_alloc)
{
	if(! str)
	{
		return str;
	}
	if(str->alloc >= new_alloc)
	{
		return str;
	}
	new_alloc = nearest_pow(new_alloc);
	str->str = g_renew(uint16, str->str, new_alloc);
	if (str->str == NULL)
	{
		new_alloc = 0;
		str->len = 0;
	}
	str->alloc = new_alloc;
	return str;
}

UString *ustring_shrink(UString *str)
{
	size_t new_alloc;

	if(! str)
	{
		return str;
	}
	new_alloc = str->len + 1;
	if (new_alloc == str->alloc)
	{
		return str;
	}

	str->str = g_renew(uint16, str->str, new_alloc);
	str->alloc = new_alloc;
	return str;
}

UString *ustring_assign(UString *str, const uint16 *src, size_t len)
{
	if (! str)
	{
		return str;
	}
	if ((src == NULL) || (len == 0))
	{
		str->len = 0;
		str->str[0] = 0;
	}

	ustring_grow(str, len+1);

	memcpy(str->str, src, len*sizeof(uint16));

	str->str[len] = 0;
	str->len = len;

	return str;
}

UString *ustring_assign_ascii(UString *str, const char *src, size_t len)
{
	uint16 *dest;

	if (! str)
	{
		return str;
	}
	if ((src == NULL) || (len == 0))
	{
		str->len = 0;
		str->str[0] = 0;
		return str;
	}
	ustring_grow(str, len+1);

	str->len = len;

	dest = str->str;

	while (len > 0)
	{
		char c = *src++;
		*dest++ = c;
		len--;
	}

	*dest = 0;

	return str;
}

UString *ustring_assign_ascii_str(UString *str, const char *src)
{
	return ustring_assign_ascii(str, src, (src ? strlen(src) : 0));
}

UString *ustring_dup(const UString *str)
{
	UString *new;

	if (! str)
	{
		return str;
	}
	new = ustring_new(NULL);
	if (! new)
	{
		return new;
	}

	ustring_assign(new, str->str, str->len);

	return new;
}

int ustring_compare(const UString *a, const UString *b)
{
	uint16 *pa, *pb;
	int ca, cb;
	size_t len;

	if (a == b) return 0;
	if (!a) return 1;
	if (!b) return -1;

	pa = a->str;
	pb = b->str;
	len = MIN(a->len, b->len) + 1; /* include the final NUL */

	while ((len > 0) && (*pa == *pb))
	{
		pa++;
		pb++;
		len--;
	}
	if (len == 0)
	{
		if (a->len == b->len) return 0;
		if (a->len <  b->len) return 1;
		return 1;
	}

	ca = *pa;
	cb = *pb;

	return cb - ca;
}

int ustring_compare_case(const UString *a, const UString *b)
{
	uint16 *pa, *pb;
	int ca, cb;
	size_t len;

	if (a == b) return 0;
	if (!a) return 1;
	if (!b) return -1;

	pa = a->str;
	pb = b->str;
	len = MIN(a->len, b->len) + 1; /* include the final NUL */

	while ((len > 0) && (toupper(*pa) == toupper(*pb)))
	{
		pa++;
		pb++;
		len--;
	}
	if (len == 0)
	{
		if (a->len == b->len) return 0;
		if (a->len <  b->len) return 1;
		return 1;
	}

	ca = toupper(*pa);
	cb = toupper(*pb);

	return cb - ca;
}

UString *ustring_append_c(UString *str, uint16 c)
{
	if (! str)
	{
		return str;
	}
	ustring_grow(str, str->len + 2);
	str->str[str->len] = c;
	str->len++;
	str->str[str->len] = 0;

	return str;
}

UString *ustring_sync_len(UString *str)
{
	uint16 *p, *a;

	if (! str)
	{
		return str;
	}

	a = str->str;
	p = a + str->len - 1;
	while((p > a) && (*p == 0))
	{
		p--;
	}
	p++;
	str->len = p - a;

	return str;
}

UString *ustring_upper(UString *str)
{
	uint16 *p, *e;

	if (! str)
	{
		return str;
	}

	p = str->str;
	e = p + str->len;

	while (p < e)
	{
		*p = toupper(*p);
		p++;
	}

	return str;
}

UString *ustring_lower(UString *str)
{
	uint16 *p, *e;

	if (! str)
	{
		return str;
	}

	p = str->str;
	e = p + str->len;

	while (p < e)
	{
		*p = tolower(*p);
		p++;
	}

	return str;
}

BOOL ustring_equal(const UString *s1, const UString *s2)
{
	UString *a;
	UString *b;
	BOOL ret;

	a = ustring_sync_len(ustring_dup(s1));
	b = ustring_sync_len(ustring_dup(s2));
	ret = ustring_compare_case(a, b);

	ustring_free(a);
	ustring_free(b);

	return ret;
}
