/* 
   Unix SMB/CIFS implementation.
   Character set conversion Extensions
   Copyright (C) Igor Vergeichik <iverg@mail.ru> 2001
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Simo Sorce 2001
   Copyright (C) Martin Pool 2003
   
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

/**
 * @file
 *
 * @brief Character-set conversion routines built on our iconv.
 * 
 * @note Samba's internal character set (at least in the 3.0 series)
 * is always the same as the one for the Unix filesystem.  It is
 * <b>not</b> necessarily UTF-8 and may be different on machines that
 * need i18n filenames to be compatible with Unix software.  It does
 * have to be a superset of ASCII.  All multibyte sequences must start
 * with a byte with the high bit set.
 *
 * @sa lib/iconv.c
 */


static smb_iconv_t conv_handles[NUM_CHARSETS][NUM_CHARSETS];
static BOOL conv_silent; /* Should we do a debug if the conversion fails ? */

/**
 * Return the name of a charset to give to iconv().
 **/
static const char *charset_name(charset_t ch)
{
	const char *ret = NULL;

	if (ch == CH_UCS2) ret = "UCS-2LE";
	else if (ch == CH_UNIX) ret = lp_unix_charset();
	else if (ch == CH_DOS) ret = lp_dos_charset();
	else if (ch == CH_DISPLAY) ret = lp_display_charset();
	else if (ch == CH_UTF8) ret = "UTF8";

#if defined(HAVE_NL_LANGINFO) && defined(CODESET)
	if (ret && strcasecmp(ret, "LOCALE") == 0) {
		const char *ln = NULL;

#ifdef HAVE_SETLOCALE
		setlocale(LC_ALL, "");
#endif
		ln = nl_langinfo(CODESET);
		if (ln) {
			/* Check whether the charset name is supported
			   by iconv */
			smb_iconv_t handle = smb_iconv_open(ln,"UCS-2LE");
			if (handle == (smb_iconv_t) -1) {
				DEBUG(5,("Locale charset '%s' unsupported, using ASCII instead\n", ln));
				ln = NULL;
			} else {
				DEBUG(5,("Substituting charset '%s' for LOCALE\n", ln));
				smb_iconv_close(handle);
			}
		}
		ret = ln;
	}
#endif

	if (!ret || !*ret) ret = "ASCII";
	return ret;
}

void lazy_initialize_conv(void)
{
	static int initialized = False;

	if (!initialized) {
		initialized = True;
		load_case_tables();
		init_iconv();
	}
}

/**
 * Initialize iconv conversion descriptors.
 *
 * This is called the first time it is needed, and also called again
 * every time the configuration is reloaded, because the charset or
 * codepage might have changed.
 **/
void init_iconv(void)
{
	int c1, c2;
	BOOL did_reload = False;

	/* so that charset_name() works we need to get the UNIX<->UCS2 going
	   first */
	if (!conv_handles[CH_UNIX][CH_UCS2])
		conv_handles[CH_UNIX][CH_UCS2] = smb_iconv_open("UCS-2LE", "ASCII");

	if (!conv_handles[CH_UCS2][CH_UNIX])
		conv_handles[CH_UCS2][CH_UNIX] = smb_iconv_open("ASCII", "UCS-2LE");

	for (c1=0;c1<NUM_CHARSETS;c1++) {
		for (c2=0;c2<NUM_CHARSETS;c2++) {
			const char *n1 = charset_name((charset_t)c1);
			const char *n2 = charset_name((charset_t)c2);
			if (conv_handles[c1][c2] &&
			    strcmp(n1, conv_handles[c1][c2]->from_name) == 0 &&
			    strcmp(n2, conv_handles[c1][c2]->to_name) == 0)
				continue;

			did_reload = True;

			if (conv_handles[c1][c2])
				smb_iconv_close(conv_handles[c1][c2]);

			conv_handles[c1][c2] = smb_iconv_open(n2,n1);
			if (conv_handles[c1][c2] == (smb_iconv_t)-1) {
				DEBUG(0,("Conversion from %s to %s not supported\n",
					 charset_name((charset_t)c1), charset_name((charset_t)c2)));
				conv_handles[c1][c2] = NULL;
			}
		}
	}

	if (did_reload) {
		/* XXX: Does this really get called every time the dos
		 * codepage changes? */
		/* XXX: Is the did_reload test too strict? */
		conv_silent = True;
		init_doschar_table();
		init_valid_table();
		conv_silent = False;
	}
}

/**
 * Convert string from one encoding to another, making error checking etc
 *
 * @param src pointer to source string (multibyte or singlebyte)
 * @param srclen length of the source string in bytes
 * @param dest pointer to destination string (multibyte or singlebyte)
 * @param destlen maximal length allowed for string
 * @returns the number of bytes occupied in the destination
 *
 * Ensure the srclen contains the terminating zero.
 *
 **/
size_t convert_string(charset_t from, charset_t to,
		      void const *src, size_t srclen, 
		      void *dest, size_t destlen)
{
	size_t i_len, o_len;
	size_t retval;
	const char* inbuf = (const char*)src;
	char* outbuf = (char*)dest;
	smb_iconv_t descriptor;

	if (srclen == (size_t)-1)
		srclen = strlen(src)+1;
	if (srclen == 0)
		return 0;

	lazy_initialize_conv();

	descriptor = conv_handles[from][to];

	if (descriptor == (smb_iconv_t)-1 || descriptor == (smb_iconv_t)0) {
		if (!conv_silent)
			DEBUG(0,("convert_string: Conversion not supported.\n"));
		goto use_as_is;
	}

	i_len=srclen;
	o_len=destlen;
	retval = smb_iconv(descriptor,  &inbuf, &i_len, &outbuf, &o_len);
	if(retval==(size_t)-1) {
	    	const char *reason="unknown error";
		switch(errno) {
			case EINVAL:
				reason="Incomplete multibyte sequence";
				if (!conv_silent)
					DEBUG(3,("convert_string: Conversion error: %s(%s)\n",reason,inbuf));
				goto use_as_is;
			case E2BIG:
				reason="No more room"; 
				if (!conv_silent)
					DEBUG(3, ("convert_string: Required %lu, available %lu\n",
						(unsigned long)srclen, (unsigned long)destlen));
				/* we are not sure we need srclen bytes,
			          may be more, may be less.
				  We only know we need more than destlen
				  bytes ---simo */
		               break;
			case EILSEQ:
				reason="Illegal multibyte sequence";
				if (!conv_silent)
					DEBUG(3,("convert_string: Conversion error: %s(%s)\n",reason,inbuf));
				goto use_as_is;
			default:
				if (!conv_silent)
					DEBUG(0,("convert_string: Conversion error: %s(%s)\n",reason,inbuf));
				break;
		}
		/* smb_panic(reason); */
	}
	return destlen-o_len;

 use_as_is:

	/* conversion not supported, use as is */
	{
		size_t len = MIN(srclen,destlen);
		if (len)
			memcpy(dest,src,len);
		return len;
	}
}

/**
 * Convert between character sets, allocating a new buffer for the result.
 *
 * @param ctx TALLOC_CTX to use to allocate with. If NULL use malloc.
 * @param srclen length of source buffer.
 * @param dest always set at least to NULL
 * @note -1 is not accepted for srclen.
 *
 * @returns Size in bytes of the converted string; or -1 in case of error.
 *
 * Ensure the srclen contains the terminating zero.
 **/

size_t convert_string_allocate(TALLOC_CTX *ctx, charset_t from, charset_t to,
			       void const *src, size_t srclen, void **dest)
{
	size_t i_len, o_len, destlen = MAX(srclen, 512);
	size_t retval;
	const char *inbuf = (const char *)src;
	char *outbuf = NULL, *ob = NULL;
	smb_iconv_t descriptor;

	*dest = NULL;

	if (src == NULL || srclen == (size_t)-1)
		return (size_t)-1;
	if (srclen == 0)
		return 0;

	lazy_initialize_conv();

	descriptor = conv_handles[from][to];

	if (descriptor == (smb_iconv_t)-1 || descriptor == (smb_iconv_t)0) {
		if (!conv_silent)
			DEBUG(0,("convert_string_allocate: Conversion not supported.\n"));
		goto use_as_is;
	}

convert:
	if ((destlen*2) < destlen) {
		/* wrapped ! abort. */
		if (!conv_silent)
			DEBUG(0, ("convert_string_allocate: destlen wrapped !\n"));
		if (!ctx)
			SAFE_FREE(outbuf);
		return (size_t)-1;
	} else {
		destlen = destlen * 2;
	}

	if (ctx)
		ob = (char *)talloc_realloc(ctx, ob, destlen);
	else
		ob = (char *)Realloc(ob, destlen);

	if (!ob) {
		DEBUG(0, ("convert_string_allocate: realloc failed!\n"));
		if (!ctx)
			SAFE_FREE(outbuf);
		return (size_t)-1;
	} else {
		outbuf = ob;
	}
	i_len = srclen;
	o_len = destlen;
	retval = smb_iconv(descriptor,
			   &inbuf, &i_len,
			   &outbuf, &o_len);
	if(retval == (size_t)-1) 		{
	    	const char *reason="unknown error";
		switch(errno) {
			case EINVAL:
				reason="Incomplete multibyte sequence";
				if (!conv_silent)
					DEBUG(3,("convert_string_allocate: Conversion error: %s(%s)\n",reason,inbuf));
				goto use_as_is;
			case E2BIG:
				goto convert;		
			case EILSEQ:
				reason="Illegal multibyte sequence";
				if (!conv_silent)
					DEBUG(3,("convert_string_allocate: Conversion error: %s(%s)\n",reason,inbuf));
				goto use_as_is;
		}
		if (!conv_silent)
			DEBUG(0,("Conversion error: %s(%s)\n",reason,inbuf));
		/* smb_panic(reason); */
		return (size_t)-1;
	}
	
	destlen = destlen - o_len;
	if (ctx)
		*dest = (char *)talloc_realloc(ctx,ob,destlen);
	else
		*dest = (char *)Realloc(ob,destlen);
	if (destlen && !*dest) {
		DEBUG(0, ("convert_string_allocate: out of memory!\n"));
		if (!ctx)
			SAFE_FREE(ob);
		return (size_t)-1;
	}

	return destlen;

  use_as_is:

	/* conversion not supported, use as is */
	{
		if (srclen && (destlen != srclen)) {
			destlen = srclen;
			if (ctx)
				ob = (char *)talloc_realloc(ctx, ob, destlen);
			else
				ob = (char *)Realloc(ob, destlen);
			if (!ob) {
				DEBUG(0, ("convert_string_allocate: realloc failed!\n"));
				if (!ctx)
					SAFE_FREE(outbuf);
				return (size_t)-1;
			}
		}
		if (srclen && ob)
			memcpy(ob,(const char *)src,srclen);
		*dest = (char *)ob;
		return srclen;
	}
}


/**
 * Convert between character sets, allocating a new buffer using talloc for the result.
 *
 * @param srclen length of source buffer.
 * @param dest always set at least to NULL 
 * @note -1 is not accepted for srclen.
 *
 * @returns Size in bytes of the converted string; or -1 in case of error.
 **/
static size_t convert_string_talloc(TALLOC_CTX *ctx, charset_t from, charset_t to,
		      		void const *src, size_t srclen, void **dest)
{
	size_t dest_len;

	*dest = NULL;
	dest_len=convert_string_allocate(ctx, from, to, src, srclen, dest);
	if (dest_len == (size_t)-1)
		return (size_t)-1;
	if (*dest == NULL)
		return (size_t)-1;
	return dest_len;
}

size_t unix_strupper(const char *src, size_t srclen, char *dest, size_t destlen)
{
	size_t size;
	smb_ucs2_t *buffer;
	
	size = push_ucs2_allocate(&buffer, src);
	if (size == -1) {
		smb_panic("failed to create UCS2 buffer");
	}
	if (!strupper_w(buffer) && (dest == src)) {
		free(buffer);
		return srclen;
	}
	
	size = convert_string(CH_UCS2, CH_UNIX, buffer, size, dest, destlen);
	free(buffer);
	return size;
}

/**
 strdup() a unix string to upper case.
**/

char *strdup_upper(const char *s)
{
	size_t size;
	smb_ucs2_t *buffer;
	char *out_buffer;
	
	size = push_ucs2_allocate(&buffer, s);
	if (size == -1) {
		return NULL;
	}

	strupper_w(buffer);
	
	size = pull_ucs2_allocate(&out_buffer, buffer);
	SAFE_FREE(buffer);

	if (size == -1) {
		return NULL;
	}
	
	return out_buffer;
}

size_t unix_strlower(const char *src, size_t srclen, char *dest, size_t destlen)
{
	size_t size;
	smb_ucs2_t *buffer;
	
	size = convert_string_allocate(NULL, CH_UNIX, CH_UCS2, src, srclen,
				       (void **) &buffer);
	if (size == -1) {
		smb_panic("failed to create UCS2 buffer");
	}
	if (!strlower_w(buffer) && (dest == src)) {
		free(buffer);
		return srclen;
	}
	size = convert_string(CH_UCS2, CH_UNIX, buffer, size, dest, destlen);
	free(buffer);
	return size;
}

/**
 strdup() a unix string to lower case.
**/

char *strdup_lower(const char *s)
{
	size_t size;
	smb_ucs2_t *buffer;
	char *out_buffer;
	
	size = push_ucs2_allocate(&buffer, s);
	if (size == -1) {
		return NULL;
	}

	strlower_w(buffer);
	
	size = pull_ucs2_allocate(&out_buffer, buffer);
	SAFE_FREE(buffer);

	if (size == -1) {
		return NULL;
	}
	
	return out_buffer;
}

static size_t ucs2_align(const void *base_ptr, const void *p, int flags)
{
	if (flags & (STR_NOALIGN|STR_ASCII))
		return 0;
	return PTR_DIFF(p, base_ptr) & 1;
}


/**
 * Copy a string from a char* unix src to a dos codepage string destination.
 *
 * @return the number of bytes occupied by the string in the destination.
 *
 * @param flags can include
 * <dl>
 * <dt>STR_TERMINATE</dt> <dd>means include the null termination</dd>
 * <dt>STR_UPPER</dt> <dd>means uppercase in the destination</dd>
 * </dl>
 *
 * @param dest_len the maximum length in bytes allowed in the
 * destination.  If @p dest_len is -1 then no maximum is used.
 **/
size_t push_ascii(void *dest, const char *src, size_t dest_len, int flags)
{
	size_t src_len = strlen(src);
	pstring tmpbuf;

	/* treat a pstring as "unlimited" length */
	if (dest_len == (size_t)-1)
		dest_len = sizeof(pstring);

	if (flags & STR_UPPER) {
		pstrcpy(tmpbuf, src);
		strupper_m(tmpbuf);
		src = tmpbuf;
	}

	if (flags & (STR_TERMINATE | STR_TERMINATE_ASCII))
		src_len++;

	return convert_string(CH_UNIX, CH_DOS, src, src_len, dest, dest_len);
}

size_t push_ascii_fstring(void *dest, const char *src)
{
	return push_ascii(dest, src, sizeof(fstring), STR_TERMINATE);
}

size_t push_ascii_pstring(void *dest, const char *src)
{
	return push_ascii(dest, src, sizeof(pstring), STR_TERMINATE);
}

size_t push_ascii_nstring(void *dest, const char *src)
{
	return push_ascii(dest, src, sizeof(nstring), STR_TERMINATE);
}

/**
 * Copy a string from a dos codepage source to a unix char* destination.
 *
 * The resulting string in "dest" is always null terminated.
 *
 * @param flags can have:
 * <dl>
 * <dt>STR_TERMINATE</dt>
 * <dd>STR_TERMINATE means the string in @p src
 * is null terminated, and src_len is ignored.</dd>
 * </dl>
 *
 * @param src_len is the length of the source area in bytes.
 * @returns the number of bytes occupied by the string in @p src.
 **/
size_t pull_ascii(char *dest, const void *src, size_t dest_len, size_t src_len, int flags)
{
	size_t ret;

	if (dest_len == (size_t)-1)
		dest_len = sizeof(pstring);

	if (flags & STR_TERMINATE) {
		if (src_len == (size_t)-1) {
			src_len = strlen(src) + 1;
		} else {
			size_t len = strnlen(src, src_len);
			if (len < src_len)
				len++;
			src_len = len;
		}
	}

	ret = convert_string(CH_DOS, CH_UNIX, src, src_len, dest, dest_len);

	if (dest_len)
		dest[MIN(ret, dest_len-1)] = 0;
	else 
		dest[0] = 0;

	return src_len;
}

size_t pull_ascii_pstring(char *dest, const void *src)
{
	return pull_ascii(dest, src, sizeof(pstring), -1, STR_TERMINATE);
}

size_t pull_ascii_fstring(char *dest, const void *src)
{
	return pull_ascii(dest, src, sizeof(fstring), -1, STR_TERMINATE);
}

size_t pull_ascii_nstring(char *dest, const void *src)
{
	return pull_ascii(dest, src, sizeof(nstring), sizeof(nstring), STR_TERMINATE);
}

/**
 * Copy a string from a char* src to a unicode destination.
 *
 * @returns the number of bytes occupied by the string in the destination.
 *
 * @param flags can have:
 *
 * <dl>
 * <dt>STR_TERMINATE <dd>means include the null termination.
 * <dt>STR_UPPER     <dd>means uppercase in the destination.
 * <dt>STR_NOALIGN   <dd>means don't do alignment.
 * </dl>
 *
 * @param dest_len is the maximum length allowed in the
 * destination. If dest_len is -1 then no maxiumum is used.
 **/
size_t push_ucs2(const void *base_ptr, void *dest, const char *src, size_t dest_len, int flags)
{
	size_t len=0;
	size_t src_len = strlen(src);

	/* treat a pstring as "unlimited" length */
	if (dest_len == (size_t)-1)
		dest_len = sizeof(pstring);

	if (flags & STR_TERMINATE)
		src_len++;

	if (ucs2_align(base_ptr, dest, flags)) {
		*(char *)dest = 0;
		dest = (void *)((char *)dest + 1);
		if (dest_len) dest_len--;
		len++;
	}

	/* ucs2 is always a multiple of 2 bytes */
	dest_len &= ~1;

	len += convert_string(CH_UNIX, CH_UCS2, src, src_len, dest, dest_len);

	if (flags & STR_UPPER) {
		smb_ucs2_t *dest_ucs2 = dest;
		size_t i;
		for (i = 0; i < (dest_len / 2) && dest_ucs2[i]; i++) {
			smb_ucs2_t v = toupper_w(dest_ucs2[i]);
			if (v != dest_ucs2[i]) {
				dest_ucs2[i] = v;
			}
		}
	}

	return len;
}


/**
 * Copy a string from a unix char* src to a UCS2 destination,
 * allocating a buffer using talloc().
 *
 * @param dest always set at least to NULL 
 *
 * @returns The number of bytes occupied by the string in the destination
 *         or -1 in case of error.
 **/
size_t push_ucs2_talloc(TALLOC_CTX *ctx, smb_ucs2_t **dest, const char *src)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_talloc(ctx, CH_UNIX, CH_UCS2, src, src_len, (void **)dest);
}


/**
 * Copy a string from a unix char* src to a UCS2 destination, allocating a buffer
 *
 * @param dest always set at least to NULL 
 *
 * @returns The number of bytes occupied by the string in the destination
 *         or -1 in case of error.
 **/

size_t push_ucs2_allocate(smb_ucs2_t **dest, const char *src)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_allocate(NULL, CH_UNIX, CH_UCS2, src, src_len, (void **)dest);	
}

/**
 Copy a string from a char* src to a UTF-8 destination.
 Return the number of bytes occupied by the string in the destination
 Flags can have:
  STR_TERMINATE means include the null termination
  STR_UPPER     means uppercase in the destination
 dest_len is the maximum length allowed in the destination. If dest_len
 is -1 then no maxiumum is used.
**/

static size_t push_utf8(void *dest, const char *src, size_t dest_len, int flags)
{
	size_t src_len = strlen(src);
	pstring tmpbuf;

	/* treat a pstring as "unlimited" length */
	if (dest_len == (size_t)-1)
		dest_len = sizeof(pstring);

	if (flags & STR_UPPER) {
		pstrcpy(tmpbuf, src);
		strupper_m(tmpbuf);
		src = tmpbuf;
	}

	if (flags & STR_TERMINATE)
		src_len++;

	return convert_string(CH_UNIX, CH_UTF8, src, src_len, dest, dest_len);
}

size_t push_utf8_fstring(void *dest, const char *src)
{
	return push_utf8(dest, src, sizeof(fstring), STR_TERMINATE);
}

/**
 * Copy a string from a unix char* src to a UTF-8 destination, allocating a buffer using talloc
 *
 * @param dest always set at least to NULL 
 *
 * @returns The number of bytes occupied by the string in the destination
 **/

size_t push_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_talloc(ctx, CH_UNIX, CH_UTF8, src, src_len, (void**)dest);
}

/**
 * Copy a string from a unix char* src to a UTF-8 destination, allocating a buffer
 *
 * @param dest always set at least to NULL 
 *
 * @returns The number of bytes occupied by the string in the destination
 **/

size_t push_utf8_allocate(char **dest, const char *src)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_allocate(NULL, CH_UNIX, CH_UTF8, src, src_len, (void **)dest);	
}

/**
 Copy a string from a ucs2 source to a unix char* destination.
 Flags can have:
  STR_TERMINATE means the string in src is null terminated.
  STR_NOALIGN   means don't try to align.
 if STR_TERMINATE is set then src_len is ignored if it is -1.
 src_len is the length of the source area in bytes
 Return the number of bytes occupied by the string in src.
 The resulting string in "dest" is always null terminated.
**/

size_t pull_ucs2(const void *base_ptr, char *dest, const void *src, size_t dest_len, size_t src_len, int flags)
{
	size_t ret;

	if (dest_len == (size_t)-1)
		dest_len = sizeof(pstring);

	if (ucs2_align(base_ptr, src, flags)) {
		src = (const void *)((const char *)src + 1);
		if (src_len > 0)
			src_len--;
	}

	if (flags & STR_TERMINATE) {
		if (src_len == (size_t)-1) {
			src_len = strlen_w(src)*2 + 2;
		} else {
			size_t len = strnlen_w(src, src_len/2);
			if (len < src_len/2)
				len++;
			src_len = len*2;
		}
	}

	/* ucs2 is always a multiple of 2 bytes */
	if (src_len != (size_t)-1)
		src_len &= ~1;
	
	ret = convert_string(CH_UCS2, CH_UNIX, src, src_len, dest, dest_len);
	if (dest_len)
		dest[MIN(ret, dest_len-1)] = 0;
	else 
		dest[0] = 0;

	return src_len;
}

size_t pull_ucs2_pstring(char *dest, const void *src)
{
	return pull_ucs2(NULL, dest, src, sizeof(pstring), -1, STR_TERMINATE);
}

size_t pull_ucs2_fstring(char *dest, const void *src)
{
	return pull_ucs2(NULL, dest, src, sizeof(fstring), -1, STR_TERMINATE);
}

/**
 * Copy a string from a UCS2 src to a unix char * destination, allocating a buffer using talloc
 *
 * @param dest always set at least to NULL 
 *
 * @returns The number of bytes occupied by the string in the destination
 **/

size_t pull_ucs2_talloc(TALLOC_CTX *ctx, char **dest, const smb_ucs2_t *src)
{
	size_t src_len = (strlen_w(src)+1) * sizeof(smb_ucs2_t);
	*dest = NULL;
	return convert_string_talloc(ctx, CH_UCS2, CH_UNIX, src, src_len, (void **)dest);
}

/**
 * Copy a string from a UCS2 src to a unix char * destination, allocating a buffer
 *
 * @param dest always set at least to NULL 
 *
 * @returns The number of bytes occupied by the string in the destination
 **/

size_t pull_ucs2_allocate(char **dest, const smb_ucs2_t *src)
{
	size_t src_len = (strlen_w(src)+1) * sizeof(smb_ucs2_t);
	*dest = NULL;
	return convert_string_allocate(NULL, CH_UCS2, CH_UNIX, src, src_len, (void **)dest);	
}

/**
 * Copy a string from a UTF-8 src to a unix char * destination, allocating a buffer using talloc
 *
 * @param dest always set at least to NULL 
 *
 * @returns The number of bytes occupied by the string in the destination
 **/

size_t pull_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src)
{
	size_t src_len = strlen(src)+1;
	*dest = NULL;
	return convert_string_talloc(ctx, CH_UTF8, CH_UNIX, src, src_len, (void **)dest);	
}

/**
 * Copy a string from a UTF-8 src to a unix char * destination, allocating a buffer
 *
 * @param dest always set at least to NULL 
 *
 * @returns The number of bytes occupied by the string in the destination
 **/

size_t pull_utf8_allocate(void **dest, const char *src)
{
	size_t src_len = strlen(src)+1;
	*dest = NULL;
	return convert_string_allocate(NULL, CH_UTF8, CH_UNIX, src, src_len, dest);	
}
 
/**
 Copy a string from a char* src to a unicode or ascii
 dos codepage destination choosing unicode or ascii based on the 
 flags in the SMB buffer starting at base_ptr.
 Return the number of bytes occupied by the string in the destination.
 flags can have:
  STR_TERMINATE means include the null termination.
  STR_UPPER     means uppercase in the destination.
  STR_ASCII     use ascii even with unicode packet.
  STR_NOALIGN   means don't do alignment.
 dest_len is the maximum length allowed in the destination. If dest_len
 is -1 then no maxiumum is used.
**/

size_t push_string_fn(const char *function, unsigned int line, const void *base_ptr, void *dest, const char *src, size_t dest_len, int flags)
{
#ifdef DEVELOPER
	/* We really need to zero fill here, not clobber
	 * region, as we want to ensure that valgrind thinks
	 * all of the outgoing buffer has been written to
	 * so a send() or write() won't trap an error.
	 * JRA.
	 */
#if 0
	if (dest_len != (size_t)-1)
		clobber_region(function, line, dest, dest_len);
#else
	if (dest_len != (size_t)-1)
		memset(dest, '\0', dest_len);
#endif
#endif

	if (!(flags & STR_ASCII) && \
	    ((flags & STR_UNICODE || \
	      (SVAL(base_ptr, smb_flg2) & FLAGS2_UNICODE_STRINGS)))) {
		return push_ucs2(base_ptr, dest, src, dest_len, flags);
	}
	return push_ascii(dest, src, dest_len, flags);
}


/**
 Copy a string from a unicode or ascii source (depending on
 the packet flags) to a char* destination.
 Flags can have:
  STR_TERMINATE means the string in src is null terminated.
  STR_UNICODE   means to force as unicode.
  STR_ASCII     use ascii even with unicode packet.
  STR_NOALIGN   means don't do alignment.
 if STR_TERMINATE is set then src_len is ignored is it is -1
 src_len is the length of the source area in bytes.
 Return the number of bytes occupied by the string in src.
 The resulting string in "dest" is always null terminated.
**/

size_t pull_string_fn(const char *function, unsigned int line, const void *base_ptr, char *dest, const void *src, size_t dest_len, size_t src_len, int flags)
{
	if (dest_len != (size_t)-1)
		clobber_region(function, line, dest, dest_len);

	if (!(flags & STR_ASCII) && \
	    ((flags & STR_UNICODE || \
	      (SVAL(base_ptr, smb_flg2) & FLAGS2_UNICODE_STRINGS)))) {
		return pull_ucs2(base_ptr, dest, src, dest_len, src_len, flags);
	}
	return pull_ascii(dest, src, dest_len, src_len, flags);
}

size_t align_string(const void *base_ptr, const char *p, int flags)
{
	if (!(flags & STR_ASCII) && \
	    ((flags & STR_UNICODE || \
	      (SVAL(base_ptr, smb_flg2) & FLAGS2_UNICODE_STRINGS)))) {
		return ucs2_align(base_ptr, p, flags);
	}
	return 0;
}

