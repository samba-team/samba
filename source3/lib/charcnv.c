/*
   Unix SMB/CIFS implementation.
   Character set conversion Extensions
   Copyright (C) Igor Vergeichik <iverg@mail.ru> 2001
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Simo Sorce 2001
   Copyright (C) Martin Pool 2003

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


static bool initialized;

static void lazy_initialize_conv(void)
{
	if (!initialized) {
		load_case_tables_library();
		init_iconv();
		initialized = true;
	}
}

/**
 * Destroy global objects allocated by init_iconv()
 **/
void gfree_charcnv(void)
{
	TALLOC_FREE(global_iconv_handle);
	initialized = false;
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
	global_iconv_handle = smb_iconv_handle_reinit(NULL, lp_dos_charset(),
								lp_unix_charset(), lp_display_charset(),
								true, global_iconv_handle);
}

/**
 * Convert string from one encoding to another, making error checking etc
 * Slow path version - uses (slow) iconv.
 *
 * @param src pointer to source string (multibyte or singlebyte)
 * @param srclen length of the source string in bytes
 * @param dest pointer to destination string (multibyte or singlebyte)
 * @param destlen maximal length allowed for string
 * @param converted size is the number of bytes occupied in the destination
 *
 * @returns false and sets errno on fail, true on success.
 *
 * Ensure the srclen contains the terminating zero.
 *
 **/

static bool convert_string_internal(charset_t from, charset_t to,
		      void const *src, size_t srclen, 
		      void *dest, size_t destlen, size_t *converted_size)
{
	size_t i_len, o_len;
	size_t retval;
	const char* inbuf = (const char*)src;
	char* outbuf = (char*)dest;
	smb_iconv_t descriptor;
	struct smb_iconv_handle *ic;

	lazy_initialize_conv();
	ic = get_iconv_handle();
	descriptor = get_conv_handle(ic, from, to);

	if (srclen == (size_t)-1) {
		if (from == CH_UTF16LE || from == CH_UTF16BE) {
			srclen = (strlen_w((const smb_ucs2_t *)src)+1) * 2;
		} else {
			srclen = strlen((const char *)src)+1;
		}
	}


	if (descriptor == (smb_iconv_t)-1 || descriptor == (smb_iconv_t)0) {
		errno = EINVAL;
		return false;
	}

	i_len=srclen;
	o_len=destlen;

	retval = smb_iconv(descriptor, &inbuf, &i_len, &outbuf, &o_len);
	if (retval == (size_t)-1) {
		return false;
	}
	*converted_size = destlen-o_len;
	return true;
}

/**
 * Convert string from one encoding to another, making error checking etc
 * Fast path version - handles ASCII first.
 *
 * @param src pointer to source string (multibyte or singlebyte)
 * @param srclen length of the source string in bytes, or -1 for nul terminated.
 * @param dest pointer to destination string (multibyte or singlebyte)
 * @param destlen maximal length allowed for string - *NEVER* -1.
 * @param converted size is the number of bytes occupied in the destination
 *
 * @returns false and sets errno on fail, true on success.
 *
 * Ensure the srclen contains the terminating zero.
 *
 * This function has been hand-tuned to provide a fast path.
 * Don't change unless you really know what you are doing. JRA.
 **/

bool convert_string_error(charset_t from, charset_t to,
			    void const *src, size_t srclen,
			    void *dest, size_t destlen,
			    size_t *converted_size)
{
	/*
	 * NB. We deliberately don't do a strlen here if srclen == -1.
	 * This is very expensive over millions of calls and is taken
	 * care of in the slow path in convert_string_internal. JRA.
	 */

#ifdef DEVELOPER
	SMB_ASSERT(destlen != (size_t)-1);
#endif

	if (srclen == 0) {
		*converted_size = 0;
		return true;
	}

	if (from != CH_UTF16LE && from != CH_UTF16BE && to != CH_UTF16LE && to != CH_UTF16BE) {
		const unsigned char *p = (const unsigned char *)src;
		unsigned char *q = (unsigned char *)dest;
		size_t slen = srclen;
		size_t dlen = destlen;
		unsigned char lastp = '\0';
		size_t retval = 0;

		/* If all characters are ascii, fast path here. */
		while (slen && dlen) {
			if ((lastp = *p) <= 0x7f) {
				*q++ = *p++;
				if (slen != (size_t)-1) {
					slen--;
				}
				dlen--;
				retval++;
				if (!lastp)
					break;
			} else {
#ifdef BROKEN_UNICODE_COMPOSE_CHARACTERS
				goto general_case;
#else
				bool ret = convert_string_internal(from, to, p, slen, q, dlen, converted_size);
				*converted_size += retval;
				return ret;
#endif
			}
		}

		*converted_size = retval;

		if (!dlen) {
			/* Even if we fast path we should note if we ran out of room. */
			if (((slen != (size_t)-1) && slen) ||
					((slen == (size_t)-1) && lastp)) {
				errno = E2BIG;
				return false;
			}
		}
		return true;
	} else if (from == CH_UTF16LE && to != CH_UTF16LE) {
		const unsigned char *p = (const unsigned char *)src;
		unsigned char *q = (unsigned char *)dest;
		size_t retval = 0;
		size_t slen = srclen;
		size_t dlen = destlen;
		unsigned char lastp = '\0';

		/* If all characters are ascii, fast path here. */
		while (((slen == (size_t)-1) || (slen >= 2)) && dlen) {
			if (((lastp = *p) <= 0x7f) && (p[1] == 0)) {
				*q++ = *p;
				if (slen != (size_t)-1) {
					slen -= 2;
				}
				p += 2;
				dlen--;
				retval++;
				if (!lastp)
					break;
			} else {
#ifdef BROKEN_UNICODE_COMPOSE_CHARACTERS
				goto general_case;
#else
				bool ret = convert_string_internal(from, to, p, slen, q, dlen, converted_size);
				*converted_size += retval;
				return ret;
#endif
			}
		}

		*converted_size = retval;

		if (!dlen) {
			/* Even if we fast path we should note if we ran out of room. */
			if (((slen != (size_t)-1) && slen) ||
					((slen == (size_t)-1) && lastp)) {
				errno = E2BIG;
				return false;
			}
		}
		return true;
	} else if (from != CH_UTF16LE && from != CH_UTF16BE && to == CH_UTF16LE) {
		const unsigned char *p = (const unsigned char *)src;
		unsigned char *q = (unsigned char *)dest;
		size_t retval = 0;
		size_t slen = srclen;
		size_t dlen = destlen;
		unsigned char lastp = '\0';

		/* If all characters are ascii, fast path here. */
		while (slen && (dlen >= 2)) {
			if ((lastp = *p) <= 0x7F) {
				*q++ = *p++;
				*q++ = '\0';
				if (slen != (size_t)-1) {
					slen--;
				}
				dlen -= 2;
				retval += 2;
				if (!lastp)
					break;
			} else {
#ifdef BROKEN_UNICODE_COMPOSE_CHARACTERS
				goto general_case;
#else
				bool ret = convert_string_internal(from, to, p, slen, q, dlen, converted_size);
				*converted_size += retval;
				return ret;
#endif
			}
		}

		*converted_size = retval;

		if (!dlen) {
			/* Even if we fast path we should note if we ran out of room. */
			if (((slen != (size_t)-1) && slen) ||
					((slen == (size_t)-1) && lastp)) {
				errno = E2BIG;
				return false;
			}
		}
		return true;
	}

#ifdef BROKEN_UNICODE_COMPOSE_CHARACTERS
  general_case:
#endif
	return convert_string_internal(from, to, src, srclen, dest, destlen, converted_size);
}

bool convert_string(charset_t from, charset_t to,
		      void const *src, size_t srclen,
		      void *dest, size_t destlen,
		      size_t *converted_size)
{
	bool ret = convert_string_error(from, to, src, srclen, dest, destlen, converted_size);

	if(ret==false) {
		const char *reason="unknown error";
		switch(errno) {
			case EINVAL:
				reason="Incomplete multibyte sequence";
				DEBUG(3,("convert_string_internal: Conversion error: %s(%s)\n",
					 reason, (const char *)src));
				break;
			case E2BIG:
			{
				struct smb_iconv_handle *ic;
				lazy_initialize_conv();
				ic = get_iconv_handle();

				reason="No more room";
				if (from == CH_UNIX) {
					DEBUG(3,("E2BIG: convert_string(%s,%s): srclen=%u destlen=%u - '%s'\n",
						 charset_name(ic, from), charset_name(ic, to),
						 (unsigned int)srclen, (unsigned int)destlen, (const char *)src));
				} else {
					DEBUG(3,("E2BIG: convert_string(%s,%s): srclen=%u destlen=%u\n",
						 charset_name(ic, from), charset_name(ic, to),
						 (unsigned int)srclen, (unsigned int)destlen));
				}
				break;
			}
			case EILSEQ:
				reason="Illegal multibyte sequence";
				DEBUG(3,("convert_string_internal: Conversion error: %s(%s)\n",
					 reason, (const char *)src));
				break;
			default:
				DEBUG(0,("convert_string_internal: Conversion error: %s(%s)\n",
					 reason, (const char *)src));
				break;
		}
		/* smb_panic(reason); */
	}
	return ret;
}


/**
 * Convert between character sets, allocating a new buffer using talloc for the result.
 *
 * @param srclen length of source buffer.
 * @param dest always set at least to NULL
 * @parm converted_size set to the number of bytes occupied by the string in
 * the destination on success.
 * @note -1 is not accepted for srclen.
 *
 * @return true if new buffer was correctly allocated, and string was
 * converted.
 *
 * Ensure the srclen contains the terminating zero.
 *
 * I hate the goto's in this function. It's embarressing.....
 * There has to be a cleaner way to do this. JRA.
 */
bool convert_string_talloc(TALLOC_CTX *ctx, charset_t from, charset_t to,
			   void const *src, size_t srclen, void *dst,
			   size_t *converted_size)

{
	size_t i_len, o_len, destlen = (srclen * 3) / 2;
	size_t retval;
	const char *inbuf = (const char *)src;
	char *outbuf = NULL, *ob = NULL;
	smb_iconv_t descriptor;
	void **dest = (void **)dst;
	struct smb_iconv_handle *ic;

	*dest = NULL;

	if (src == NULL || srclen == (size_t)-1) {
		errno = EINVAL;
		return false;
	}

	if (srclen == 0) {
		/* We really should treat this as an error, but
		   there are too many callers that need this to
		   return a NULL terminated string in the correct
		   character set. */
		if (to == CH_UTF16LE|| to == CH_UTF16BE || to == CH_UTF16MUNGED) {
			destlen = 2;
		} else {
			destlen = 1;
		}
		ob = talloc_zero_array(ctx, char, destlen);
		if (ob == NULL) {
			errno = ENOMEM;
			return false;
		}
		*converted_size = destlen;
		*dest = ob;
		return true;
	}

	lazy_initialize_conv();
	ic = get_iconv_handle();
	descriptor = get_conv_handle(ic, from, to);

	if (descriptor == (smb_iconv_t)-1 || descriptor == (smb_iconv_t)0) {
		DEBUG(0,("convert_string_talloc: Conversion not supported.\n"));
		errno = EOPNOTSUPP;
		return false;
	}

  convert:

	/* +2 is for ucs2 null termination. */
	if ((destlen*2)+2 < destlen) {
		/* wrapped ! abort. */
		DEBUG(0, ("convert_string_talloc: destlen wrapped !\n"));
		TALLOC_FREE(outbuf);
		errno = EOPNOTSUPP;
		return false;
	} else {
		destlen = destlen * 2;
	}

	/* +2 is for ucs2 null termination. */
	ob = (char *)TALLOC_REALLOC(ctx, ob, destlen + 2);

	if (!ob) {
		DEBUG(0, ("convert_string_talloc: realloc failed!\n"));
		errno = ENOMEM;
		return false;
	}
	outbuf = ob;
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
				DEBUG(3,("convert_string_talloc: Conversion error: %s(%s)\n",reason,inbuf));
				break;
			case E2BIG:
				goto convert;
			case EILSEQ:
				reason="Illegal multibyte sequence";
				DEBUG(3,("convert_string_talloc: Conversion error: %s(%s)\n",reason,inbuf));
				break;
		}
		DEBUG(0,("Conversion error: %s(%s)\n",reason,inbuf));
		/* smb_panic(reason); */
		TALLOC_FREE(ob);
		return false;
	}

	destlen = destlen - o_len;
	/* Don't shrink unless we're reclaiming a lot of
	 * space. This is in the hot codepath and these
	 * reallocs *cost*. JRA.
	 */
	if (o_len > 1024) {
		/* We're shrinking here so we know the +2 is safe from wrap. */
		ob = (char *)TALLOC_REALLOC(ctx,ob,destlen + 2);
	}

	if (destlen && !ob) {
		DEBUG(0, ("convert_string_talloc: out of memory!\n"));
		errno = ENOMEM;
		return false;
	}

	*dest = ob;

	/* Must ucs2 null terminate in the extra space we allocated. */
	ob[destlen] = '\0';
	ob[destlen+1] = '\0';

	/* Ensure we can never return a *converted_size of zero. */
	if (destlen == 0) {
		/* As we're now returning false on a bad smb_iconv call,
		   this should never happen. But be safe anyway. */
		if (to == CH_UTF16LE|| to == CH_UTF16BE || to == CH_UTF16MUNGED) {
			destlen = 2;
		} else {
			destlen = 1;
		}
	}

	*converted_size = destlen;
	return true;
}

bool unix_strupper(const char *src, size_t srclen, char *dest, size_t destlen)
{
	size_t size;
	smb_ucs2_t *buffer;
	bool ret;

	if (!push_ucs2_talloc(talloc_tos(), &buffer, src, &size)) {
		return (size_t)-1;
	}

	if (!strupper_w(buffer) && (dest == src)) {
		TALLOC_FREE(buffer);
		return srclen;
	}

	ret = convert_string(CH_UTF16LE, CH_UNIX, buffer, size, dest, destlen, &size);
	TALLOC_FREE(buffer);
	return ret;
}

/**
 talloc_strdup() a unix string to upper case.
**/

char *talloc_strdup_upper(TALLOC_CTX *ctx, const char *s)
{
	char *out_buffer = talloc_strdup(ctx,s);
	const unsigned char *p = (const unsigned char *)s;
	unsigned char *q = (unsigned char *)out_buffer;

	if (!q) {
		return NULL;
	}

	/* this is quite a common operation, so we want it to be
	   fast. We optimise for the ascii case, knowing that all our
	   supported multi-byte character sets are ascii-compatible
	   (ie. they match for the first 128 chars) */

	while (*p) {
		if (*p & 0x80)
			break;
		*q++ = toupper_ascii_fast(*p);
		p++;
	}

	if (*p) {
		/* MB case. */
		size_t converted_size, converted_size2;
		smb_ucs2_t *ubuf = NULL;

		/* We're not using the ascii buffer above. */
		TALLOC_FREE(out_buffer);

		if (!convert_string_talloc(ctx, CH_UNIX, CH_UTF16LE, s,
					   strlen(s)+1, (void *)&ubuf,
					   &converted_size))
		{
			return NULL;
		}

		strupper_w(ubuf);

		if (!convert_string_talloc(ctx, CH_UTF16LE, CH_UNIX, ubuf,
					   converted_size, (void *)&out_buffer,
					   &converted_size2))
		{
			TALLOC_FREE(ubuf);
			return NULL;
		}

		/* Don't need the intermediate buffer
 		 * anymore.
 		 */
		TALLOC_FREE(ubuf);
	}

	return out_buffer;
}

char *strupper_talloc(TALLOC_CTX *ctx, const char *s) {
	return talloc_strdup_upper(ctx, s);
}


bool unix_strlower(const char *src, size_t srclen, char *dest, size_t destlen)
{
	size_t size;
	smb_ucs2_t *buffer = NULL;
	bool ret;

	if (!convert_string_talloc(talloc_tos(), CH_UNIX, CH_UTF16LE, src, srclen,
				   (void **)(void *)&buffer, &size))
	{
		smb_panic("failed to create UCS2 buffer");
	}
	if (!strlower_w(buffer) && (dest == src)) {
		TALLOC_FREE(buffer);
		return srclen;
	}
	ret = convert_string(CH_UTF16LE, CH_UNIX, buffer, size, dest, destlen, &size);
	TALLOC_FREE(buffer);
	return ret;
}


char *talloc_strdup_lower(TALLOC_CTX *ctx, const char *s)
{
	size_t converted_size;
	smb_ucs2_t *buffer = NULL;
	char *out_buffer;

	if (!push_ucs2_talloc(ctx, &buffer, s, &converted_size)) {
		return NULL;
	}

	strlower_w(buffer);

	if (!pull_ucs2_talloc(ctx, &out_buffer, buffer, &converted_size)) {
		TALLOC_FREE(buffer);
		return NULL;
	}

	TALLOC_FREE(buffer);

	return out_buffer;
}

char *strlower_talloc(TALLOC_CTX *ctx, const char *s) {
	return talloc_strdup_lower(ctx, s);
}

size_t ucs2_align(const void *base_ptr, const void *p, int flags)
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
 * destination.
 **/
size_t push_ascii(void *dest, const char *src, size_t dest_len, int flags)
{
	size_t src_len = strlen(src);
	char *tmpbuf = NULL;
	size_t size;
	bool ret;

	/* No longer allow a length of -1. */
	if (dest_len == (size_t)-1) {
		smb_panic("push_ascii - dest_len == -1");
	}

	if (flags & STR_UPPER) {
		tmpbuf = SMB_STRDUP(src);
		if (!tmpbuf) {
			smb_panic("malloc fail");
		}
		strupper_m(tmpbuf);
		src = tmpbuf;
	}

	if (flags & (STR_TERMINATE | STR_TERMINATE_ASCII)) {
		src_len++;
	}

	ret = convert_string(CH_UNIX, CH_DOS, src, src_len, dest, dest_len, &size);
	if (ret == false &&
			(flags & (STR_TERMINATE | STR_TERMINATE_ASCII))
			&& dest_len > 0) {
		((char *)dest)[0] = '\0';
	}
	SAFE_FREE(tmpbuf);
	return ret ? size : (size_t)-1;
}

/********************************************************************
 Push and malloc an ascii string. src and dest null terminated.
********************************************************************/

bool push_ascii_talloc(TALLOC_CTX *mem_ctx, char **dest, const char *src, size_t *converted_size)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_talloc(mem_ctx, CH_UNIX, CH_DOS, src, src_len,
				     (void **)dest, converted_size);
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
	bool ret;
	size_t size = 0;

	if (dest_len == (size_t)-1) {
		/* No longer allow dest_len of -1. */
		smb_panic("pull_ascii - invalid dest_len of -1");
	}

	if (flags & STR_TERMINATE) {
		if (src_len == (size_t)-1) {
			src_len = strlen((const char *)src) + 1;
		} else {
			size_t len = strnlen((const char *)src, src_len);
			if (len < src_len)
				len++;
			src_len = len;
		}
	}

	ret = convert_string(CH_DOS, CH_UNIX, src, src_len, dest, dest_len, &size);
	if (ret == false) {
		size = 0;
		dest_len = 0;
	}

	if (dest_len && size) {
		/* Did we already process the terminating zero ? */
		if (dest[MIN(size-1, dest_len-1)] != 0) {
			dest[MIN(size, dest_len-1)] = 0;
		}
	} else  {
		dest[0] = 0;
	}

	return src_len;
}

/**
 * Copy a string from a dos codepage source to a unix char* destination.
 * Talloc version.
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

static size_t pull_ascii_base_talloc(TALLOC_CTX *ctx,
				     char **ppdest,
				     const void *src,
				     size_t src_len,
				     int flags)
{
	char *dest = NULL;
	size_t dest_len;

	*ppdest = NULL;

	if (!src_len) {
		return 0;
	}

	if (src_len == (size_t)-1) {
		smb_panic("sec_len == -1 in pull_ascii_base_talloc");
	}

	if (flags & STR_TERMINATE) {
		size_t len = strnlen((const char *)src, src_len);
		if (len < src_len)
			len++;
		src_len = len;
		/* Ensure we don't use an insane length from the client. */
		if (src_len >= 1024*1024) {
			char *msg = talloc_asprintf(ctx,
					"Bad src length (%u) in "
					"pull_ascii_base_talloc",
					(unsigned int)src_len);
			smb_panic(msg);
		}
	}

	/* src_len != -1 here. */

	if (!convert_string_talloc(ctx, CH_DOS, CH_UNIX, src, src_len, &dest,
				     &dest_len)) {
		dest_len = 0;
	}

	if (dest_len && dest) {
		/* Did we already process the terminating zero ? */
		if (dest[dest_len-1] != 0) {
			size_t size = talloc_get_size(dest);
			/* Have we got space to append the '\0' ? */
			if (size <= dest_len) {
				/* No, realloc. */
				dest = TALLOC_REALLOC_ARRAY(ctx, dest, char,
						dest_len+1);
				if (!dest) {
					/* talloc fail. */
					dest_len = (size_t)-1;
					return 0;
				}
			}
			/* Yay - space ! */
			dest[dest_len] = '\0';
			dest_len++;
		}
	} else if (dest) {
		dest[0] = 0;
	}

	*ppdest = dest;
	return src_len;
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
 * destination.
 **/

size_t push_ucs2(const void *base_ptr, void *dest, const char *src, size_t dest_len, int flags)
{
	size_t len=0;
	size_t src_len;
	size_t size = 0;
	bool ret;

	if (dest_len == (size_t)-1) {
		/* No longer allow dest_len of -1. */
		smb_panic("push_ucs2 - invalid dest_len of -1");
	}

	if (flags & STR_TERMINATE)
		src_len = (size_t)-1;
	else
		src_len = strlen(src);

	if (ucs2_align(base_ptr, dest, flags)) {
		*(char *)dest = 0;
		dest = (void *)((char *)dest + 1);
		if (dest_len)
			dest_len--;
		len++;
	}

	/* ucs2 is always a multiple of 2 bytes */
	dest_len &= ~1;

	ret = convert_string(CH_UNIX, CH_UTF16LE, src, src_len, dest, dest_len, &size);
	if (ret == false) {
		if ((flags & STR_TERMINATE) &&
				dest &&
				dest_len) {
			*(char *)dest = 0;
		}
		return len;
	}

	len += size;

	if (flags & STR_UPPER) {
		smb_ucs2_t *dest_ucs2 = (smb_ucs2_t *)dest;
		size_t i;

		/* We check for i < (ret / 2) below as the dest string isn't null
		   terminated if STR_TERMINATE isn't set. */

		for (i = 0; i < (ret / 2) && i < (dest_len / 2) && dest_ucs2[i]; i++) {
			smb_ucs2_t v = toupper_m(dest_ucs2[i]);
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
 * @parm converted_size set to the number of bytes occupied by the string in
 * the destination on success.
 *
 * @return true if new buffer was correctly allocated, and string was
 * converted.
 **/
bool push_ucs2_talloc(TALLOC_CTX *ctx, smb_ucs2_t **dest, const char *src,
		      size_t *converted_size)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_talloc(ctx, CH_UNIX, CH_UTF16LE, src, src_len,
				     (void **)dest, converted_size);
}


/**
 * Copy a string from a unix char* src to a UTF-8 destination, allocating a buffer using talloc
 *
 * @param dest always set at least to NULL 
 * @parm converted_size set to the number of bytes occupied by the string in
 * the destination on success.
 *
 * @return true if new buffer was correctly allocated, and string was
 * converted.
 **/

bool push_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src,
		      size_t *converted_size)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_talloc(ctx, CH_UNIX, CH_UTF8, src, src_len,
				     (void**)dest, converted_size);
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
	size_t size = 0;
	size_t ucs2_align_len = 0;
	bool ret;

	if (dest_len == (size_t)-1) {
		/* No longer allow dest_len of -1. */
		smb_panic("pull_ucs2 - invalid dest_len of -1");
	}

	if (!src_len) {
		if (dest && dest_len > 0) {
			dest[0] = '\0';
		}
		return 0;
	}

	if (ucs2_align(base_ptr, src, flags)) {
		src = (const void *)((const char *)src + 1);
		if (src_len != (size_t)-1)
			src_len--;
		ucs2_align_len = 1;
	}

	if (flags & STR_TERMINATE) {
		/* src_len -1 is the default for null terminated strings. */
		if (src_len != (size_t)-1) {
			size_t len = strnlen_w((const smb_ucs2_t *)src,
						src_len/2);
			if (len < src_len/2)
				len++;
			src_len = len*2;
		}
	}

	/* ucs2 is always a multiple of 2 bytes */
	if (src_len != (size_t)-1)
		src_len &= ~1;

	ret = convert_string(CH_UTF16LE, CH_UNIX, src, src_len, dest, dest_len, &size);
	if (ret == false) {
		size = 0;
		dest_len = 0;
	}

	if (src_len == (size_t)-1)
		src_len = size*2;

	if (dest_len && size) {
		/* Did we already process the terminating zero ? */
		if (dest[MIN(size-1, dest_len-1)] != 0) {
			dest[MIN(size, dest_len-1)] = 0;
		}
	} else {
		dest[0] = 0;
	}

	return src_len + ucs2_align_len;
}

/**
 Copy a string from a ucs2 source to a unix char* destination.
 Talloc version with a base pointer.
 Uses malloc if TALLOC_CTX is NULL (this is a bad interface and
 needs fixing. JRA).
 Flags can have:
  STR_TERMINATE means the string in src is null terminated.
  STR_NOALIGN   means don't try to align.
 if STR_TERMINATE is set then src_len is ignored if it is -1.
 src_len is the length of the source area in bytes
 Return the number of bytes occupied by the string in src.
 The resulting string in "dest" is always null terminated.
**/

static size_t pull_ucs2_base_talloc(TALLOC_CTX *ctx,
				    const void *base_ptr,
				    char **ppdest,
				    const void *src,
				    size_t src_len,
				    int flags)
{
	char *dest;
	size_t dest_len;
	size_t ucs2_align_len = 0;

	*ppdest = NULL;

#ifdef DEVELOPER
	/* Ensure we never use the braindead "malloc" varient. */
	if (ctx == NULL) {
		smb_panic("NULL talloc CTX in pull_ucs2_base_talloc\n");
	}
#endif

	if (!src_len) {
		return 0;
	}

	if (src_len == (size_t)-1) {
		/* no longer used anywhere, but worth checking */
		smb_panic("sec_len == -1 in pull_ucs2_base_talloc");
	}

	if (ucs2_align(base_ptr, src, flags)) {
		src = (const void *)((const char *)src + 1);
		src_len--;
		ucs2_align_len = 1;
	}

	if (flags & STR_TERMINATE) {
		/* src_len -1 is the default for null terminated strings. */
		size_t len = strnlen_w((const smb_ucs2_t *)src,
				       src_len/2);
		if (len < src_len/2)
			len++;
		src_len = len*2;

		/* Ensure we don't use an insane length from the client. */
		if (src_len >= 1024*1024) {
			smb_panic("Bad src length in pull_ucs2_base_talloc\n");
		}
	}

	/* ucs2 is always a multiple of 2 bytes */
	src_len &= ~1;

	if (!convert_string_talloc(ctx, CH_UTF16LE, CH_UNIX, src, src_len,
				   (void *)&dest, &dest_len)) {
		dest_len = 0;
	}

	if (dest_len) {
		/* Did we already process the terminating zero ? */
		if (dest[dest_len-1] != 0) {
			size_t size = talloc_get_size(dest);
			/* Have we got space to append the '\0' ? */
			if (size <= dest_len) {
				/* No, realloc. */
				dest = TALLOC_REALLOC_ARRAY(ctx, dest, char,
						dest_len+1);
				if (!dest) {
					/* talloc fail. */
					dest_len = (size_t)-1;
					return 0;
				}
			}
			/* Yay - space ! */
			dest[dest_len] = '\0';
			dest_len++;
		}
	} else if (dest) {
		dest[0] = 0;
	}

	*ppdest = dest;
	return src_len + ucs2_align_len;
}

/**
 * Copy a string from a UCS2 src to a unix char * destination, allocating a buffer using talloc
 *
 * @param dest always set at least to NULL 
 * @parm converted_size set to the number of bytes occupied by the string in
 * the destination on success.
 *
 * @return true if new buffer was correctly allocated, and string was
 * converted.
 **/

bool pull_ucs2_talloc(TALLOC_CTX *ctx, char **dest, const smb_ucs2_t *src,
		      size_t *converted_size)
{
	size_t src_len = (strlen_w(src)+1) * sizeof(smb_ucs2_t);

	*dest = NULL;
	return convert_string_talloc(ctx, CH_UTF16LE, CH_UNIX, src, src_len,
				     (void **)dest, converted_size);
}

/**
 * Copy a string from a UTF-8 src to a unix char * destination, allocating a buffer using talloc
 *
 * @param dest always set at least to NULL 
 * @parm converted_size set to the number of bytes occupied by the string in
 * the destination on success.
 *
 * @return true if new buffer was correctly allocated, and string was
 * converted.
 **/

bool pull_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src,
		      size_t *converted_size)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_talloc(ctx, CH_UTF8, CH_UNIX, src, src_len,
				     (void **)dest, converted_size);
}

 
/**
 * Copy a string from a DOS src to a unix char * destination, allocating a buffer using talloc
 *
 * @param dest always set at least to NULL 
 * @parm converted_size set to the number of bytes occupied by the string in
 * the destination on success.
 *
 * @return true if new buffer was correctly allocated, and string was
 * converted.
 **/

bool pull_ascii_talloc(TALLOC_CTX *ctx, char **dest, const char *src,
		       size_t *converted_size)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_talloc(ctx, CH_DOS, CH_UNIX, src, src_len,
				     (void **)dest, converted_size);
}

/**
 Copy a string from a char* src to a unicode or ascii
 dos codepage destination choosing unicode or ascii based on the 
 flags supplied
 Return the number of bytes occupied by the string in the destination.
 flags can have:
  STR_TERMINATE means include the null termination.
  STR_UPPER     means uppercase in the destination.
  STR_ASCII     use ascii even with unicode packet.
  STR_NOALIGN   means don't do alignment.
 dest_len is the maximum length allowed in the destination. If dest_len
 is -1 then no maxiumum is used.
**/

size_t push_string_check_fn(void *dest, const char *src,
			 size_t dest_len, int flags)
{
	if (!(flags & STR_ASCII) && (flags & STR_UNICODE)) {
		return push_ucs2(NULL, dest, src, dest_len, flags);
	}
	return push_ascii(dest, src, dest_len, flags);
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

size_t push_string_base(const char *base, uint16 flags2,
			void *dest, const char *src,
			size_t dest_len, int flags)
{

	if (!(flags & STR_ASCII) && \
	    ((flags & STR_UNICODE || \
	      (flags2 & FLAGS2_UNICODE_STRINGS)))) {
		return push_ucs2(base, dest, src, dest_len, flags);
	}
	return push_ascii(dest, src, dest_len, flags);
}

/**
 Copy a string from a char* src to a unicode or ascii
 dos codepage destination choosing unicode or ascii based on the 
 flags supplied
 Return the number of bytes occupied by the string in the destination.
 flags can have:
  STR_TERMINATE means include the null termination.
  STR_UPPER     means uppercase in the destination.
  STR_ASCII     use ascii even with unicode packet.
  STR_NOALIGN   means don't do alignment.
 dest_len is the maximum length allowed in the destination. If dest_len
 is -1 then no maxiumum is used.
**/

ssize_t push_string(void *dest, const char *src, size_t dest_len, int flags)
{
	size_t ret;

	if (!(flags & STR_ASCII) && \
	    (flags & STR_UNICODE)) {
		ret = push_ucs2(NULL, dest, src, dest_len, flags);
	} else {
		ret = push_ascii(dest, src, dest_len, flags);
	}
	if (ret == (size_t)-1) {
		return -1;
	}
	return ret;
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

size_t pull_string_fn(const void *base_ptr,
		   uint16 smb_flags2,
		   char *dest,
		   const void *src,
		   size_t dest_len,
		   size_t src_len,
		   int flags)
{
	if ((base_ptr == NULL) && ((flags & (STR_ASCII|STR_UNICODE)) == 0)) {
		smb_panic("No base ptr to get flg2 and neither ASCII nor "
			  "UNICODE defined");
	}

	if (!(flags & STR_ASCII) && \
	    ((flags & STR_UNICODE || \
	      (smb_flags2 & FLAGS2_UNICODE_STRINGS)))) {
		return pull_ucs2(base_ptr, dest, src, dest_len, src_len, flags);
	}
	return pull_ascii(dest, src, dest_len, src_len, flags);
}

/**
 Copy a string from a unicode or ascii source (depending on
 the packet flags) to a char* destination.
 Variant that uses talloc.
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

size_t pull_string_talloc(TALLOC_CTX *ctx,
			  const void *base_ptr,
			  uint16 smb_flags2,
			  char **ppdest,
			  const void *src,
			  size_t src_len,
			  int flags)
{
	if ((base_ptr == NULL) && ((flags & (STR_ASCII|STR_UNICODE)) == 0)) {
		smb_panic("No base ptr to get flg2 and neither ASCII nor "
			  "UNICODE defined");
	}

	if (!(flags & STR_ASCII) && \
	    ((flags & STR_UNICODE || \
	      (smb_flags2 & FLAGS2_UNICODE_STRINGS)))) {
		return pull_ucs2_base_talloc(ctx,
					base_ptr,
					ppdest,
					src,
					src_len,
					flags);
	}
	return pull_ascii_base_talloc(ctx,
					ppdest,
					src,
					src_len,
					flags);
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

