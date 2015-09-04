/*
   Unix SMB/CIFS implementation.
   Character set conversion Extensions
   Copyright (C) Igor Vergeichik <iverg@mail.ru> 2001
   Copyright (C) Andrew Tridgell 2001-2011
   Copyright (C) Andrew Bartlett 2011
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
#include "system/iconv.h"

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

static bool convert_string_internal(struct smb_iconv_handle *ic,
				    charset_t from, charset_t to,
				    void const *src, size_t srclen,
				    void *dest, size_t destlen, size_t *converted_size)
{
	size_t i_len, o_len;
	size_t retval;
	const char* inbuf = (const char*)src;
	char* outbuf = (char*)dest;
	smb_iconv_t descriptor;

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
	*converted_size = destlen-o_len;

	return (retval != (size_t)-1);
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

bool convert_string_error_handle(struct smb_iconv_handle *ic,
				 charset_t from, charset_t to,
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
				bool ret = convert_string_internal(ic, from, to, p, slen, q, dlen, converted_size);
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
#ifndef BROKEN_UNICODE_COMPOSE_CHARACTERS
		bool ret;
#endif

		if (slen == (size_t)-1) {
			while (dlen &&
			       ((lastp = *p) <= 0x7f) && (p[1] == 0)) {
				*q++ = *p;
				p += 2;
				dlen--;
				retval++;
				if (!lastp)
					break;
			}
			if (lastp != 0) goto slow_path;
		} else {
			while (slen >= 2 && dlen &&
			       (*p <= 0x7f) && (p[1] == 0)) {
				*q++ = *p;
				slen -= 2;
				p += 2;
				dlen--;
				retval++;
			}
			if (slen != 0) goto slow_path;
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

	slow_path:
		/* come here when we hit a character we can't deal
		 * with in the fast path
		 */
#ifdef BROKEN_UNICODE_COMPOSE_CHARACTERS
		goto general_case;
#else
		ret = convert_string_internal(ic, from, to, p, slen, q, dlen, converted_size);
		*converted_size += retval;
		return ret;
#endif

	} else if (from != CH_UTF16LE && from != CH_UTF16BE && to == CH_UTF16LE) {
		const unsigned char *p = (const unsigned char *)src;
		unsigned char *q = (unsigned char *)dest;
		size_t retval = 0;
		size_t slen = srclen;
		size_t dlen = destlen;
		unsigned char lastp = '\0';

		/* If all characters are ascii, fast path here. */
		while (slen && (dlen >= 1)) {
			if (dlen >=2 && (lastp = *p) <= 0x7F) {
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
				bool ret = convert_string_internal(ic, from, to, p, slen, q, dlen, converted_size);
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
	return convert_string_internal(ic, from, to, src, srclen, dest, destlen, converted_size);
}

bool convert_string_handle(struct smb_iconv_handle *ic,
			   charset_t from, charset_t to,
			   void const *src, size_t srclen,
			   void *dest, size_t destlen,
			   size_t *converted_size)
{
	bool ret = convert_string_error_handle(ic, from, to, src, srclen, dest, destlen, converted_size);

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
 * I hate the goto's in this function. It's emberrassing.....
 * There has to be a cleaner way to do this. JRA.
 */
bool convert_string_talloc_handle(TALLOC_CTX *ctx, struct smb_iconv_handle *ic,
				  charset_t from, charset_t to,
				  void const *src, size_t srclen, void *dst,
				  size_t *converted_size)

{
	size_t i_len, o_len, destlen = (srclen * 3) / 2;
	size_t retval;
	const char *inbuf = (const char *)src;
	char *outbuf = NULL, *ob = NULL;
	smb_iconv_t descriptor;
	void **dest = (void **)dst;

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
		if (converted_size != NULL) {
			*converted_size = destlen;
		}
		*dest = ob;
		return true;
	}

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
	ob = talloc_realloc(ctx, ob, char, destlen + 2);

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
			default:
				DEBUG(0,("Conversion error: %s(%s)\n",reason,inbuf));
				break;
		}
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
		ob = talloc_realloc(ctx,ob, char, destlen + 2);
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

	if (converted_size != NULL) {
		*converted_size = destlen;
	}
	return true;
}

/**
 * Convert string from one encoding to another, making error checking etc
 *
 * @param src pointer to source string (multibyte or singlebyte)
 * @param srclen length of the source string in bytes
 * @param dest pointer to destination string (multibyte or singlebyte)
 * @param destlen maximal length allowed for string
 * @param converted_size the number of bytes occupied in the destination
 *
 * @returns true on success, false on fail.
 **/
_PUBLIC_ bool convert_string(charset_t from, charset_t to,
			       void const *src, size_t srclen,
			       void *dest, size_t destlen,
			       size_t *converted_size)
{
	return convert_string_handle(get_iconv_handle(), from, to,
					src, srclen,
					dest, destlen, converted_size);
}

/**
 * Convert string from one encoding to another, making error checking etc
 *
 * @param src pointer to source string (multibyte or singlebyte)
 * @param srclen length of the source string in bytes
 * @param dest pointer to destination string (multibyte or singlebyte)
 * @param destlen maximal length allowed for string
 * @param converted_size the number of bytes occupied in the destination
 *
 * @returns true on success, false on fail.
 **/
_PUBLIC_ bool convert_string_error(charset_t from, charset_t to,
				   void const *src, size_t srclen,
				   void *dest, size_t destlen,
				   size_t *converted_size)
{
	return convert_string_error_handle(get_iconv_handle(), from, to,
					   src, srclen,
					   dest, destlen, converted_size);
}

/**
 * Convert between character sets, allocating a new buffer using talloc for the result.
 *
 * @param srclen length of source buffer.
 * @param dest always set at least to NULL
 * @param converted_size Size in bytes of the converted string
 * @note -1 is not accepted for srclen.
 *
 * @returns boolean indication whether the conversion succeeded
 **/

_PUBLIC_ bool convert_string_talloc(TALLOC_CTX *ctx,
				    charset_t from, charset_t to,
				    void const *src, size_t srclen,
				    void *dest, size_t *converted_size)
{
	return convert_string_talloc_handle(ctx, get_iconv_handle(),
						 from, to, src, srclen, dest,
						 converted_size);
}
