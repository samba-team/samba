/* 
   Unix SMB/CIFS implementation.
   Character set conversion Extensions
   Copyright (C) Igor Vergeichik <iverg@mail.ru> 2001
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jelmer Vernooij 2007
   
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
#include "libcli/smb/smb_common.h"

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
 *
 * @param mem_ctx Memory context
 * @param cd Iconv handle
 * @param src pointer to source string (multibyte or singlebyte)
 * @param srclen length of the source string in bytes
 * @param dest pointer to destination string (multibyte or singlebyte)
 * @param destlen maximal length allowed for string
 * @returns the number of bytes occupied in the destination
 **/
_PUBLIC_ ssize_t iconv_talloc(TALLOC_CTX *ctx, 
				       smb_iconv_t cd,
				       void const *src, size_t srclen, 
				       void *dst)
{
	size_t i_len, o_len, destlen;
	void **dest = (void **)dst;
	size_t retval;
	const char *inbuf = (const char *)src;
	char *outbuf, *ob;

	*dest = NULL;

	/* it is _very_ rare that a conversion increases the size by
	   more than 3x */
	destlen = srclen;
	outbuf = NULL;
convert:
	destlen = 2 + (destlen*3);
	ob = talloc_realloc(ctx, outbuf, char, destlen);
	if (!ob) {
		DEBUG(0, ("iconv_talloc: realloc failed!\n"));
		talloc_free(outbuf);
		return (size_t)-1;
	} else {
		outbuf = ob;
	}

	/* we give iconv 2 less bytes to allow us to terminate at the
	   end */
	i_len = srclen;
	o_len = destlen-2;
	retval = smb_iconv(cd,
			   &inbuf, &i_len,
			   &outbuf, &o_len);
	if(retval == (size_t)-1) 		{
	    	const char *reason="unknown error";
		switch(errno) {
			case EINVAL:
				reason="Incomplete multibyte sequence";
				break;
			case E2BIG:
				goto convert;		
			case EILSEQ:
				reason="Illegal multibyte sequence";
				break;
		}
		DEBUG(0,("Conversion error: %s - ",reason));
		dump_data(0, (const uint8_t *) inbuf, i_len);
		talloc_free(ob);
		return (size_t)-1;
	}
	
	destlen = (destlen-2) - o_len;

	/* guarantee null termination in all charsets */
	SSVAL(ob, destlen, 0);

	*dest = ob;

	return destlen;

}
