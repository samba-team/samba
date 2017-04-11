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
 * Destroy global objects allocated by init_iconv()
 **/
void gfree_charcnv(void)
{
	free_iconv_handle();
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
	size_t src_len = 0;
	char *tmpbuf = NULL;
	size_t size = 0;
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
		if (!strupper_m(tmpbuf)) {
			if ((flags & (STR_TERMINATE|STR_TERMINATE_ASCII)) &&
					dest &&
					dest_len > 0) {
				*(char *)dest = 0;
			}
			SAFE_FREE(tmpbuf);
			return 0;
		}
		src = tmpbuf;
	}

	src_len = strlen(src);
	if (flags & (STR_TERMINATE | STR_TERMINATE_ASCII)) {
		src_len++;
	}

	ret = convert_string(CH_UNIX, CH_DOS, src, src_len, dest, dest_len, &size);
	SAFE_FREE(tmpbuf);
	if (ret == false) {
		if ((flags & (STR_TERMINATE | STR_TERMINATE_ASCII)) &&
				dest_len > 0) {
			((char *)dest)[0] = '\0';
		}
		return 0;
	}
	return size;
}

/********************************************************************
 Push and malloc an ascii string. src and dest null terminated.
********************************************************************/

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
		smb_panic("src_len == -1 in pull_ascii_base_talloc");
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
				dest = talloc_realloc(ctx, dest, char,
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

static size_t push_ucs2(const void *base_ptr, void *dest, const char *src, size_t dest_len, int flags)
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

		/* We check for i < (size / 2) below as the dest string isn't null
		   terminated if STR_TERMINATE isn't set. */

		for (i = 0; i < (size / 2) && i < (dest_len / 2) && dest_ucs2[i]; i++) {
			smb_ucs2_t v = toupper_w(dest_ucs2[i]);
			if (v != dest_ucs2[i]) {
				dest_ucs2[i] = v;
			}
		}
	}

	return len;
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
				dest = talloc_realloc(ctx, dest, char,
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

size_t push_string_base(const char *base, uint16_t flags2,
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
			  uint16_t smb_flags2,
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

/*******************************************************************
 Write a string in (little-endian) unicode format. src is in
 the current DOS codepage. len is the length in bytes of the
 string pointed to by dst.

 if null_terminate is True then null terminate the packet (adds 2 bytes)

 the return value is the length in bytes consumed by the string, including the
 null termination if applied
********************************************************************/

size_t dos_PutUniCode(char *dst,const char *src, size_t len, bool null_terminate)
{
	int flags = null_terminate ? STR_UNICODE|STR_NOALIGN|STR_TERMINATE
				   : STR_UNICODE|STR_NOALIGN;
	return push_ucs2(NULL, dst, src, len, flags);
}


/* Converts a string from internal samba format to unicode. Always terminates.
 * Actually just a wrapper round push_ucs2_talloc().
 */

int rpcstr_push_talloc(TALLOC_CTX *ctx, smb_ucs2_t **dest, const char *src)
{
	size_t size;
	if (push_ucs2_talloc(ctx, dest, src, &size))
		return size;
	else
		return -1;
}
