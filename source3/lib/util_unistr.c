/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   
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

extern int DEBUGLEVEL;

 smb_ucs2_t wchar_list_sep[] = { (smb_ucs2_t)' ', (smb_ucs2_t)'\t', (smb_ucs2_t)',',
								(smb_ucs2_t)';', (smb_ucs2_t)':', (smb_ucs2_t)'\n',
								(smb_ucs2_t)'\r', 0 };
/*
 * The following are the codepage to ucs2 and vica versa maps.
 * These are dynamically loaded from a unicode translation file.
 */

static smb_ucs2_t *doscp_to_ucs2;
static uint16 *ucs2_to_doscp;

static smb_ucs2_t *unixcp_to_ucs2;
static uint16 *ucs2_to_unixcp;

#ifndef MAXUNI
#define MAXUNI 1024
#endif

/*******************************************************************
 Write a string in (little-endian) unicode format. src is in
 the current DOS codepage. len is the length in bytes of the
 string pointed to by dst.

 the return value is the length of the string *without* the trailing 
 two bytes of zero
********************************************************************/

int dos_PutUniCode(char *dst,const char *src, ssize_t len)
{
	int ret = 0;
	while (*src && (len > 2)) {
		size_t skip = get_character_len(*src);
		smb_ucs2_t val = (*src & 0xff);

		/*
		 * If this is a multibyte character (and all DOS/Windows
		 * codepages have at maximum 2 byte multibyte characters)
		 * then work out the index value for the unicode conversion.
		 */

		if (skip == 2)
			val = ((val << 8) | (src[1] & 0xff));

		SSVAL(dst,ret,doscp_to_ucs2[val]);
		ret += 2;
		len -= 2;
		if (skip)
			src += skip;
		else
			src++;
	}
	SSVAL(dst,ret,0);
	return(ret);
}

/*******************************************************************
 Put an ASCII string into a UNICODE array (uint16's).

 Warning: doesn't do any codepage !!! BAD !!!
 
 Help ! Fix Me ! Fix Me !
********************************************************************/

void ascii_to_unistr(uint16 *dest, const char *src, int maxlen)
{
	uint16 *destend = dest + maxlen;
	register char c;

	while (dest < destend)
	{
		c = *(src++);
		if (c == 0)
		{
			break;
		}

		*(dest++) = (uint16)c;
	}

	*dest = 0;
}

/*******************************************************************
 Pull an ASCII string out of a UNICODE array (uint16's).

 Warning: doesn't do any codepage !!! BAD !!!
 
 Help ! Fix Me ! Fix Me !
********************************************************************/

void unistr_to_ascii(char *dest, const uint16 *src, int len)
{
	char *destend = dest + len;
	register uint16 c;

	while (dest < destend)
	{
		c = *(src++);
		if (c == 0)
		{
			break;
		}

		*(dest++) = (char)c;
	}

	*dest = 0;
}


/*******************************************************************
 Skip past some unicode strings in a buffer.
********************************************************************/

char *skip_unicode_string(char *buf,int n)
{
	while (n--) {
		while (*buf)
			buf += 2;
		buf += 2;
	}
	return(buf);
}

/*******************************************************************
 Return a DOS codepage version of a little-endian unicode string.
 Hack alert: uses fixed buffer(s).
********************************************************************/

char *dos_unistrn2(uint16 *src, int len)
{
	static char lbufs[8][MAXUNI];
	static int nexti;
	char *lbuf = lbufs[nexti];
	char *p;

	nexti = (nexti+1)%8;

	for (p = lbuf; (len > 0) && (p-lbuf < MAXUNI-3) && *src; len--, src++) {
		uint16 ucs2_val = SVAL(src,0);
		uint16 cp_val = ucs2_to_doscp[ucs2_val];

		if (cp_val < 256)
			*p++ = (char)cp_val;
		else {
			*p++ = (cp_val >> 8) & 0xff;
			*p++ = (cp_val & 0xff);
		}
	}

	*p = 0;
	return lbuf;
}

static char lbufs[8][MAXUNI];
static int nexti;

/*******************************************************************
 Return a DOS codepage version of a little-endian unicode string.
 Hack alert: uses fixed buffer(s).
********************************************************************/

char *dos_unistr2(uint16 *src)
{
	char *lbuf = lbufs[nexti];
	char *p;

	nexti = (nexti+1)%8;

	for (p = lbuf; *src && (p-lbuf < MAXUNI-3); src++) {
		uint16 ucs2_val = SVAL(src,0);
		uint16 cp_val = ucs2_to_doscp[ucs2_val];

		if (cp_val < 256)
			*p++ = (char)cp_val;
		else {
			*p++ = (cp_val >> 8) & 0xff;
			*p++ = (cp_val & 0xff);
		}
	}

	*p = 0;
	return lbuf;
}

/*******************************************************************
Return a DOS codepage version of a little-endian unicode string
********************************************************************/

char *dos_unistr2_to_str(UNISTR2 *str)
{
	char *lbuf = lbufs[nexti];
	char *p;
	uint16 *src = str->buffer;
	int max_size = MIN(sizeof(str->buffer)-3, str->uni_str_len);

	nexti = (nexti+1)%8;

	for (p = lbuf; *src && p-lbuf < max_size; src++) {
		uint16 ucs2_val = SVAL(src,0);
		uint16 cp_val = ucs2_to_doscp[ucs2_val];

		if (cp_val < 256)
			*p++ = (char)cp_val;
		else {
			*p++ = (cp_val >> 8) & 0xff;
			*p++ = (cp_val & 0xff);
		}
	}

	*p = 0;
	return lbuf;
}

/*******************************************************************
 Convert a UNISTR2 structure to an ASCII string
 Warning: this version does DOS codepage.
********************************************************************/

void unistr2_to_ascii(char *dest, const UNISTR2 *str, size_t maxlen)
{
	char *destend;
	const uint16 *src;
	size_t len;
	register uint16 c;

	src = str->buffer;
	len = MIN(str->uni_str_len, maxlen);
	destend = dest + len;

	while (dest < destend)
	{
		uint16 ucs2_val;
		uint16 cp_val;

		c = *src;
		if (c == 0)
		{
			break;
		}
		
		ucs2_val = SVAL(src++,0);
		cp_val = ucs2_to_doscp[ucs2_val];
				
		if (cp_val < 256)
			*(dest++) = (char)cp_val;
		else {
			*dest= (cp_val >> 8) & 0xff;
			*(dest++) = (cp_val & 0xff);
		}
	}

	*dest = 0;
}


/*******************************************************************
Return a number stored in a buffer
********************************************************************/

uint32 buffer2_to_uint32(BUFFER2 *str)
{
	if (str->buf_len == 4)
		return IVAL(str->buffer, 0);
	else
		return 0;
}

/*******************************************************************
Return a DOS codepage version of a NOTunicode string
********************************************************************/

char *dos_buffer2_to_str(BUFFER2 *str)
{
	char *lbuf = lbufs[nexti];
	char *p;
	uint16 *src = str->buffer;
	int max_size = MIN(sizeof(str->buffer)-3, str->buf_len/2);

	nexti = (nexti+1)%8;

	for (p = lbuf; *src && p-lbuf < max_size; src++) {
		uint16 ucs2_val = SVAL(src,0);
		uint16 cp_val = ucs2_to_doscp[ucs2_val];

		if (cp_val < 256)
			*p++ = (char)cp_val;
		else {
			*p++ = (cp_val >> 8) & 0xff;
			*p++ = (cp_val & 0xff);
		}
	}

	*p = 0;
	return lbuf;
}

/*******************************************************************
 Return a dos codepage version of a NOTunicode string
********************************************************************/

char *dos_buffer2_to_multistr(BUFFER2 *str)
{
	char *lbuf = lbufs[nexti];
	char *p;
	uint16 *src = str->buffer;
	int max_size = MIN(sizeof(str->buffer)-3, str->buf_len/2);

	nexti = (nexti+1)%8;

	for (p = lbuf; p-lbuf < max_size; src++) {
		if (*src == 0) {
			*p++ = ' ';
		} else {
			uint16 ucs2_val = SVAL(src,0);
			uint16 cp_val = ucs2_to_doscp[ucs2_val];

			if (cp_val < 256)
				*p++ = (char)cp_val;
			else {
				*p++ = (cp_val >> 8) & 0xff;
				*p++ = (cp_val & 0xff);
			}
		}
	}

	*p = 0;
	return lbuf;
}

/*******************************************************************
 Create a null-terminated unicode string from a null-terminated DOS
 codepage string.
 Return number of unicode chars copied, excluding the null character.
 Unicode strings created are in little-endian format.
********************************************************************/

size_t dos_struni2(char *dst, const char *src, size_t max_len)
{
	size_t len = 0;

	if (dst == NULL)
		return 0;

	if (src != NULL) {
		for (; *src && len < max_len-2; len++, dst +=2) {
			size_t skip = get_character_len(*src);
			smb_ucs2_t val = (*src & 0xff);

			/*
			 * If this is a multibyte character (and all DOS/Windows
			 * codepages have at maximum 2 byte multibyte characters)
			 * then work out the index value for the unicode conversion.
			 */

			if (skip == 2)
				val = ((val << 8) | (src[1] & 0xff));

			SSVAL(dst,0,doscp_to_ucs2[val]);
			if (skip)
				src += skip;
			else
				src++;
		}
	}

	SSVAL(dst,0,0);

	return len;
}

/*******************************************************************
 Return a DOS codepage version of a little-endian unicode string.
 Hack alert: uses fixed buffer(s).
********************************************************************/

char *dos_unistr(char *buf)
{
	char *lbuf = lbufs[nexti];
	uint16 *src = (uint16 *)buf;
	char *p;

	nexti = (nexti+1)%8;

	for (p = lbuf; *src && p-lbuf < MAXUNI-3; src++) {
		uint16 ucs2_val = SVAL(src,0);
		uint16 cp_val = ucs2_to_doscp[ucs2_val];

		if (cp_val < 256)
			*p++ = (char)cp_val;
		else {
			*p++ = (cp_val >> 8) & 0xff;
			*p++ = (cp_val & 0xff);
		}
	}

	*p = 0;
	return lbuf;
}

/*******************************************************************
 Strcpy for unicode strings.  returns length (in num of wide chars)
********************************************************************/

int unistrcpy(char *dst, char *src)
{
	int num_wchars = 0;
	uint16 *wsrc = (uint16 *)src;
	uint16 *wdst = (uint16 *)dst;

	while (*wsrc) {
		*wdst++ = *wsrc++;
		num_wchars++;
	}
	*wdst = 0;

	return num_wchars;
}



/*******************************************************************
 Free any existing maps.
********************************************************************/

static void free_maps(smb_ucs2_t **pp_cp_to_ucs2, uint16 **pp_ucs2_to_cp)
{
	/* this handles identity mappings where we share the pointer */
	if (*pp_ucs2_to_cp == *pp_cp_to_ucs2) {
		*pp_ucs2_to_cp = NULL;
	}

	if (*pp_cp_to_ucs2) {
		free(*pp_cp_to_ucs2);
		*pp_cp_to_ucs2 = NULL;
	}

	if (*pp_ucs2_to_cp) {
		free(*pp_ucs2_to_cp);
		*pp_ucs2_to_cp = NULL;
	}
}


/*******************************************************************
 Build a default (null) codepage to unicode map.
********************************************************************/

void default_unicode_map(smb_ucs2_t **pp_cp_to_ucs2, uint16 **pp_ucs2_to_cp)
{
  int i;

  free_maps(pp_cp_to_ucs2, pp_ucs2_to_cp);

  if ((*pp_ucs2_to_cp = (uint16 *)malloc(2*65536)) == NULL) {
    DEBUG(0,("default_unicode_map: malloc fail for ucs2_to_cp size %u.\n", 2*65536));
    abort();
  }

  *pp_cp_to_ucs2 = *pp_ucs2_to_cp; /* Default map is an identity. */
  for (i = 0; i < 65536; i++)
    (*pp_cp_to_ucs2)[i] = i;
}

/*******************************************************************
 Load a codepage to unicode and vica-versa map.
********************************************************************/

BOOL load_unicode_map(const char *codepage, smb_ucs2_t **pp_cp_to_ucs2, uint16 **pp_ucs2_to_cp)
{
  pstring unicode_map_file_name;
  FILE *fp = NULL;
  SMB_STRUCT_STAT st;
  smb_ucs2_t *cp_to_ucs2 = *pp_cp_to_ucs2;
  uint16 *ucs2_to_cp = *pp_ucs2_to_cp;
  size_t cp_to_ucs2_size;
  size_t ucs2_to_cp_size;
  size_t i;
  size_t size;
  char buf[UNICODE_MAP_HEADER_SIZE];

  DEBUG(5, ("load_unicode_map: loading unicode map for codepage %s.\n", codepage));

  if (*codepage == '\0')
    goto clean_and_exit;

  if(strlen(CODEPAGEDIR) + 13 + strlen(codepage) > sizeof(unicode_map_file_name)) {
    DEBUG(0,("load_unicode_map: filename too long to load\n"));
    goto clean_and_exit;
  }

  pstrcpy(unicode_map_file_name, CODEPAGEDIR);
  pstrcat(unicode_map_file_name, "/");
  pstrcat(unicode_map_file_name, "unicode_map.");
  pstrcat(unicode_map_file_name, codepage);

  if(sys_stat(unicode_map_file_name,&st)!=0) {
    DEBUG(0,("load_unicode_map: filename %s does not exist.\n",
              unicode_map_file_name));
    goto clean_and_exit;
  }

  size = st.st_size;

  if ((size != UNICODE_MAP_HEADER_SIZE + 4*65536) && (size != UNICODE_MAP_HEADER_SIZE +(2*256 + 2*65536))) {
    DEBUG(0,("load_unicode_map: file %s is an incorrect size for a \
unicode map file (size=%d).\n", unicode_map_file_name, (int)size));
    goto clean_and_exit;
  }

  if((fp = sys_fopen( unicode_map_file_name, "r")) == NULL) {
    DEBUG(0,("load_unicode_map: cannot open file %s. Error was %s\n",
              unicode_map_file_name, strerror(errno)));
    goto clean_and_exit;
  }

  if(fread( buf, 1, UNICODE_MAP_HEADER_SIZE, fp)!=UNICODE_MAP_HEADER_SIZE) {
    DEBUG(0,("load_unicode_map: cannot read header from file %s. Error was %s\n",
              unicode_map_file_name, strerror(errno)));
    goto clean_and_exit;
  }

  /* Check the version value */
  if(SVAL(buf,UNICODE_MAP_VERSION_OFFSET) != UNICODE_MAP_FILE_VERSION_ID) {
    DEBUG(0,("load_unicode_map: filename %s has incorrect version id. \
Needed %hu, got %hu.\n",
          unicode_map_file_name, (uint16)UNICODE_MAP_FILE_VERSION_ID,
          SVAL(buf,UNICODE_MAP_VERSION_OFFSET)));
    goto clean_and_exit;
  }

  /* Check the codepage value */
  if(!strequal(&buf[UNICODE_MAP_CLIENT_CODEPAGE_OFFSET], codepage)) {
    DEBUG(0,("load_unicode_map: codepage %s in file %s is not the same as that \
requested (%s).\n", &buf[UNICODE_MAP_CLIENT_CODEPAGE_OFFSET], unicode_map_file_name, codepage ));
    goto clean_and_exit;
  }

  ucs2_to_cp_size = 2*65536;
  if (size == UNICODE_MAP_HEADER_SIZE + 4*65536) {
    /* 
     * This is a multibyte code page.
     */
    cp_to_ucs2_size = 2*65536;
  } else {
    /*
     * Single byte code page.
     */
    cp_to_ucs2_size = 2*256;
  }

  /* 
   * Free any old translation tables.
   */

  free_maps(pp_cp_to_ucs2, pp_ucs2_to_cp);

  if ((cp_to_ucs2 = (smb_ucs2_t *)malloc(cp_to_ucs2_size)) == NULL) {
    DEBUG(0,("load_unicode_map: malloc fail for cp_to_ucs2 size %u.\n", cp_to_ucs2_size ));
    goto clean_and_exit;
  }

  if ((ucs2_to_cp = (uint16 *)malloc(ucs2_to_cp_size)) == NULL) {
    DEBUG(0,("load_unicode_map: malloc fail for ucs2_to_cp size %u.\n", ucs2_to_cp_size ));
    goto clean_and_exit;
  }

  if(fread( (char *)cp_to_ucs2, 1, cp_to_ucs2_size, fp)!=cp_to_ucs2_size) {
    DEBUG(0,("load_unicode_map: cannot read cp_to_ucs2 from file %s. Error was %s\n",
              unicode_map_file_name, strerror(errno)));
    goto clean_and_exit;
  }

  if(fread( (char *)ucs2_to_cp, 1, ucs2_to_cp_size, fp)!=ucs2_to_cp_size) {
    DEBUG(0,("load_unicode_map: cannot read ucs2_to_cp from file %s. Error was %s\n",
              unicode_map_file_name, strerror(errno)));
    goto clean_and_exit;
  }

  /*
   * Now ensure the 16 bit values are in the correct endianness.
   */

  for (i = 0; i < cp_to_ucs2_size/2; i++)
    cp_to_ucs2[i] = SVAL(cp_to_ucs2,i*2);

  for (i = 0; i < ucs2_to_cp_size/2; i++)
    ucs2_to_cp[i] = SVAL(ucs2_to_cp,i*2);

  fclose(fp);

  *pp_cp_to_ucs2 = cp_to_ucs2;
  *pp_ucs2_to_cp = ucs2_to_cp;

  return True;

clean_and_exit:

  /* pseudo destructor :-) */

  if(fp != NULL)
    fclose(fp);

  free_maps(pp_cp_to_ucs2, pp_ucs2_to_cp);

  default_unicode_map(pp_cp_to_ucs2, pp_ucs2_to_cp);

  return False;
}

/*******************************************************************
 Load a dos codepage to unicode and vica-versa map.
********************************************************************/

BOOL load_dos_unicode_map(int codepage)
{
  fstring codepage_str;

  slprintf(codepage_str, sizeof(fstring)-1, "%03d", codepage);
  return load_unicode_map(codepage_str, &doscp_to_ucs2, &ucs2_to_doscp);
}

/*******************************************************************
 Load a UNIX codepage to unicode and vica-versa map.
********************************************************************/

BOOL load_unix_unicode_map(const char *unix_char_set)
{
  fstring upper_unix_char_set;

  fstrcpy(upper_unix_char_set, unix_char_set);
  strupper(upper_unix_char_set);
  return load_unicode_map(upper_unix_char_set, &unixcp_to_ucs2, &ucs2_to_unixcp);
}

/*******************************************************************
 The following functions reproduce many of the non-UNICODE standard
 string functions in Samba.
********************************************************************/

/*******************************************************************
 Convert a UNICODE string to multibyte format. Note that the 'src' is in
 native byte order, not little endian. Always zero terminates.
 dst_len is in bytes.
********************************************************************/

static char *unicode_to_multibyte(char *dst, const smb_ucs2_t *src,
                                  size_t dst_len, const uint16 *ucs2_to_cp)
{
	size_t dst_pos;

	for(dst_pos = 0; *src && (dst_pos < dst_len - 1);) {
		smb_ucs2_t val = ucs2_to_cp[*src++];
		if(val < 256) {
			dst[dst_pos++] = (char)val;
		} else {

			if(dst_pos >= dst_len - 2)
				break;

			/*
			 * A 2 byte value is always written as
			 * high/low into the buffer stream.
			 */

			dst[dst_pos++] = (char)((val >> 8) & 0xff);
			dst[dst_pos++] = (char)(val & 0xff);
		}
	} 	

	dst[dst_pos] = '\0';

	return dst;
}

/*******************************************************************
 Convert a multibyte string to UNICODE format. Note that the 'dst' is in
 native byte order, not little endian. Always zero terminates.
 dst_len is in bytes.
********************************************************************/

smb_ucs2_t *multibyte_to_unicode(smb_ucs2_t *dst, const char *src,
                                 size_t dst_len, smb_ucs2_t *cp_to_ucs2)
{
	size_t i;

	dst_len /= sizeof(smb_ucs2_t); /* Convert to smb_ucs2_t units. */

	for(i = 0; (i < (dst_len  - 1)) && src[i];) {
		size_t skip = get_character_len(*src);
		smb_ucs2_t val = (*src & 0xff);

		/*
		 * If this is a multibyte character
		 * then work out the index value for the unicode conversion.
		 */

		if (skip == 2)
			val = ((val << 8) | (src[1] & 0xff));

		dst[i++] = cp_to_ucs2[val];
		if (skip)
			src += skip;
		else
			src++;
	}

	dst[i] = 0;

	return dst;
}

/*******************************************************************
 Convert a UNICODE string to multibyte format. Note that the 'src' is in
 native byte order, not little endian. Always zero terminates.
 This function may be replaced if the MB  codepage format is an
 encoded one (ie. utf8, hex). See the code in lib/kanji.c
 for details. dst_len is in bytes.
********************************************************************/

char *unicode_to_unix(char *dst, const smb_ucs2_t *src, size_t dst_len)
{
	return unicode_to_multibyte(dst, src, dst_len, ucs2_to_unixcp);
}

/*******************************************************************
 Convert a UNIX string to UNICODE format. Note that the 'dst' is in
 native byte order, not little endian. Always zero terminates.
 This function may be replaced if the UNIX codepage format is a
 multi-byte one (ie. JIS, SJIS or utf8). See the code in lib/kanji.c
 for details. dst_len is in bytes, not ucs2 units.
********************************************************************/

smb_ucs2_t *unix_to_unicode(smb_ucs2_t *dst, const char *src, size_t dst_len)
{
	return multibyte_to_unicode(dst, src, dst_len, unixcp_to_ucs2);
}

/*******************************************************************
 Convert a UNICODE string to DOS format. Note that the 'src' is in
 native byte order, not little endian. Always zero terminates. 
 dst_len is in bytes.
********************************************************************/ 

char *unicode_to_dos(char *dst, const smb_ucs2_t *src, size_t dst_len)
{
	return unicode_to_multibyte(dst, src, dst_len, ucs2_to_doscp);
}

/*******************************************************************
 Convert a DOS string to UNICODE format. Note that the 'dst' is in
 native byte order, not little endian. Always zero terminates.
 This function may be replaced if the DOS codepage format is a
 multi-byte one (ie. JIS, SJIS or utf8). See the code in lib/kanji.c
 for details. dst_len is in bytes, not ucs2 units.
********************************************************************/

smb_ucs2_t *dos_to_unicode(smb_ucs2_t *dst, const char *src, size_t dst_len)
{
	return multibyte_to_unicode(dst, src, dst_len, doscp_to_ucs2);
}

/*******************************************************************
 Count the number of characters in a smb_ucs2_t string.
********************************************************************/

size_t strlen_w(const smb_ucs2_t *src)
{
  size_t len;

  for(len = 0; *src; len++)
    ;

  return len;
}

/*******************************************************************
 Safe wstring copy into a known length string. maxlength includes
 the terminating zero. maxlength is in bytes.
********************************************************************/

smb_ucs2_t *safe_strcpy_w(smb_ucs2_t *dest,const smb_ucs2_t *src, size_t maxlength)
{
    size_t ucs2_len;

    if (!dest) {
        DEBUG(0,("ERROR: NULL dest in safe_strcpy_w\n"));
        return NULL;
    }

    if (!src) {
        *dest = 0;
        return dest;
    }

	/*
	 * Convert maxlength to smb_ucs2_t units.
	 */

	maxlength /= sizeof(smb_ucs2_t);

	ucs2_len = strlen_w(src);

    if (ucs2_len >= maxlength) {
		fstring out;
        DEBUG(0,("ERROR: string overflow by %u bytes in safe_strcpy_w [%.50s]\n",
			(unsigned int)((ucs2_len-maxlength)*sizeof(smb_ucs2_t)),
			unicode_to_unix(out,src,sizeof(out))) );
		ucs2_len = maxlength - 1;
    }

    memcpy(dest, src, ucs2_len*sizeof(smb_ucs2_t));
    dest[ucs2_len] = 0;
    return dest;
}

/*******************************************************************
 Safe string cat into a string. maxlength includes the terminating zero.
 maxlength is in bytes.
********************************************************************/

smb_ucs2_t *safe_strcat_w(smb_ucs2_t *dest, const smb_ucs2_t *src, size_t maxlength)
{
    size_t ucs2_src_len, ucs2_dest_len;

    if (!dest) {
        DEBUG(0,("ERROR: NULL dest in safe_strcat_w\n"));
        return NULL;
    }

    if (!src)
        return dest;

	/*
	 * Convert maxlength to smb_ucs2_t units.
	 */

	maxlength /= sizeof(smb_ucs2_t);

    ucs2_src_len = strlen_w(src);
    ucs2_dest_len = strlen_w(dest);

    if (ucs2_src_len + ucs2_dest_len >= maxlength) {
		fstring out;
		int new_len = maxlength - ucs2_dest_len - 1;
        DEBUG(0,("ERROR: string overflow by %u characters in safe_strcat_w [%.50s]\n",
			(unsigned int)(sizeof(smb_ucs2_t)*(ucs2_src_len + ucs2_dest_len - maxlength)),
			unicode_to_unix(out,src,sizeof(out))) );
        ucs2_src_len = (size_t)(new_len > 0 ? new_len : 0);
    }

    memcpy(&dest[ucs2_dest_len], src, ucs2_src_len*sizeof(smb_ucs2_t));
    dest[ucs2_dest_len + ucs2_src_len] = 0;
    return dest;
}

/*******************************************************************
 Compare the two strings s1 and s2. len is in ucs2 units.
********************************************************************/

int strcmp_w(const smb_ucs2_t *s1, const smb_ucs2_t *s2)
{
	smb_ucs2_t c1, c2;

	for (;;) {
		c1 = *s1++;
		c2 = *s2++;

		if (c1 != c2)
			return c1 - c2;

		if (c1 == 0)
            return 0;
    }
	return 0;
}

/*******************************************************************
 Compare the first n characters of s1 to s2. len is in ucs2 units.
********************************************************************/

int strncmp_w(const smb_ucs2_t *s1, const smb_ucs2_t *s2, size_t len)
{
	smb_ucs2_t c1, c2;

	for (; len != 0; --len) {
		c1 = *s1++;
		c2 = *s2++;

		if (c1 != c2)
			return c1 - c2;

		if (c1 == 0)
			return 0;

    }
	return 0;
}

/*******************************************************************
 Search string s2 from s1.
********************************************************************/

smb_ucs2_t *strstr_w(const smb_ucs2_t *s1, const smb_ucs2_t *s2)
{
	size_t len = strlen_w(s2);

	if (!*s2)
		return (smb_ucs2_t *)s1;

	for(;*s1; s1++) {
		if (*s1 == *s2) {
			if (strncmp_w(s1, s2, len) == 0)
				return (smb_ucs2_t *)s1;
		}
	}
	return NULL; 
}

/*******************************************************************
 Search for ucs2 char c from the beginning of s.
********************************************************************/ 

smb_ucs2_t *strchr_w(const smb_ucs2_t *s, smb_ucs2_t c)
{
	do {
		if (*s == c)
			return (smb_ucs2_t *)s;
	} while (*s++);

	return NULL;
}

/*******************************************************************
 Search for ucs2 char c from the end of s.
********************************************************************/ 

smb_ucs2_t *strrchr_w(const smb_ucs2_t *s, smb_ucs2_t c)
{
	smb_ucs2_t *retval = 0;

	do {
		if (*s == c)
			retval = (smb_ucs2_t *)s;
	} while (*s++);

	return retval;
}

/*******************************************************************
 Search token from s1 separated by any ucs2 char of s2.
********************************************************************/

smb_ucs2_t *strtok_w(smb_ucs2_t *s1, const smb_ucs2_t *s2)
{
	static smb_ucs2_t *s = NULL;
	smb_ucs2_t *q;

	if (!s1) {
		if (!s)
			return NULL;
		s1 = s;
	}

	for (q = s1; *s1; s1++) {
		smb_ucs2_t *p = strchr_w(s2, *s1);
		if (p) {
			if (s1 != q) {
				s = s1 + 1;
				*s1 = '\0';
				return q;
			}
			q = s1 + 1;
		}
	}

	s = NULL;
	if (*q)
		return q;

	return NULL;
}

/*******************************************************************
 Duplicate a ucs2 string.
********************************************************************/

smb_ucs2_t *strdup_w(const smb_ucs2_t *s)
{
	size_t newlen = (strlen_w(s)+1)*sizeof(smb_ucs2_t);
	smb_ucs2_t *newstr = (smb_ucs2_t *)malloc(newlen);
    if (newstr == NULL)
        return NULL;
    safe_strcpy_w(newstr, s, newlen);
    return newstr;
}

/*******************************************************************
 Mapping tables for UNICODE character. Allows toupper/tolower and
 isXXX functions to work.
********************************************************************/

typedef struct {
	smb_ucs2_t lower;
	smb_ucs2_t upper;
	unsigned char flags;
} smb_unicode_table_t;

static smb_unicode_table_t map_table[] = {
#include "unicode_map_table.h"
};

/*******************************************************************
 Is an upper case wchar.
********************************************************************/

int isupper_w( smb_ucs2_t val)
{
	return (map_table[val].flags & UNI_UPPER);
}

/*******************************************************************
 Is a lower case wchar.
********************************************************************/

int islower_w( smb_ucs2_t val)
{
	return (map_table[val].flags & UNI_LOWER);
}

/*******************************************************************
 Is a digit wchar.
********************************************************************/

int isdigit_w( smb_ucs2_t val)
{
	return (map_table[val].flags & UNI_DIGIT);
}

/*******************************************************************
 Is a hex digit wchar.
********************************************************************/

int isxdigit_w( smb_ucs2_t val)
{
	return (map_table[val].flags & UNI_XDIGIT);
}

/*******************************************************************
 Is a space wchar.
********************************************************************/

int isspace_w( smb_ucs2_t val)
{
	return (map_table[val].flags & UNI_SPACE);
}

/*******************************************************************
 Convert a wchar to upper case.
********************************************************************/

smb_ucs2_t toupper_w( smb_ucs2_t val )
{
	return map_table[val].upper;
}

/*******************************************************************
 Convert a wchar to lower case.
********************************************************************/

smb_ucs2_t tolower_w( smb_ucs2_t val )
{
	return map_table[val].lower;
}

static smb_ucs2_t *last_ptr = NULL;

void set_first_token_w(smb_ucs2_t *ptr)
{
	last_ptr = ptr;
}

/****************************************************************************
 Get the next token from a string, return False if none found
 handles double-quotes. 
 Based on a routine by GJC@VILLAGE.COM. 
 Extensively modified by Andrew.Tridgell@anu.edu.au
 bufsize is in bytes.
****************************************************************************/

static smb_ucs2_t sep_list[] = { (smb_ucs2_t)' ', (smb_ucs2_t)'\t',  (smb_ucs2_t)'\n',  (smb_ucs2_t)'\r', 0};
static smb_ucs2_t quotechar = (smb_ucs2_t)'\"';

BOOL next_token_w(smb_ucs2_t **ptr, smb_ucs2_t *buff, smb_ucs2_t *sep, size_t bufsize)
{
	smb_ucs2_t *s;
	BOOL quoted;
	size_t len=1;

	/*
	 * Convert bufsize to smb_ucs2_t units.
	 */

	bufsize /= sizeof(smb_ucs2_t);

	if (!ptr)
		ptr = &last_ptr;
	if (!ptr)
		return(False);

	s = *ptr;

	/*
	 * Default to simple separators.
	 */

	if (!sep)
		sep = sep_list;

	/*
	 * Find the first non sep char.
	 */

	while(*s && strchr_w(sep,*s))
		s++;

	/*
	 * Nothing left ?
	 */

	if (!*s)
		return(False);

	/*
	 * Copy over the token.
	 */

	for (quoted = False; len < bufsize && *s && (quoted || !strchr_w(sep,*s)); s++) {
		if (*s == quotechar) {
			quoted = !quoted;
		} else {
			len++;
			*buff++ = *s;
		}
	}

	*ptr = (*s) ? s+1 : s;  
	*buff = 0;
	last_ptr = *ptr;

	return(True);
}

/****************************************************************************
 Convert list of tokens to array; dependent on above routine.
 Uses last_ptr from above - bit of a hack.
****************************************************************************/

smb_ucs2_t **toktocliplist_w(int *ctok, smb_ucs2_t *sep)
{
	smb_ucs2_t *s=last_ptr;
	int ictok=0;
	smb_ucs2_t **ret, **iret;

	if (!sep)
		sep = sep_list;

	while(*s && strchr_w(sep,*s))
		s++;

	/*
	 * Nothing left ?
	 */

	if (!*s)
		return(NULL);

	do {
		ictok++;
		while(*s && (!strchr_w(sep,*s)))
			s++;
		while(*s && strchr_w(sep,*s))
			*s++=0;
	} while(*s);

	*ctok = ictok;
	s = last_ptr;

	if (!(ret=iret=malloc(ictok*sizeof(smb_ucs2_t *))))
		return NULL;
  
	while(ictok--) {
		*iret++=s;
		while(*s++)
			;
		while(!*s)
			s++;
	}

	return ret;
}

/*******************************************************************
 Case insensitive string compararison.
********************************************************************/

int StrCaseCmp_w(const smb_ucs2_t *s, const smb_ucs2_t *t)
{
	/* 
	 * Compare until we run out of string, either t or s, or find a difference.
	 */

	while (*s && *t && toupper_w(*s) == toupper_w(*t)) {
		s++;
		t++;
	}

	return(toupper_w(*s) - toupper_w(*t));
}

/*******************************************************************
 Case insensitive string compararison, length limited.
********************************************************************/

int StrnCaseCmp_w(const smb_ucs2_t *s, const smb_ucs2_t *t, size_t n)
{
	/*
	 * Compare until we run out of string, either t or s, or chars.
	 */

	while (n && *s && *t && toupper_w(*s) == toupper_w(*t)) {
		s++;
		t++;
		n--;
	}

    /*
	 * Not run out of chars - strings are different lengths.
	 */

    if (n) 
      return(toupper_w(*s) - toupper_w(*t));

    /*
	 * Identical up to where we run out of chars, 
	 * and strings are same length.
	 */

	return(0);
}

/*******************************************************************
 Compare 2 strings.
********************************************************************/

BOOL strequal_w(const smb_ucs2_t *s1, const smb_ucs2_t *s2)
{
	if (s1 == s2)
		return(True);
	if (!s1 || !s2)
		return(False);
  
	return(StrCaseCmp_w(s1,s2)==0);
}

/*******************************************************************
 Compare 2 strings up to and including the nth char.
******************************************************************/

BOOL strnequal_w(const smb_ucs2_t *s1,const smb_ucs2_t *s2,size_t n)
{
	if (s1 == s2)
		return(True);
	if (!s1 || !s2 || !n)
		return(False);
  
	return(StrnCaseCmp_w(s1,s2,n)==0);
}

/*******************************************************************
 Compare 2 strings (case sensitive).
********************************************************************/

BOOL strcsequal_w(const smb_ucs2_t *s1,const smb_ucs2_t *s2)
{
	if (s1 == s2)
		return(True);
	if (!s1 || !s2)
		return(False);
  
	return(strcmp_w(s1,s2)==0);
}

/*******************************************************************
 Convert a string to lower case.
********************************************************************/

void strlower_w(smb_ucs2_t *s)
{
	while (*s) {
		if (isupper_w(*s))
			*s = tolower_w(*s);
		s++;
	}
}

/*******************************************************************
 Convert a string to upper case.
********************************************************************/

void strupper_w(smb_ucs2_t *s)
{
	while (*s) {
		if (islower_w(*s))
			*s = toupper_w(*s);
		s++;
	}
}

/*******************************************************************
 Convert a string to "normal" form.
********************************************************************/

void strnorm_w(smb_ucs2_t *s)
{
	extern int case_default;
	if (case_default == CASE_UPPER)
		strupper_w(s);
	else
		strlower_w(s);
}

/*******************************************************************
 Check if a string is in "normal" case.
********************************************************************/

BOOL strisnormal_w(smb_ucs2_t *s)
{
	extern int case_default;
	if (case_default == CASE_UPPER)
		return(!strhaslower_w(s));

	return(!strhasupper_w(s));
}

/****************************************************************************
 String replace.
****************************************************************************/

void string_replace_w(smb_ucs2_t *s, smb_ucs2_t oldc, smb_ucs2_t newc)
{
	while (*s) {
		if (oldc == *s)
			*s = newc;
		s++;
	}
}

/*******************************************************************
 Skip past some strings in a buffer. n is in bytes.
********************************************************************/

smb_ucs2_t *skip_string_w(smb_ucs2_t *buf,size_t n)
{
	while (n--)
		buf += (strlen_w(buf)*sizeof(smb_ucs2_t)) + 1;
	return(buf);
}

/*******************************************************************
 Count the number of characters in a string. Same as strlen_w in
 smb_ucs2_t string units.
********************************************************************/

size_t str_charnum_w(const smb_ucs2_t *s)
{
	return strlen_w(s);
}

/*******************************************************************
 Trim the specified elements off the front and back of a string.
********************************************************************/

BOOL trim_string_w(smb_ucs2_t *s,const smb_ucs2_t *front,const smb_ucs2_t *back)
{
	BOOL ret = False;
	size_t front_len = (front && *front) ? strlen_w(front) : 0;
	size_t back_len = (back && *back) ? strlen_w(back) : 0;
	size_t s_len;

	while (front_len && strncmp_w(s, front, front_len) == 0) {
		smb_ucs2_t *p = s;
		ret = True;

		while (1) {
			if (!(*p = p[front_len]))
				break;
			p++;
		}
	}

	if(back_len) {
		s_len = strlen_w(s);
		while ((s_len >= back_len) && 
			(strncmp_w(s + s_len - back_len, back, back_len)==0)) {
			ret = True;
			s[s_len - back_len] = 0;
			s_len = strlen_w(s);
		}
	}

	return(ret);
}

/****************************************************************************
 Does a string have any uppercase chars in it ?
****************************************************************************/

BOOL strhasupper_w(const smb_ucs2_t *s)
{
	while (*s) {
		if (isupper_w(*s))
			return(True);
		s++;
	}
	return(False);
}

/****************************************************************************
 Does a string have any lowercase chars in it ?
****************************************************************************/

BOOL strhaslower_w(const smb_ucs2_t *s)
{
	while (*s) {
		if (islower(*s))
			return(True);
		s++;
	}
	return(False);
}

/****************************************************************************
 Find the number of 'c' chars in a string.
****************************************************************************/

size_t count_chars_w(const smb_ucs2_t *s,smb_ucs2_t c)
{
	size_t count=0;

	while (*s) {
		if (*s == c)
			count++;
		s++;
	}
	return(count);
}

/*******************************************************************
 Return True if a string consists only of one particular character.
********************************************************************/

BOOL str_is_all_w(const smb_ucs2_t *s,smb_ucs2_t c)
{
	if(s == NULL)
		return False;
	if(!*s)
		return False;

	while (*s) {
		if (*s != c)
			return False;
		s++;
	}
	return True;
}

/*******************************************************************
 Paranoid strcpy into a buffer of given length (includes terminating
 zero. Strips out all but 'a-Z0-9' and replaces with '_'. Deliberately
 does *NOT* check for multibyte characters. Don't change it !
 maxlength is in bytes.
********************************************************************/

smb_ucs2_t *alpha_strcpy_w(smb_ucs2_t *dest, const smb_ucs2_t *src, size_t maxlength)
{
	size_t len, i;

	/*
	 * Convert to smb_ucs2_t units.
	 */

	maxlength /= sizeof(smb_ucs2_t);

	if (!dest) {
		DEBUG(0,("ERROR: NULL dest in alpha_strcpy_w\n"));
		return NULL;
	}

	if (!src) {
		*dest = 0;
		return dest;
	}  

	len = strlen_w(src);
	if (len >= maxlength)
		len = maxlength - 1;

	for(i = 0; i < len; i++) {
		smb_ucs2_t val = src[i];
		if(isupper_w(val) ||islower_w(val) || isdigit_w(val))
			dest[i] = src[i];
		else
			dest[i] = (smb_ucs2_t)'_';
	}

	dest[i] = 0;

	return dest;
}

/****************************************************************************
 Like strncpy but always null terminates. Make sure there is room !
 The variable n should always be one less than the available size and is in bytes.
****************************************************************************/

smb_ucs2_t *StrnCpy_w(smb_ucs2_t *dest,const smb_ucs2_t *src,size_t n)
{
	smb_ucs2_t *d = dest;
	if (!dest)
		return(NULL);
	if (!src) {
		*dest = 0;
		return(dest);
	}

	/*
	 * Convert to smb_ucs2_t units.
	 */

	n /= sizeof(smb_ucs2_t);

	while (n-- && (*d++ = *src++))
		;
	*d = 0;
	return(dest);
}

/****************************************************************************
 Like strncpy but copies up to the character marker. Always null terminates.
 returns a pointer to the character marker in the source string (src).
 n is in bytes.
****************************************************************************/

smb_ucs2_t *strncpyn_w(smb_ucs2_t *dest, const smb_ucs2_t *src,size_t n, smb_ucs2_t c)
{
	smb_ucs2_t *p;
	size_t str_len;

	p = strchr_w(src, c);
	if (p == NULL) {
		fstring cval;
		smb_ucs2_t mbcval[2];
		mbcval[0] = c;
		mbcval[1] = 0;
		DEBUG(5, ("strncpyn_w: separator character (%s) not found\n",
			unicode_to_unix(cval,mbcval,sizeof(cval)) ));
		return NULL;
	}

	str_len = PTR_DIFF(p, src) + sizeof(smb_ucs2_t);
	safe_strcpy_w(dest, src, MIN(n, str_len));

	return p;
}

/*************************************************************
 Routine to get hex characters and turn them into a 16 byte array.
 The array can be variable length, and any non-hex-numeric
 characters are skipped.  "0xnn" or "0Xnn" is specially catered
 for. len is in bytes.
 Valid examples: "0A5D15"; "0x15, 0x49, 0xa2"; "59\ta9\te3\n"
**************************************************************/

static smb_ucs2_t hexprefix[] = { (smb_ucs2_t)'0', (smb_ucs2_t)'x', 0 };
static smb_ucs2_t hexchars[] = { (smb_ucs2_t)'0', (smb_ucs2_t)'1', (smb_ucs2_t)'2', (smb_ucs2_t)'3',
								(smb_ucs2_t)'4', (smb_ucs2_t)'5', (smb_ucs2_t)'6', (smb_ucs2_t)'7',
								(smb_ucs2_t)'8', (smb_ucs2_t)'9', (smb_ucs2_t)'A', (smb_ucs2_t)'B',
								(smb_ucs2_t)'C', (smb_ucs2_t)'D', (smb_ucs2_t)'E', (smb_ucs2_t)'F', 0 };

size_t strhex_to_str_w(char *p, size_t len, const smb_ucs2_t *strhex)
{
	size_t i;
	size_t num_chars = 0;
	unsigned char   lonybble, hinybble;
	smb_ucs2_t *p1 = NULL, *p2 = NULL;

	/*
	 * Convert to smb_ucs2_t units.
	 */

	len /= sizeof(smb_ucs2_t);

	for (i = 0; i < len && strhex[i] != 0; i++) {
		if (strnequal_w(hexchars, hexprefix, 2)) {
			i++; /* skip two chars */
			continue;
		}

		if (!(p1 = strchr_w(hexchars, toupper_w(strhex[i]))))
			break;

		i++; /* next hex digit */

		if (!(p2 = strchr_w(hexchars, toupper_w(strhex[i]))))
			break;

		/* get the two nybbles */
		hinybble = (PTR_DIFF(p1, hexchars)/sizeof(smb_ucs2_t));
		lonybble = (PTR_DIFF(p2, hexchars)/sizeof(smb_ucs2_t));

		p[num_chars] = (hinybble << 4) | lonybble;
		num_chars++;

		p1 = NULL;
		p2 = NULL;
	}
	return num_chars;
}

/****************************************************************************
 Check if a string is part of a list.
****************************************************************************/

BOOL in_list_w(smb_ucs2_t *s,smb_ucs2_t *list,BOOL casesensitive)
{
	wpstring tok;
	smb_ucs2_t *p=list;

	if (!list)
		return(False);

	while (next_token_w(&p,tok,LIST_SEP_W,sizeof(tok))) {
		if (casesensitive) {
			if (strcmp_w(tok,s) == 0)
				return(True);
		} else {
			if (StrCaseCmp_w(tok,s) == 0)
				return(True);
		}
	}
	return(False);
}

/* This is used to prevent lots of mallocs of size 2 */
static smb_ucs2_t *null_string = NULL;

/****************************************************************************
 Set a string value, allocing the space for the string.
****************************************************************************/

BOOL string_init_w(smb_ucs2_t **dest,const smb_ucs2_t *src)
{
	size_t l;

	if (!null_string) {
		if((null_string = (smb_ucs2_t *)malloc(sizeof(smb_ucs2_t))) == NULL) {
			DEBUG(0,("string_init_w: malloc fail for null_string.\n"));
		return False;
		}
		*null_string = 0;
	}

	if (!src)     
		src = null_string;

	l = strlen_w(src);

	if (l == 0)
		*dest = null_string;
	else {
		(*dest) = (smb_ucs2_t *)malloc(sizeof(smb_ucs2_t)*(l+1));
		if ((*dest) == NULL) {
			DEBUG(0,("Out of memory in string_init_w\n"));
			return False;
		}

		wpstrcpy(*dest,src);
	}
	return(True);
}

/****************************************************************************
 Free a string value.
****************************************************************************/

void string_free_w(smb_ucs2_t **s)
{
	if (!s || !(*s))
		return;
	if (*s == null_string)
		*s = NULL;
	if (*s)
		free((char *)*s);
	*s = NULL;
}

/****************************************************************************
 Set a string value, allocing the space for the string, and deallocating any 
 existing space.
****************************************************************************/

BOOL string_set_w(smb_ucs2_t **dest,const smb_ucs2_t *src)
{
	string_free_w(dest);

	return(string_init_w(dest,src));
}

/****************************************************************************
 Substitute a string for a pattern in another string. Make sure there is 
 enough room !

 This routine looks for pattern in s and replaces it with 
 insert. It may do multiple replacements.

 Any of " ; ' $ or ` in the insert string are replaced with _
 if len==0 then no length check is performed
 len is in bytes.
****************************************************************************/

void string_sub_w(smb_ucs2_t *s,const smb_ucs2_t *pattern,const smb_ucs2_t *insert, size_t len)
{
	smb_ucs2_t *p;
	ssize_t ls,lp,li, i;

	/*
	 * Convert to smb_ucs2_t units.
	 */

	len /= sizeof(smb_ucs2_t);

	if (!insert || !pattern || !s)
		return;

	ls = (ssize_t)strlen_w(s);
	lp = (ssize_t)strlen_w(pattern);
	li = (ssize_t)strlen_w(insert);

	if (!*pattern)
		return;
	
	while (lp <= ls && (p = strstr_w(s,pattern))) {
		if (len && (ls + (li-lp) >= len)) {
			fstring out;
			DEBUG(0,("ERROR: string overflow by %d in string_sub_w(%.50s, %d)\n", 
				 (int)(sizeof(smb_ucs2_t)*(ls + (li-lp) - len)),
				 unicode_to_unix(out,pattern,sizeof(out)), (int)len*sizeof(smb_ucs2_t)));
			break;
		}
		if (li != lp)
			memmove(p+li,p+lp,sizeof(smb_ucs2_t)*(strlen_w(p+lp)+1));

		for (i=0;i<li;i++) {
			switch (insert[i]) {
			case (smb_ucs2_t)'`':
			case (smb_ucs2_t)'"':
			case (smb_ucs2_t)'\'':
			case (smb_ucs2_t)';':
			case (smb_ucs2_t)'$':
			case (smb_ucs2_t)'%':
			case (smb_ucs2_t)'\r':
			case (smb_ucs2_t)'\n':
				p[i] = (smb_ucs2_t)'_';
				break;
			default:
				p[i] = insert[i];
			}
		}
		s = p + li;
		ls += (li-lp);
	}
}

void fstring_sub_w(smb_ucs2_t *s,const smb_ucs2_t *pattern,const smb_ucs2_t *insert)
{
	string_sub_w(s, pattern, insert, sizeof(wfstring));
}

void pstring_sub_w(smb_ucs2_t *s,const smb_ucs2_t *pattern,smb_ucs2_t *insert)
{
	string_sub_w(s, pattern, insert, sizeof(wpstring));
}

/****************************************************************************
 Similar to string_sub() but allows for any character to be substituted. 
 Use with caution !
 if len==0 then no length check is performed.
****************************************************************************/

void all_string_sub_w(smb_ucs2_t *s,const smb_ucs2_t *pattern,const smb_ucs2_t *insert, size_t len)
{
	smb_ucs2_t *p;
	ssize_t ls,lp,li;

	/*
	 * Convert to smb_ucs2_t units.
	 */

	len /= sizeof(smb_ucs2_t);

	if (!insert || !pattern || !s)
		return;

	ls = (ssize_t)strlen_w(s);
	lp = (ssize_t)strlen_w(pattern);
	li = (ssize_t)strlen_w(insert);

	if (!*pattern)
		return;
	
	while (lp <= ls && (p = strstr_w(s,pattern))) {
		if (len && (ls + (li-lp) >= len)) {
			fstring out;
			DEBUG(0,("ERROR: string overflow by %d in all_string_sub_w(%.50s, %d)\n", 
				 (int)(sizeof(smb_ucs2_t)*(ls + (li-lp) - len)),
				 unicode_to_unix(out,pattern,sizeof(out)), (int)len*sizeof(smb_ucs2_t)));
			break;
		}
		if (li != lp)
			memmove(p+li,p+lp,sizeof(smb_ucs2_t)*(strlen_w(p+lp)+1));

		memcpy(p, insert, li*sizeof(smb_ucs2_t));
		s = p + li;
		ls += (li-lp);
	}
}

/****************************************************************************
 Splits out the front and back at a separator.
****************************************************************************/

void split_at_last_component_w(smb_ucs2_t *path, smb_ucs2_t *front, smb_ucs2_t sep, smb_ucs2_t *back)
{
    smb_ucs2_t *p = strrchr_w(path, sep);

	if (p != NULL)
		*p = 0;

	if (front != NULL)
		wpstrcpy(front, path);

	if (p != NULL) {
		if (back != NULL)
			wpstrcpy(back, p+1);
		*p = (smb_ucs2_t)'\\';
	} else {
		if (back != NULL)
			back[0] = 0;
	}
}


/****************************************************************************
 Write an octal as a string.
****************************************************************************/

smb_ucs2_t *octal_string_w(int i)
{
	static smb_ucs2_t wret[64];
	char ret[64];

	if (i == -1)
		slprintf(ret, sizeof(ret), "-1");
	else 
		slprintf(ret, sizeof(ret), "0%o", i);
	return unix_to_unicode(wret, ret, sizeof(wret));
}


/****************************************************************************
 Truncate a string at a specified length.
 length is in bytes.
****************************************************************************/

smb_ucs2_t *string_truncate_w(smb_ucs2_t *s, size_t length)
{
	/*
	 * Convert to smb_ucs2_t units.
	 */

	length /= sizeof(smb_ucs2_t);

	if (s && strlen_w(s) > length)
		s[length] = 0;

	return s;
}
