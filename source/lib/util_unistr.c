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
		size_t skip = skip_multibyte_char(*src);
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
			size_t skip = skip_multibyte_char(*src);
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
 free any existing maps
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
