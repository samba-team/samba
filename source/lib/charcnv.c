/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Character set conversion Extensions
   Copyright (C) Igor Vergeichik <iverg@mail.ru> 2001
   Copyright (C) Andrew Tridgell 2001
   
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

static pstring cvtbuf;

static smb_iconv_t 
	ucs2_to_unix=(smb_iconv_t)-1, /*ucs2 (MS) <-> unix format */  
      	unix_to_ucs2=(smb_iconv_t)-1,		
      	dos_to_unix=(smb_iconv_t)-1, /*unix format <-> dos codepage*/
      	unix_to_dos=(smb_iconv_t)-1;  /*for those clients who does not support unicode*/

	
/****************************************************************************
 Initialize iconv conversion descriptors 
****************************************************************************/
void init_iconv(char *unix_charset, char *dos_charset)
{
#define ICONV(descr, from_name, to_name)\
	if(descr!=(smb_iconv_t)-1) smb_iconv_close(descr);\
	  descr = smb_iconv_open(to_name, from_name);\
	  if(descr==(smb_iconv_t)-1)\
		DEBUG(0,("Conversion from %s to %s is not supported\n",from_name,to_name));

	if (!unix_charset || !*unix_charset) unix_charset = "ASCII";
	if (!dos_charset || !*dos_charset) dos_charset = "ASCII";
	
	ICONV(ucs2_to_unix, "UCS2", unix_charset)
	ICONV(unix_to_ucs2, unix_charset, "UCS2")
	ICONV(dos_to_unix, dos_charset, unix_charset)
	ICONV(unix_to_dos, unix_charset, dos_charset)

#undef ICONV	
}

/****************************************************************************
 Convert string from one encoding to another, makeing error checking etc
 Parameters:
	descriptor - conversion descriptor, created in init_iconv
 	src - pointer to source string (multibute or singlebyte)
	srclen - length of the source string in bytes
	dest - pointer to destination string (multibyte or singlebyte)
	destlen - maximal length allowed for string
return the number of bytes occupied in the destination
****************************************************************************/
static size_t convert_string(smb_iconv_t descriptor, 
			     void const *src, size_t srclen, 
			     void *dest, size_t destlen)
{
	size_t i_len, o_len;
	size_t retval;
	char* inbuf = (char*)src;
	char* outbuf = (char*)dest;

	if (descriptor == (smb_iconv_t)-1) {
		/* conversion not supported, use as is */
		int len = MIN(srclen,destlen);
		memcpy(dest,src,len);
		return len;
	}

	i_len=srclen;
	o_len=destlen;
	retval=smb_iconv(descriptor,&inbuf, &i_len, &outbuf, &o_len);
	if(retval==-1) 		
	{    	char *reason="unknown error";
		switch(errno)
		{ case EINVAL: reason="Incomplete multybyte sequence"; break;
		  case E2BIG:  reason="No more room"; 
		   	       DEBUG(0, ("Required %d, available %d\n",
			       srclen, destlen));	
		               break;
		  case EILSEQ: reason="Illegal myltybyte sequence"; break;
		}
		DEBUG(0,("Conversion error:%s(%s)\n",reason,inbuf));
		/* smb_panic(reason); */
	}
	return destlen-o_len;
}

int unix_strupper(const char *src, size_t srclen, char *dest, size_t destlen)
{
	int size,len;
	smb_ucs2_t *buffer=(smb_ucs2_t*)cvtbuf;
	size=convert_string(unix_to_ucs2, src, srclen, buffer, sizeof(cvtbuf));
	len=size/2;
	strupper_w(buffer);
	return convert_string(ucs2_to_unix, buffer, size, dest, destlen);
}

int unix_strlower(const char *src, size_t srclen, char *dest, size_t destlen)
{
	int size,len;
	smb_ucs2_t *buffer=(smb_ucs2_t*)cvtbuf;
	size=convert_string(unix_to_ucs2, src, srclen, buffer, sizeof(cvtbuf));
	len=size/2;
	strlower_w(buffer);
	return convert_string(ucs2_to_unix, buffer, size, dest, destlen);
}


int ucs2_align(const void *base_ptr, const void *p, int flags)
{
	if (flags & (STR_NOALIGN|STR_ASCII)) return 0;
	return PTR_DIFF(p, base_ptr) & 1;
}


/****************************************************************************
copy a string from a char* unix src to a dos codepage string destination
return the number of bytes occupied by the string in the destination
flags can have:
  STR_TERMINATE means include the null termination
  STR_UPPER     means uppercase in the destination
dest_len is the maximum length allowed in the destination. If dest_len
is -1 then no maxiumum is used
****************************************************************************/
int push_ascii(void *dest, const char *src, int dest_len, int flags)
{
	int src_len = strlen(src);
	pstring tmpbuf;

	/* treat a pstring as "unlimited" length */
	if (dest_len == -1) {
		dest_len = sizeof(pstring);
	}

	if (flags & STR_UPPER) {
		pstrcpy(tmpbuf, src);
		strupper(tmpbuf);
		src = tmpbuf;
	}

	if (flags & STR_TERMINATE) {
		src_len++;
	}

	return convert_string(unix_to_dos, src, src_len, dest, dest_len);
}

int push_ascii_fstring(void *dest, const char *src)
{
	return push_ascii(dest, src, sizeof(fstring), STR_TERMINATE);
}

int push_ascii_pstring(void *dest, const char *src)
{
	return push_ascii(dest, src, sizeof(pstring), STR_TERMINATE);
}

int push_pstring(void *dest, const char *src)
{
	return push_ascii(dest, src, sizeof(pstring), STR_TERMINATE);
}


/****************************************************************************
copy a string from a dos codepage source to a unix char* destination
flags can have:
  STR_TERMINATE means the string in src is null terminated
if STR_TERMINATE is set then src_len is ignored
src_len is the length of the source area in bytes
return the number of bytes occupied by the string in src
the resulting string in "dest" is always null terminated
****************************************************************************/
int pull_ascii(char *dest, const void *src, int dest_len, int src_len, int flags)
{
	int ret;

	if (dest_len == -1) {
		dest_len = sizeof(pstring);
	}

	if (flags & STR_TERMINATE) src_len = strlen(src)+1;

	ret = convert_string(dos_to_unix, src, src_len, dest, dest_len);

	if (dest_len) dest[MIN(ret, dest_len-1)] = 0;

	return src_len;
}

int pull_ascii_pstring(char *dest, const void *src)
{
	return pull_ascii(dest, src, sizeof(pstring), -1, STR_TERMINATE);
}

int pull_ascii_fstring(char *dest, const void *src)
{
	return pull_ascii(dest, src, sizeof(fstring), -1, STR_TERMINATE);
}

/****************************************************************************
copy a string from a char* src to a unicode destination
return the number of bytes occupied by the string in the destination
flags can have:
  STR_TERMINATE means include the null termination
  STR_UPPER     means uppercase in the destination
  STR_NOALIGN   means don't do alignment
dest_len is the maximum length allowed in the destination. If dest_len
is -1 then no maxiumum is used
****************************************************************************/
int push_ucs2(const void *base_ptr, void *dest, const char *src, int dest_len, int flags)
{
	int len=0;
	int src_len = strlen(src);
	pstring tmpbuf;

	/* treat a pstring as "unlimited" length */
	if (dest_len == -1) {
		dest_len = sizeof(pstring);
	}

	if (flags & STR_UPPER) {
		pstrcpy(tmpbuf, src);
		strupper(tmpbuf);
		src = tmpbuf;
	}

	if (flags & STR_TERMINATE) {
		src_len++;
	}

	if (ucs2_align(base_ptr, dest, flags)) {
		*(char *)dest = 0;
		dest = (void *)((char *)dest + 1);
		if (dest_len) dest_len--;
		len++;
	}

	len += convert_string(unix_to_ucs2, src, src_len, dest, dest_len);
	return len;
}


/****************************************************************************
copy a string from a ucs2 source to a unix char* destination
flags can have:
  STR_TERMINATE means the string in src is null terminated
  STR_NOALIGN   means don't try to align
if STR_TERMINATE is set then src_len is ignored
src_len is the length of the source area in bytes
return the number of bytes occupied by the string in src
the resulting string in "dest" is always null terminated
****************************************************************************/
int pull_ucs2(const void *base_ptr, char *dest, const void *src, int dest_len, int src_len, int flags)
{
	int ret;

	if (dest_len == -1) {
		dest_len = sizeof(pstring);
	}

	if (ucs2_align(base_ptr, src, flags)) {
		src = (const void *)((const char *)src + 1);
		if (src_len > 0) src_len--;
	}

	if (flags & STR_TERMINATE) src_len = strlen_w(src)*2+2;

	ret = convert_string(ucs2_to_unix, src, src_len, dest, dest_len);
	if (dest_len) dest[MIN(ret, dest_len-1)] = 0;

	return src_len;
}

int pull_ucs2_pstring(char *dest, const void *src)
{
	return pull_ucs2(NULL, dest, src, sizeof(pstring), -1, STR_TERMINATE);
}

int pull_ucs2_fstring(char *dest, const void *src)
{
	return pull_ucs2(NULL, dest, src, sizeof(fstring), -1, STR_TERMINATE);
}


/****************************************************************************
copy a string from a char* src to a unicode or ascii
dos code page destination choosing unicode or ascii based on the 
flags in the SMB buffer starting at base_ptr
return the number of bytes occupied by the string in the destination
flags can have:
  STR_TERMINATE means include the null termination
  STR_UPPER     means uppercase in the destination
  STR_ASCII     use ascii even with unicode packet
  STR_NOALIGN   means don't do alignment
dest_len is the maximum length allowed in the destination. If dest_len
is -1 then no maxiumum is used
****************************************************************************/
int push_string(const void *base_ptr, void *dest, const char *src, int dest_len, int flags)
{
	if (!(flags & STR_ASCII) && \
	    ((flags & STR_UNICODE || \
	      (SVAL(base_ptr, smb_flg2) & FLAGS2_UNICODE_STRINGS)))) {
		return push_ucs2(base_ptr, dest, src, dest_len, flags);
	}
	return push_ascii(dest, src, dest_len, flags);
}


/****************************************************************************
copy a string from a unicode or ascii source (depending on
the packet flags) to a char* destination
flags can have:
  STR_TERMINATE means the string in src is null terminated
  STR_UNICODE   means to force as unicode
  STR_ASCII     use ascii even with unicode packet
  STR_NOALIGN   means don't do alignment
if STR_TERMINATE is set then src_len is ignored
src_len is the length of the source area in bytes
return the number of bytes occupied by the string in src
the resulting string in "dest" is always null terminated
****************************************************************************/
int pull_string(const void *base_ptr, char *dest, const void *src, int dest_len, int src_len, 
		int flags)
{
	if (!(flags & STR_ASCII) && \
	    ((flags & STR_UNICODE || \
	      (SVAL(base_ptr, smb_flg2) & FLAGS2_UNICODE_STRINGS)))) {
		return pull_ucs2(base_ptr, dest, src, dest_len, src_len, flags);
	}
	return pull_ascii(dest, src, dest_len, src_len, flags);
}

int align_string(const void *base_ptr, const char *p, int flags)
{
	if (!(flags & STR_ASCII) && \
	    ((flags & STR_UNICODE || \
	      (SVAL(base_ptr, smb_flg2) & FLAGS2_UNICODE_STRINGS)))) {
		return ucs2_align(base_ptr, p, flags);
	}
	return 0;
}
