/* 
   Unix SMB/CIFS implementation.
   minimal iconv implementation
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Jelmer Vernooij 2002
   
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
 * @brief Samba wrapper/stub for iconv character set conversion.
 *
 * iconv is the XPG2 interface for converting between character
 * encodings.  This file provides a Samba wrapper around it, and also
 * a simple reimplementation that is used if the system does not
 * implement iconv.
 *
 * Samba only works with encodings that are supersets of ASCII: ascii
 * characters like whitespace can be tested for directly, multibyte
 * sequences start with a byte with the high bit set, and strings are
 * terminated by a nul byte.
 *
 * Note that the only function provided by iconv is conversion between
 * characters.  It doesn't directly support operations like
 * uppercasing or comparison.  We have to convert to UCS-2 and compare
 * there.
 *
 * @sa Samba Developers Guide
 **/

static size_t ascii_pull  (void *,const char **, size_t *, char **, size_t *);
static size_t ascii_push  (void *,const char **, size_t *, char **, size_t *);
static size_t utf8_pull   (void *,const char **, size_t *, char **, size_t *);
static size_t utf8_push   (void *,const char **, size_t *, char **, size_t *);
static size_t ucs2hex_pull(void *,const char **, size_t *, char **, size_t *);
static size_t ucs2hex_push(void *,const char **, size_t *, char **, size_t *);
static size_t iconv_copy  (void *,const char **, size_t *, char **, size_t *);
static size_t iconv_swab  (void *,const char **, size_t *, char **, size_t *);

static struct charset_functions builtin_functions[] = {
	{"UCS-2LE",  iconv_copy, iconv_copy},
	{"UCS-2BE",  iconv_swab, iconv_swab},
	{"UTF8",   utf8_pull,  utf8_push},
	{"ASCII", ascii_pull, ascii_push},
	{"UCS2-HEX", ucs2hex_pull, ucs2hex_push},
	{NULL, NULL, NULL}
};

static struct charset_functions *charsets = NULL;

static NTSTATUS charset_register_backend(void *_funcs) 
{
	struct charset_functions *funcs = (struct charset_functions *)_funcs;
	struct charset_functions *c = charsets;

	DEBUG(5, ("Attempting to register new charset %s\n", funcs->name));
	/* Check whether we already have this charset... */
	while(c) {
		if(!strcasecmp(c->name, funcs->name)){ 
			DEBUG(2, ("Duplicate charset %s, not registering\n", funcs->name));
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}
		c = c->next;
	}

	funcs->next = funcs->prev = NULL;
	DEBUG(5, ("Registered charset %s\n", funcs->name));
	DLIST_ADD(charsets, funcs);
	return NT_STATUS_OK;
}

static void lazy_initialize_iconv(void)
{
	static BOOL initialized = False;
	int i;

	if (!initialized) {
		initialized = True;
		register_subsystem("charset", charset_register_backend);
		
		for(i = 0; builtin_functions[i].name; i++) 
			register_backend("charset", &builtin_functions[i]);
	}
}

#ifdef HAVE_NATIVE_ICONV
/* if there was an error then reset the internal state,
   this ensures that we don't have a shift state remaining for
   character sets like SJIS */
static size_t sys_iconv(void *cd, 
			const char **inbuf, size_t *inbytesleft,
			char **outbuf, size_t *outbytesleft)
{
	size_t ret = iconv((iconv_t)cd, 
			   inbuf, inbytesleft, 
			   outbuf, outbytesleft);
	if (ret == (size_t)-1) iconv(cd, NULL, NULL, NULL, NULL);
	return ret;
}
#endif

/**
 * This is a simple portable iconv() implementaion.
 *
 * It only knows about a very small number of character sets - just
 * enough that Samba works on systems that don't have iconv.
 **/
size_t smb_iconv(smb_iconv_t cd, 
		 const char **inbuf, size_t *inbytesleft,
		 char **outbuf, size_t *outbytesleft)
{
	char cvtbuf[2048];
	char *bufp = cvtbuf;
	size_t bufsize;

	/* in many cases we can go direct */
	if (cd->direct) {
		return cd->direct(cd->cd_direct, 
				  inbuf, inbytesleft, outbuf, outbytesleft);
	}


	/* otherwise we have to do it chunks at a time */
	while (*inbytesleft > 0) {
		bufp = cvtbuf;
		bufsize = sizeof(cvtbuf);
		
		if (cd->pull(cd->cd_pull, 
			     inbuf, inbytesleft, &bufp, &bufsize) == -1
		    && errno != E2BIG) return -1;

		bufp = cvtbuf;
		bufsize = sizeof(cvtbuf) - bufsize;

		if (cd->push(cd->cd_push, 
			     &bufp, &bufsize, 
			     outbuf, outbytesleft) == -1) return -1;
	}

	return 0;
}

/*
  simple iconv_open() wrapper
 */
smb_iconv_t smb_iconv_open(const char *tocode, const char *fromcode)
{
	smb_iconv_t ret;
	struct charset_functions *from, *to;
	
	lazy_initialize_iconv();
	from = charsets;
	to = charsets;

	ret = (smb_iconv_t)malloc(sizeof(*ret));
	if (!ret) {
		errno = ENOMEM;
		return (smb_iconv_t)-1;
	}
	memset(ret, 0, sizeof(*ret));

	ret->from_name = strdup(fromcode);
	ret->to_name = strdup(tocode);

	/* check for the simplest null conversion */
	if (strcmp(fromcode, tocode) == 0) {
		ret->direct = iconv_copy;
		return ret;
	}

	while (from) {
		if (strcasecmp(from->name, fromcode) == 0) break;
		from = from->next;
	}

	while (to) {
		if (strcasecmp(to->name, tocode) == 0) break;
		to = to->next;
	}

#ifdef HAVE_NATIVE_ICONV
	if (!from) {
		ret->pull = sys_iconv;
		ret->cd_pull = iconv_open("UCS-2LE", fromcode);
		if (ret->cd_pull == (iconv_t)-1) goto failed;
	}

	if (!to) {
		ret->push = sys_iconv;
		ret->cd_push = iconv_open(tocode, "UCS-2LE");
		if (ret->cd_push == (iconv_t)-1) goto failed;
	}
#else
	if (!from || !to) {
		goto failed;
	}
#endif

	/* check for conversion to/from ucs2 */
	if (strcasecmp(fromcode, "UCS-2LE") == 0 && to) {
		ret->direct = to->push;
		return ret;
	}
	if (strcasecmp(tocode, "UCS-2LE") == 0 && from) {
		ret->direct = from->pull;
		return ret;
	}

#ifdef HAVE_NATIVE_ICONV
	if (strcasecmp(fromcode, "UCS-2LE") == 0) {
		ret->direct = sys_iconv;
		ret->cd_direct = ret->cd_push;
		ret->cd_push = NULL;
		return ret;
	}
	if (strcasecmp(tocode, "UCS-2LE") == 0) {
		ret->direct = sys_iconv;
		ret->cd_direct = ret->cd_pull;
		ret->cd_pull = NULL;
		return ret;
	}
#endif

	/* the general case has to go via a buffer */
	if (!ret->pull) ret->pull = from->pull;
	if (!ret->push) ret->push = to->push;
	return ret;

failed:
	SAFE_FREE(ret);
	errno = EINVAL;
	return (smb_iconv_t)-1;
}

/*
  simple iconv_close() wrapper
*/
int smb_iconv_close (smb_iconv_t cd)
{
#ifdef HAVE_NATIVE_ICONV
	if (cd->cd_direct) iconv_close((iconv_t)cd->cd_direct);
	if (cd->cd_pull) iconv_close((iconv_t)cd->cd_pull);
	if (cd->cd_push) iconv_close((iconv_t)cd->cd_push);
#endif

	SAFE_FREE(cd->from_name);
	SAFE_FREE(cd->to_name);

	memset(cd, 0, sizeof(*cd));
	SAFE_FREE(cd);
	return 0;
}


/**********************************************************************
 the following functions implement the builtin character sets in Samba
 and also the "test" character sets that are designed to test
 multi-byte character set support for english users
***********************************************************************/
static size_t ascii_pull(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	while (*inbytesleft >= 1 && *outbytesleft >= 2) {
		(*outbuf)[0] = (*inbuf)[0];
		(*outbuf)[1] = 0;
		(*inbytesleft)  -= 1;
		(*outbytesleft) -= 2;
		(*inbuf)  += 1;
		(*outbuf) += 2;
	}

	if (*inbytesleft > 0) {
		errno = E2BIG;
		return -1;
	}
	
	return 0;
}

static size_t ascii_push(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	int ir_count=0;

	while (*inbytesleft >= 2 && *outbytesleft >= 1) {
		(*outbuf)[0] = (*inbuf)[0] & 0x7F;
		if ((*inbuf)[1]) ir_count++;
		(*inbytesleft)  -= 2;
		(*outbytesleft) -= 1;
		(*inbuf)  += 2;
		(*outbuf) += 1;
	}

	if (*inbytesleft == 1) {
		errno = EINVAL;
		return -1;
	}

	if (*inbytesleft > 1) {
		errno = E2BIG;
		return -1;
	}
	
	return ir_count;
}


static size_t ucs2hex_pull(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	while (*inbytesleft >= 1 && *outbytesleft >= 2) {
		unsigned v;

		if ((*inbuf)[0] != '@') {
			/* seven bit ascii case */
			(*outbuf)[0] = (*inbuf)[0];
			(*outbuf)[1] = 0;
			(*inbytesleft)  -= 1;
			(*outbytesleft) -= 2;
			(*inbuf)  += 1;
			(*outbuf) += 2;
			continue;
		}
		/* it's a hex character */
		if (*inbytesleft < 5) {
			errno = EINVAL;
			return -1;
		}
		
		if (sscanf(&(*inbuf)[1], "%04x", &v) != 1) {
			errno = EILSEQ;
			return -1;
		}

		(*outbuf)[0] = v&0xff;
		(*outbuf)[1] = v>>8;
		(*inbytesleft)  -= 5;
		(*outbytesleft) -= 2;
		(*inbuf)  += 5;
		(*outbuf) += 2;
	}

	if (*inbytesleft > 0) {
		errno = E2BIG;
		return -1;
	}
	
	return 0;
}

static size_t ucs2hex_push(void *cd, const char **inbuf, size_t *inbytesleft,
			   char **outbuf, size_t *outbytesleft)
{
	while (*inbytesleft >= 2 && *outbytesleft >= 1) {
		char buf[6];

		if ((*inbuf)[1] == 0 && 
		    ((*inbuf)[0] & 0x80) == 0 &&
		    (*inbuf)[0] != '@') {
			(*outbuf)[0] = (*inbuf)[0];
			(*inbytesleft)  -= 2;
			(*outbytesleft) -= 1;
			(*inbuf)  += 2;
			(*outbuf) += 1;
			continue;
		}
		if (*outbytesleft < 5) {
			errno = E2BIG;
			return -1;
		}
		snprintf(buf, 6, "@%04x", SVAL(*inbuf, 0));
		memcpy(*outbuf, buf, 5);
		(*inbytesleft)  -= 2;
		(*outbytesleft) -= 5;
		(*inbuf)  += 2;
		(*outbuf) += 5;
	}

	if (*inbytesleft == 1) {
		errno = EINVAL;
		return -1;
	}

	if (*inbytesleft > 1) {
		errno = E2BIG;
		return -1;
	}
	
	return 0;
}

static size_t iconv_swab(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	int n;

	n = MIN(*inbytesleft, *outbytesleft);

	swab(*inbuf, *outbuf, (n&~1));
	if (n&1) {
		(*outbuf)[n-1] = 0;
	}

	(*inbytesleft) -= n;
	(*outbytesleft) -= n;
	(*inbuf) += n;
	(*outbuf) += n;

	if (*inbytesleft > 0) {
		errno = E2BIG;
		return -1;
	}

	return 0;
}


static size_t iconv_copy(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	int n;

	n = MIN(*inbytesleft, *outbytesleft);

	memmove(*outbuf, *inbuf, n);

	(*inbytesleft) -= n;
	(*outbytesleft) -= n;
	(*inbuf) += n;
	(*outbuf) += n;

	if (*inbytesleft > 0) {
		errno = E2BIG;
		return -1;
	}

	return 0;
}

static size_t utf8_pull(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	while (*inbytesleft >= 1 && *outbytesleft >= 2) {
		const uint8_t *c = (const uint8_t *)*inbuf;
		uint8_t *uc = (uint8_t *)*outbuf;
		int len = 1;

		if ((c[0] & 0x80) == 0) {
			uc[0] = c[0];
			uc[1] = 0;
		} else if ((c[0] & 0xf0) == 0xe0) {
			if (*inbytesleft < 3) {
				DEBUG(0,("short utf8 char\n"));
				goto badseq;
			}
			uc[1] = ((c[0]&0xF)<<4) | ((c[1]>>2)&0xF);
			uc[0] = (c[1]<<6) | (c[2]&0x3f);
			len = 3;
		} else if ((c[0] & 0xe0) == 0xc0) {
			if (*inbytesleft < 2) {
				DEBUG(0,("short utf8 char\n"));
				goto badseq;
			}
			uc[1] = (c[0]>>2) & 0x7;
			uc[0] = (c[0]<<6) | (c[1]&0x3f);
			len = 2;
		}

		(*inbuf)  += len;
		(*inbytesleft)  -= len;
		(*outbytesleft) -= 2;
		(*outbuf) += 2;
	}

	if (*inbytesleft > 0) {
		errno = E2BIG;
		return -1;
	}
	
	return 0;

badseq:
	errno = EINVAL;
	return -1;
}

static size_t utf8_push(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	while (*inbytesleft >= 2 && *outbytesleft >= 1) {
		uint8_t *c = (uint8_t *)*outbuf;
		const uint8_t *uc = (const uint8_t *)*inbuf;
		int len=1;

		if (uc[1] & 0xf8) {
			if (*outbytesleft < 3) {
				DEBUG(0,("short utf8 write\n"));
				goto toobig;
			}
			c[0] = 0xe0 | (uc[1]>>4);
			c[1] = 0x80 | ((uc[1]&0xF)<<2) | (uc[0]>>6);
			c[2] = 0x80 | (uc[0]&0x3f);
			len = 3;
		} else if (uc[1] | (uc[0] & 0x80)) {
			if (*outbytesleft < 2) {
				DEBUG(0,("short utf8 write\n"));
				goto toobig;
			}
			c[0] = 0xc0 | (uc[1]<<2) | (uc[0]>>6);
			c[1] = 0x80 | (uc[0]&0x3f);
			len = 2;
		} else {
			c[0] = uc[0];
		}


		(*inbytesleft)  -= 2;
		(*outbytesleft) -= len;
		(*inbuf)  += 2;
		(*outbuf) += len;
	}

	if (*inbytesleft == 1) {
		errno = EINVAL;
		return -1;
	}

	if (*inbytesleft > 1) {
		errno = E2BIG;
		return -1;
	}
	
	return 0;

toobig:
	errno = E2BIG;
	return -1;
}

