/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   minimal iconv implementation
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

static size_t ascii_pull(void *,char **, size_t *, char **, size_t *);
static size_t ascii_push(void *,char **, size_t *, char **, size_t *);
static size_t  utf8_pull(void *,char **, size_t *, char **, size_t *);
static size_t  utf8_push(void *,char **, size_t *, char **, size_t *);
static size_t weird_pull(void *,char **, size_t *, char **, size_t *);
static size_t weird_push(void *,char **, size_t *, char **, size_t *);
static size_t ucs2hex_pull(void *,char **, size_t *, char **, size_t *);
static size_t ucs2hex_push(void *,char **, size_t *, char **, size_t *);
static size_t iconv_copy(void *,char **, size_t *, char **, size_t *);

/*
  for each charset we have a function that pulls from that charset to 
  a ucs2 buffer, and a function that pushes to a ucs2 buffer 
*/
static struct {
	char *name;
	size_t (*pull)(void *, char **inbuf, size_t *inbytesleft,
		       char **outbuf, size_t *outbytesleft);
	size_t (*push)(void *, char **inbuf, size_t *inbytesleft,
		       char **outbuf, size_t *outbytesleft);
} charsets[] = {
	{"UCS-2LE",  iconv_copy, iconv_copy},
	{"UTF8",   utf8_pull,  utf8_push},
	{"ASCII", ascii_pull, ascii_push},
	{"WEIRD", weird_pull, weird_push},
	{"UCS2-HEX", ucs2hex_pull, ucs2hex_push},
	{NULL, NULL, NULL}
};


/* if there was an error then reset the internal state,
   this ensures that we don't have a shift state remaining for
   character sets like SJIS */
static size_t sys_iconv(void *cd, 
			char **inbuf, size_t *inbytesleft,
			char **outbuf, size_t *outbytesleft)
{
#ifdef HAVE_NATIVE_ICONV
	size_t ret = iconv((iconv_t)cd, 
			   inbuf, inbytesleft, 
			   outbuf, outbytesleft);
	if (ret == (size_t)-1) iconv(cd, NULL, NULL, NULL, NULL);
	return ret;
#else
	errno = EINVAL;
	return -1;
#endif
}

/*
  this is a simple portable iconv() implementaion. It only knows about
  a very small number of character sets - just enough that Samba works
  on systems that don't have iconv
 */
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
				  (char **)inbuf, inbytesleft, outbuf, outbytesleft);
	}


	/* otherwise we have to do it chunks at a time */
	while (*inbytesleft > 0) {
		bufp = cvtbuf;
		bufsize = sizeof(cvtbuf);
		
		if (cd->pull(cd->cd_pull, 
			     (char **)inbuf, inbytesleft, &bufp, &bufsize) == -1
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
	int from, to;

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

	for (from=0; charsets[from].name; from++) {
		if (strcasecmp(charsets[from].name, fromcode) == 0) break;
	}
	for (to=0; charsets[to].name; to++) {
		if (strcasecmp(charsets[to].name, tocode) == 0) break;
	}

#ifdef HAVE_NATIVE_ICONV
	if (!charsets[from].name) {
		ret->pull = sys_iconv;
		ret->cd_pull = iconv_open("UCS-2LE", fromcode);
		if (ret->cd_pull == (iconv_t)-1) goto failed;
	}
	if (!charsets[to].name) {
		ret->push = sys_iconv;
		ret->cd_push = iconv_open(tocode, "UCS-2LE");
		if (ret->cd_push == (iconv_t)-1) goto failed;
	}
#else
	if (!charsets[from].name || !charsets[to].name) {
		goto failed;
	}
#endif

	/* check for conversion to/from ucs2 */
	if (from == 0 && charsets[to].name) {
		ret->direct = charsets[to].push;
		return ret;
	}
	if (to == 0 && charsets[from].name) {
		ret->direct = charsets[from].pull;
		return ret;
	}

#ifdef HAVE_NATIVE_ICONV
	if (from == 0) {
		ret->direct = sys_iconv;
		ret->cd_direct = ret->cd_push;
		ret->cd_push = NULL;
		return ret;
	}
	if (to == 0) {
		ret->direct = sys_iconv;
		ret->cd_direct = ret->cd_pull;
		ret->cd_pull = NULL;
		return ret;
	}
#endif

	/* the general case has to go via a buffer */
	if (!ret->pull) ret->pull = charsets[from].pull;
	if (!ret->push) ret->push = charsets[to].push;
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

static size_t ascii_pull(void *cd, char **inbuf, size_t *inbytesleft,
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

static size_t ascii_push(void *cd, char **inbuf, size_t *inbytesleft,
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


static size_t ucs2hex_pull(void *cd, char **inbuf, size_t *inbytesleft,
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

static size_t ucs2hex_push(void *cd, char **inbuf, size_t *inbytesleft,
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


/* the "weird" character set is very useful for testing multi-byte
   support and finding bugs. Don't use on a production system! 
*/
static struct {
	char from;
	char *to;
	int len;
} weird_table[] = {
	{'q', "^q^", 3},
	{'Q', "^Q^", 3},
	{0, NULL}
};

static size_t weird_pull(void *cd, char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	while (*inbytesleft >= 1 && *outbytesleft >= 2) {
		int i;
		int done = 0;
		for (i=0;weird_table[i].from;i++) {
			if (strncmp((*inbuf), 
				    weird_table[i].to, 
				    weird_table[i].len) == 0) {
				if (*inbytesleft < weird_table[i].len) {
					DEBUG(0,("ERROR: truncated weird string\n"));
					/* smb_panic("weird_pull"); */

				} else {
					(*outbuf)[0] = weird_table[i].from;
					(*outbuf)[1] = 0;
					(*inbytesleft)  -= weird_table[i].len;
					(*outbytesleft) -= 2;
					(*inbuf)  += weird_table[i].len;
					(*outbuf) += 2;
					done = 1;
					break;
				}
			}
		}
		if (done) continue;
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

static size_t weird_push(void *cd, char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	int ir_count=0;

	while (*inbytesleft >= 2 && *outbytesleft >= 1) {
		int i;
		int done=0;
		for (i=0;weird_table[i].from;i++) {
			if ((*inbuf)[0] == weird_table[i].from &&
			    (*inbuf)[1] == 0) {
				if (*outbytesleft < weird_table[i].len) {
					DEBUG(0,("No room for weird character\n"));
					/* smb_panic("weird_push"); */
				} else {
					memcpy(*outbuf, weird_table[i].to, 
					       weird_table[i].len);
					(*inbytesleft)  -= 2;
					(*outbytesleft) -= weird_table[i].len;
					(*inbuf)  += 2;
					(*outbuf) += weird_table[i].len;
					done = 1;
					break;
				}
			}
		}
		if (done) continue;

		(*outbuf)[0] = (*inbuf)[0];
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

static size_t iconv_copy(void *cd, char **inbuf, size_t *inbytesleft,
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

static size_t utf8_pull(void *cd, char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	while (*inbytesleft >= 1 && *outbytesleft >= 2) {
		unsigned char *c = (unsigned char *)*inbuf;
		unsigned char *uc = (unsigned char *)*outbuf;
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

static size_t utf8_push(void *cd, char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	while (*inbytesleft >= 2 && *outbytesleft >= 1) {
		unsigned char *c = (unsigned char *)*outbuf;
		unsigned char *uc = (unsigned char *)*inbuf;
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

