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

static size_t ascii_pull(char **, size_t *, char **, size_t *);
static size_t ascii_push(char **, size_t *, char **, size_t *);
static size_t  utf8_pull(char **, size_t *, char **, size_t *);
static size_t  utf8_push(char **, size_t *, char **, size_t *);
static size_t weird_pull(char **, size_t *, char **, size_t *);
static size_t weird_push(char **, size_t *, char **, size_t *);
static size_t iconv_copy(char **, size_t *, char **, size_t *);

/*
  for each charset we have a function that pulls from that charset to 
  a ucs2 buffer, and a function that pushes to a ucs2 buffer 
*/
static struct {
	char *name;
	size_t (*pull)(char **inbuf, size_t *inbytesleft,
		       char **outbuf, size_t *outbytesleft);
	size_t (*push)(char **inbuf, size_t *inbytesleft,
		       char **outbuf, size_t *outbytesleft);
} charsets[] = {
	{"UCS2",  iconv_copy, iconv_copy},
	{"UTF8",   utf8_pull,  utf8_push},
	{"ASCII", ascii_pull, ascii_push},
	{"WEIRD", weird_pull, weird_push},
	{NULL, NULL, NULL}
};

/*
  this is a simple portable iconv() implementaion. It only knows about
  a very small number of character sets - just enough that Samba works
  on systems that don't have iconv
 */
size_t smb_iconv(smb_iconv_t cd, 
		 char **inbuf, size_t *inbytesleft,
		 char **outbuf, size_t *outbytesleft)
{
	char cvtbuf[2048];
	char *bufp = cvtbuf;
	size_t bufsize;

#ifdef HAVE_NATIVE_ICONV
	if (cd->cd) {
		return iconv(cd->cd, inbuf, inbytesleft, outbuf, outbytesleft);
	}
#endif

	if (!inbuf || ! *inbuf || !outbuf || ! *outbuf) return 0;

	/* in most cases we can go direct */
	if (cd->direct) {
		return cd->direct(inbuf, inbytesleft, outbuf, outbytesleft);
	}

	/* otherwise we have to do it chunks at a time */
	while (*inbytesleft > 0) {
		bufp = cvtbuf;
		bufsize = sizeof(cvtbuf);
		if (cd->pull(inbuf, inbytesleft, &bufp, &bufsize) == -1 &&
		    errno != E2BIG) return -1;

		bufp = cvtbuf;
		bufsize = sizeof(cvtbuf) - bufsize;
		if (cd->push(&bufp, &bufsize, outbuf, outbytesleft) == -1) return -1;
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
#ifdef HAVE_NATIVE_ICONV
	iconv_t cd = NULL;
#endif

	for (from=0; charsets[from].name; from++) {
		if (strcasecmp(charsets[from].name, fromcode) == 0) break;
	}
	for (to=0; charsets[to].name; to++) {
		if (strcasecmp(charsets[to].name, tocode) == 0) break;
	}

	if (!charsets[from].name || !charsets[to].name) {
#ifdef HAVE_NATIVE_ICONV
		cd = iconv_open(tocode, fromcode);
		if (!cd)
#endif
		{
			errno = EINVAL;
			return (smb_iconv_t)-1;
		}
	}

	ret = (smb_iconv_t)malloc(sizeof(*ret));
	if (!ret) {
		errno = ENOMEM;
		return (smb_iconv_t)-1;
	}
	memset(ret, 0, sizeof(*ret));

#ifdef HAVE_NATIVE_ICONV
	/* see if we wil be using the native iconv */
	if (cd) {
		ret->cd = cd;
		return ret;
	}
#endif

	/* check for the simplest null conversion */
	if (from == to) {
		ret->direct = iconv_copy;
		return ret;
	}

	/* check for conversion to/from ucs2 */
	if (from == 0) {
		ret->direct = charsets[to].push;
		return ret;
	}
	if (to == 0) {
		ret->direct = charsets[from].pull;
		return ret;
	}

	/* the general case has to go via a buffer */
	ret->pull = charsets[from].pull;
	ret->push = charsets[to].push;
	return ret;
}

/*
  simple iconv_close() wrapper
*/
int smb_iconv_close (smb_iconv_t cd)
{
#ifdef HAVE_NATIVE_ICONV
	if (cd->cd) {
		iconv_close(cd->cd);
	}
#endif
	memset(cd, 0, sizeof(*cd));
	free(cd);
	return 0;
}


/**********************************************************************
 the following functions implement the builtin character sets in Samba
 and also the "test" character sets that are designed to test
 multi-byte character set support for english users
***********************************************************************/

static size_t ascii_pull(char **inbuf, size_t *inbytesleft,
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

static size_t ascii_push(char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	int ir_count=0;

	while (*inbytesleft >= 2 && *outbytesleft >= 1) {
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

static size_t weird_pull(char **inbuf, size_t *inbytesleft,
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

static size_t weird_push(char **inbuf, size_t *inbytesleft,
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

static size_t iconv_copy(char **inbuf, size_t *inbytesleft,
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

static size_t utf8_pull(char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	while (*inbytesleft >= 1 && *outbytesleft >= 2) {
		unsigned char *c = (unsigned char *)*inbuf;
		unsigned char *uc = (unsigned char *)*outbuf;
		int len = 1;

		if ((c[0] & 0xf0) == 0xe0) {
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
		} else {
			uc[0] = c[0];
			uc[1] = 0;
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

static size_t utf8_push(char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	while (*inbytesleft >= 2 && *outbytesleft >= 1) {
		unsigned char *c = (unsigned char *)*outbuf;
		unsigned char *uc = (unsigned char *)*inbuf;
		int len=1;

		if ((uc[1] & 0xf8) == 0xd8) {
			if (*outbytesleft < 3) {
				DEBUG(0,("short utf8 write\n"));
				goto toobig;
			}
			c[0] = 0xed;
			c[1] = 0x9f;
			c[2] = 0xbf;
			len = 3;
		} else if (uc[1] & 0xf8) {
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


		(*outbuf)[0] = (*inbuf)[0];
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

