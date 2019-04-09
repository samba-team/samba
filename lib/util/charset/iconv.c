/*
   Unix SMB/CIFS implementation.
   minimal iconv implementation
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Jelmer Vernooij 2002

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

#include "replace.h"
#include "system/iconv.h"
#include "system/filesys.h"
#include "lib/util/byteorder.h"
#include "lib/util/dlinklist.h"
#include "lib/util/charset/charset.h"
#include "lib/util/charset/charset_proto.h"
#include "libcli/util/ntstatus.h"
#include "lib/util/util_str_hex.h"

#ifdef HAVE_ICU_I18N
#include <unicode/ustring.h>
#include <unicode/utrans.h>
#endif

#ifdef strcasecmp
#undef strcasecmp
#endif

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
 * uppercasing or comparison.  We have to convert to UTF-16LE and
 * compare there.
 *
 * @sa Samba Developers Guide
 **/

static size_t ascii_pull  (void *,const char **, size_t *, char **, size_t *);
static size_t ascii_push  (void *,const char **, size_t *, char **, size_t *);
static size_t latin1_pull(void *,const char **, size_t *, char **, size_t *);
static size_t latin1_push(void *,const char **, size_t *, char **, size_t *);
static size_t utf8_pull   (void *,const char **, size_t *, char **, size_t *);
static size_t utf8_push   (void *,const char **, size_t *, char **, size_t *);
static size_t utf16_munged_pull(void *,const char **, size_t *, char **, size_t *);
static size_t ucs2hex_pull(void *,const char **, size_t *, char **, size_t *);
static size_t ucs2hex_push(void *,const char **, size_t *, char **, size_t *);
static size_t iconv_copy  (void *,const char **, size_t *, char **, size_t *);
static size_t iconv_swab  (void *,const char **, size_t *, char **, size_t *);

static const struct charset_functions builtin_functions[] = {
	/* windows is closest to UTF-16 */
	{
		.name = "UCS-2LE",
		.pull = iconv_copy,
		.push = iconv_copy
	},
	{
		.name = "UTF-16LE",
		.pull = iconv_copy,
		.push = iconv_copy
	},
	{
		.name = "UCS-2BE",
		.pull = iconv_swab,
		.push = iconv_swab
	},
	{
		.name = "UTF-16BE",
		.pull = iconv_swab,
		.push = iconv_swab
	},

	/* we include the UTF-8 alias to cope with differing locale settings */
	{
		.name = "UTF8",
		.pull = utf8_pull,
		.push = utf8_push
	},
	{
		.name = "UTF-8",
		.pull = utf8_pull,
		.push = utf8_push
	},

	/* this handles the munging needed for String2Key */
	{
		.name = "UTF16_MUNGED",
		.pull = utf16_munged_pull,
		.push = iconv_copy,
		.samba_internal_charset = true
	},

	{
		.name = "ASCII",
		.pull = ascii_pull,
		.push = ascii_push
	},
	{
		.name = "646",
		.pull = ascii_pull,
		.push = ascii_push
	},
	{
		.name = "ISO-8859-1",
		.pull = latin1_pull,
		.push = latin1_push
	},
#ifdef DEVELOPER
	{
		.name = "WEIRD",
		.pull = weird_pull,
		.push = weird_push,
		.samba_internal_charset = true
	},
#endif
#ifdef DARWINOS
	{
		.name = "MACOSXFS",
		.pull = macosxfs_encoding_pull,
		.push = macosxfs_encoding_push,
		.samba_internal_charset = true
	},
#endif
	{
		.name = "UCS2-HEX",
		.pull = ucs2hex_pull,
		.push = ucs2hex_push,
		.samba_internal_charset = true
	}
};

#ifdef HAVE_NATIVE_ICONV
/* if there was an error then reset the internal state,
   this ensures that we don't have a shift state remaining for
   character sets like SJIS */
static size_t sys_iconv(void *cd,
			const char **inbuf, size_t *inbytesleft,
			char **outbuf, size_t *outbytesleft)
{
	size_t ret = iconv((iconv_t)cd,
			   discard_const_p(char *, inbuf), inbytesleft,
			   outbuf, outbytesleft);
	if (ret == (size_t)-1) iconv(cd, NULL, NULL, NULL, NULL);
	return ret;
}
#endif

#ifdef HAVE_ICU_I18N
static size_t sys_uconv(void *cd,
			const char **inbuf,
			size_t *inbytesleft,
			char **outbuf,
			size_t *outbytesleft)
{
	UTransliterator *t = (UTransliterator *)cd;
	size_t bufsize = *inbytesleft * 2;
	UChar ustr[bufsize];
	UChar *up = NULL;
	char *p = NULL;
	int32_t ustrlen;
	int32_t limit;
	int32_t converted_len;
	size_t inbuf_consumed;
	size_t outbut_consumed;
	UErrorCode ue;

	/* Convert from UTF8 to UCS2 */
	ue = 0;
	up = u_strFromUTF8(ustr,           /* dst */
			   bufsize,        /* dst buflen */
			   &converted_len, /* dst written */
			   *inbuf,         /* src */
			   *inbytesleft,   /* src length */
			   &ue);
	if (up == NULL || U_FAILURE(ue)) {
		return -1;
	}
	if (converted_len > bufsize) {
		/*
		 * u_strFromUTF8() returns the required size in
		 * converted_len. In theory this should never overflow as the
		 * ustr[] array is allocated with a size twice as big as
		 * inbytesleft and converted_len should be equal to inbytesleft,
		 * but you never know...
		 */
		errno = EOVERFLOW;
		return -1;
	}
	inbuf_consumed = converted_len;

	/*
	 * The following transliteration function takes two parameters, the
	 * lenght of the text to be converted (converted_len) and a limit which
	 * may be smaller then converted_len. We just set limit to converted_len
	 * and also ignore the value returned in limit.
	 */
	limit = converted_len;

	/* Inplace transliteration */
	utrans_transUChars(t,
			   ustr,           /* text */
			   &converted_len, /* text length */
			   bufsize,        /* text buflen */
			   0,              /* start */
			   &limit,         /* limit */
			   &ue);
	if (U_FAILURE(ue)) {
		return -1;
	}
	if (converted_len > bufsize) {
		/*
		 * In theory this should never happen as the ustr[] array is
		 * allocated with a size twice as big as inbytesleft and
		 * converted_len should be equal to inbytesleft, but you never
		 * know...
		 */
		errno = EOVERFLOW;
		return -1;
	}
	ustrlen = converted_len;

	/* Convert from UCS2 back to UTF8 */
	ue = 0;
	p = u_strToUTF8(*outbuf,        /* dst */
			*outbytesleft,  /* dst buflen */
			&converted_len, /* dst required length */
			ustr,           /* src */
			ustrlen,        /* src length */
			&ue);
	if (p == NULL || U_FAILURE(ue)) {
		return -1;
	}

	outbut_consumed = converted_len;
	if (converted_len > *outbytesleft) {
		/*
		 * The caller's result buffer is too small...
		*/
		outbut_consumed = *outbytesleft;
	}

	*inbuf += inbuf_consumed;
	*inbytesleft -= inbuf_consumed;
	*outbuf += outbut_consumed;
	*outbytesleft -= outbut_consumed;

	return converted_len;
}
#endif

/**
 * This is a simple portable iconv() implementaion.
 *
 * It only knows about a very small number of character sets - just
 * enough that Samba works on systems that don't have iconv.
 **/
_PUBLIC_ size_t smb_iconv(smb_iconv_t cd,
		 const char **inbuf, size_t *inbytesleft,
		 char **outbuf, size_t *outbytesleft)
{
	/* in many cases we can go direct */
	if (cd->direct) {
		return cd->direct(cd->cd_direct,
				  inbuf, inbytesleft, outbuf, outbytesleft);
	}

	/* otherwise we have to do it chunks at a time */
	{
#ifndef SMB_ICONV_BUFSIZE
#define SMB_ICONV_BUFSIZE 2048
#endif
		size_t bufsize;
		char cvtbuf[SMB_ICONV_BUFSIZE];

		while (*inbytesleft > 0) {
			char *bufp1 = cvtbuf;
			const char *bufp2 = cvtbuf;
			int saved_errno = errno;
			bool pull_failed = false;
			bufsize = SMB_ICONV_BUFSIZE;

			if (cd->pull(cd->cd_pull,
				     inbuf, inbytesleft, &bufp1, &bufsize) == -1
			    && errno != E2BIG) {
				saved_errno = errno;
				pull_failed = true;
			}

			bufsize = SMB_ICONV_BUFSIZE - bufsize;

			if (cd->push(cd->cd_push,
				     &bufp2, &bufsize,
				     outbuf, outbytesleft) == -1) {
				return -1;
			} else if (pull_failed) {
				/* We want the pull errno if possible */
				errno = saved_errno;
				return -1;
			}
		}
	}

	return 0;
}

static bool is_utf16(const char *name)
{
	return strcasecmp(name, "UCS-2LE") == 0 ||
		strcasecmp(name, "UTF-16LE") == 0;
}

static int smb_iconv_t_destructor(smb_iconv_t hwd)
{
#ifdef HAVE_ICU_I18N
	/*
	 * This has to come first, as the cd_direct member won't be an iconv
	 * handle and must not be passed to iconv_close().
	 */
	if (hwd->direct == sys_uconv) {
		utrans_close(hwd->cd_direct);
		return 0;
	}
#endif
#ifdef HAVE_NATIVE_ICONV
	if (hwd->cd_pull != NULL && hwd->cd_pull != (iconv_t)-1)
		iconv_close(hwd->cd_pull);
	if (hwd->cd_push != NULL && hwd->cd_push != (iconv_t)-1)
		iconv_close(hwd->cd_push);
	if (hwd->cd_direct != NULL && hwd->cd_direct != (iconv_t)-1)
		iconv_close(hwd->cd_direct);
#endif

	return 0;
}

_PUBLIC_ smb_iconv_t smb_iconv_open_ex(TALLOC_CTX *mem_ctx, const char *tocode, 
			      const char *fromcode, bool use_builtin_handlers)
{
	smb_iconv_t ret;
	const struct charset_functions *from=NULL, *to=NULL;
	int i;

	ret = (smb_iconv_t)talloc_named(mem_ctx,
					sizeof(*ret),
					"iconv(%s,%s)", tocode, fromcode);
	if (!ret) {
		errno = ENOMEM;
		return (smb_iconv_t)-1;
	}
	memset(ret, 0, sizeof(*ret));
	talloc_set_destructor(ret, smb_iconv_t_destructor);

	/* check for the simplest null conversion */
	if (strcmp(fromcode, tocode) == 0) {
		ret->direct = iconv_copy;
		return ret;
	}

	/* check if we have a builtin function for this conversion */
	for (i=0;i<ARRAY_SIZE(builtin_functions);i++) {
		if (strcasecmp(fromcode, builtin_functions[i].name) == 0) {
			if (use_builtin_handlers || builtin_functions[i].samba_internal_charset) {
				from = &builtin_functions[i];
			}
		}
		if (strcasecmp(tocode, builtin_functions[i].name) == 0) {
			if (use_builtin_handlers || builtin_functions[i].samba_internal_charset) {
				to = &builtin_functions[i];
			}
		}
	}

#ifdef HAVE_NATIVE_ICONV
	/* the from and to variables indicate a samba module or
	 * internal conversion, ret->pull and ret->push are
	 * initialised only in this block for iconv based
	 * conversions */

	if (from == NULL) {
		ret->cd_pull = iconv_open("UTF-16LE", fromcode);
		if (ret->cd_pull == (iconv_t)-1)
			ret->cd_pull = iconv_open("UCS-2LE", fromcode);
		if (ret->cd_pull != (iconv_t)-1) {
			ret->pull = sys_iconv;
		}
	}

	if (to == NULL) {
		ret->cd_push = iconv_open(tocode, "UTF-16LE");
		if (ret->cd_push == (iconv_t)-1)
			ret->cd_push = iconv_open(tocode, "UCS-2LE");
		if (ret->cd_push != (iconv_t)-1) {
			ret->push = sys_iconv;
		}
	}
#endif

#ifdef HAVE_ICU_I18N
	if (strcasecmp(fromcode, "UTF8-NFD") == 0 &&
	    strcasecmp(tocode, "UTF8-NFC") == 0)
	{
		U_STRING_DECL(t, "any-nfc", 7);
		UErrorCode ue = 0;

		U_STRING_INIT(t, "any-nfc", 7);

		ret->cd_direct = utrans_openU(t,
					      strlen("any-nfc"),
					      UTRANS_FORWARD,
					      NULL,
					      0,
					      NULL,
					      &ue);
		if (U_FAILURE(ue)) {
			return (smb_iconv_t)-1;
		}
		ret->direct = sys_uconv;
		return ret;
	}

	if (strcasecmp(fromcode, "UTF8-NFC") == 0 &&
	    strcasecmp(tocode, "UTF8-NFD") == 0)
	{
		U_STRING_DECL(tname, "any-nfd", 7);
		UErrorCode ue = 0;

		U_STRING_INIT(tname, "any-nfd", 7);

		ret->cd_direct = utrans_openU(tname,
					      7,
					      UTRANS_FORWARD,
					      NULL,
					      0,
					      NULL,
					      &ue);
		if (U_FAILURE(ue)) {
			return (smb_iconv_t)-1;
		}
		ret->direct = sys_uconv;
		return ret;
	}
#endif

	if (ret->pull == NULL && from == NULL) {
		goto failed;
	}

	if (ret->push == NULL && to == NULL) {
		goto failed;
	}

	/* check for conversion to/from ucs2 */
	if (is_utf16(fromcode) && to) {
		ret->direct = to->push;
		return ret;
	}
	if (is_utf16(tocode) && from) {
		ret->direct = from->pull;
		return ret;
	}

#ifdef HAVE_NATIVE_ICONV
	if (is_utf16(fromcode)) {
		ret->direct = sys_iconv;
		ret->cd_direct = ret->cd_push;
		ret->cd_push = NULL;
		return ret;
	}
	if (is_utf16(tocode)) {
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
	talloc_free(ret);
	errno = EINVAL;
	return (smb_iconv_t)-1;
}

/*
  simple iconv_open() wrapper
 */
_PUBLIC_ smb_iconv_t smb_iconv_open(const char *tocode, const char *fromcode)
{
	return smb_iconv_open_ex(NULL, tocode, fromcode, true);
}

/*
  simple iconv_close() wrapper
*/
_PUBLIC_ int smb_iconv_close(smb_iconv_t cd)
{
	talloc_free(cd);
	return 0;
}


/**********************************************************************
 the following functions implement the builtin character sets in Samba
 and also the "test" character sets that are designed to test
 multi-byte character set support for english users
***********************************************************************/

/*
  this takes an ASCII sequence and produces a UTF16 sequence

  The first 127 codepoints of latin1 matches the first 127 codepoints
  of unicode, and so can be put into the first byte of UTF16LE

 */

static size_t ascii_pull(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	while (*inbytesleft >= 1 && *outbytesleft >= 2) {
		if (((*inbuf)[0] & 0x7F) != (*inbuf)[0]) {
			/* If this is multi-byte, then it isn't legal ASCII */
			errno = EILSEQ;
			return -1;
		}
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

/*
  this takes a UTF16 sequence and produces an ASCII sequence

  The first 127 codepoints of ASCII matches the first 127 codepoints
  of unicode, and so can be read directly from the first byte of UTF16LE

 */
static size_t ascii_push(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	int ir_count=0;

	while (*inbytesleft >= 2 && *outbytesleft >= 1) {
		if (((*inbuf)[0] & 0x7F) != (*inbuf)[0] ||
			(*inbuf)[1] != 0) {
			/* If this is multi-byte, then it isn't legal ASCII */
			errno = EILSEQ;
			return -1;
		}
		(*outbuf)[0] = (*inbuf)[0];
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

/*
  this takes a latin1/ISO-8859-1 sequence and produces a UTF16 sequence

  The first 256 codepoints of latin1 matches the first 256 codepoints
  of unicode, and so can be put into the first byte of UTF16LE

 */
static size_t latin1_pull(void *cd, const char **inbuf, size_t *inbytesleft,
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

/*
  this takes a UTF16 sequence and produces a latin1/ISO-8859-1 sequence

  The first 256 codepoints of latin1 matches the first 256 codepoints
  of unicode, and so can be read directly from the first byte of UTF16LE

 */
static size_t latin1_push(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	int ir_count=0;

	while (*inbytesleft >= 2 && *outbytesleft >= 1) {
		(*outbuf)[0] = (*inbuf)[0];
		if ((*inbuf)[1] != 0) {
			/* If this is multi-byte, then it isn't legal latin1 */
			errno = EILSEQ;
			return -1;
		}
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
		uint64_t v;
		NTSTATUS status;
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
		status = read_hex_bytes(&(*inbuf)[1], 4, &v);

		if (!NT_STATUS_IS_OK(status)) {
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

/*
  this takes a UTF8 sequence and produces a UTF16 sequence
 */
static size_t utf8_pull(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft)
{
	size_t in_left=*inbytesleft, out_left=*outbytesleft;
	const uint8_t *c = (const uint8_t *)*inbuf;
	uint8_t *uc = (uint8_t *)*outbuf;

	while (in_left >= 1 && out_left >= 2) {
		if ((c[0] & 0x80) == 0) {
			uc[0] = c[0];
			uc[1] = 0;
			c  += 1;
			in_left  -= 1;
			out_left -= 2;
			uc += 2;
			continue;
		}

		if ((c[0] & 0xe0) == 0xc0) {
			if (in_left < 2 ||
			    (c[1] & 0xc0) != 0x80) {
				errno = EILSEQ;
				goto error;
			}
			uc[1] = (c[0]>>2) & 0x7;
			uc[0] = (c[0]<<6) | (c[1]&0x3f);
			c  += 2;
			in_left  -= 2;
			out_left -= 2;
			uc += 2;
			continue;
		}

		if ((c[0] & 0xf0) == 0xe0) {
			if (in_left < 3 ||
			    (c[1] & 0xc0) != 0x80 ||
			    (c[2] & 0xc0) != 0x80) {
				errno = EILSEQ;
				goto error;
			}
			uc[1] = ((c[0]&0xF)<<4) | ((c[1]>>2)&0xF);
			uc[0] = (c[1]<<6) | (c[2]&0x3f);
			c  += 3;
			in_left  -= 3;
			out_left -= 2;
			uc += 2;
			continue;
		}

		if ((c[0] & 0xf8) == 0xf0) {
			unsigned int codepoint;
			if (in_left < 4 ||
			    (c[1] & 0xc0) != 0x80 ||
			    (c[2] & 0xc0) != 0x80 ||
			    (c[3] & 0xc0) != 0x80) {
				errno = EILSEQ;
				goto error;
			}
			codepoint =
				(c[3]&0x3f) |
				((c[2]&0x3f)<<6) |
				((c[1]&0x3f)<<12) |
				((c[0]&0x7)<<18);
			if (codepoint < 0x10000) {
				/* accept UTF-8 characters that are not
				   minimally packed, but pack the result */
				uc[0] = (codepoint & 0xFF);
				uc[1] = (codepoint >> 8);
				c += 4;
				in_left -= 4;
				out_left -= 2;
				uc += 2;
				continue;
			}

			codepoint -= 0x10000;

			if (out_left < 4) {
				errno = E2BIG;
				goto error;
			}

			uc[0] = (codepoint>>10) & 0xFF;
			uc[1] = (codepoint>>18) | 0xd8;
			uc[2] = codepoint & 0xFF;
			uc[3] = ((codepoint>>8) & 0x3) | 0xdc;
			c  += 4;
			in_left  -= 4;
			out_left -= 4;
			uc += 4;
			continue;
		}

		/* we don't handle 5 byte sequences */
		errno = EINVAL;
		goto error;
	}

	if (in_left > 0) {
		errno = E2BIG;
		goto error;
	}

	*inbytesleft = in_left;
	*outbytesleft = out_left;
	*inbuf = (const char *)c;
	*outbuf = (char *)uc;
	return 0;

error:
	*inbytesleft = in_left;
	*outbytesleft = out_left;
	*inbuf = (const char *)c;
	*outbuf = (char *)uc;
	return -1;
}


/*
  this takes a UTF16 sequence and produces a UTF8 sequence
 */
static size_t utf8_push(void *cd, const char **inbuf, size_t *inbytesleft,
			char **outbuf, size_t *outbytesleft)
{
	size_t in_left=*inbytesleft, out_left=*outbytesleft;
	uint8_t *c = (uint8_t *)*outbuf;
	const uint8_t *uc = (const uint8_t *)*inbuf;

	while (in_left >= 2 && out_left >= 1) {
		unsigned int codepoint;

		if (uc[1] == 0 && !(uc[0] & 0x80)) {
			/* simplest case */
			c[0] = uc[0];
			in_left  -= 2;
			out_left -= 1;
			uc += 2;
			c  += 1;
			continue;
		}

		if ((uc[1]&0xf8) == 0) {
			/* next simplest case */
			if (out_left < 2) {
				errno = E2BIG;
				goto error;
			}
			c[0] = 0xc0 | (uc[0]>>6) | (uc[1]<<2);
			c[1] = 0x80 | (uc[0] & 0x3f);
			in_left  -= 2;
			out_left -= 2;
			uc += 2;
			c  += 2;
			continue;
		}

		if ((uc[1] & 0xfc) == 0xdc) {
			errno = EILSEQ;
#ifndef HAVE_ICONV_ERRNO_ILLEGAL_MULTIBYTE
			if (in_left < 4) {
				errno = EINVAL;
			}
#endif
			goto error;
		}

		if ((uc[1] & 0xfc) != 0xd8) {
			codepoint = uc[0] | (uc[1]<<8);
			if (out_left < 3) {
				errno = E2BIG;
				goto error;
			}
			c[0] = 0xe0 | (codepoint >> 12);
			c[1] = 0x80 | ((codepoint >> 6) & 0x3f);
			c[2] = 0x80 | (codepoint & 0x3f);

			in_left  -= 2;
			out_left -= 3;
			uc  += 2;
			c   += 3;
			continue;
		}

		/* its the first part of a 4 byte sequence */
		if (in_left < 4) {
			errno = EINVAL;
			goto error;
		}
		if ((uc[3] & 0xfc) != 0xdc) {
			errno = EILSEQ;
			goto error;
		}
		codepoint = 0x10000 + (uc[2] | ((uc[3] & 0x3)<<8) |
				       (uc[0]<<10) | ((uc[1] & 0x3)<<18));

		if (out_left < 4) {
			errno = E2BIG;
			goto error;
		}
		c[0] = 0xf0 | (codepoint >> 18);
		c[1] = 0x80 | ((codepoint >> 12) & 0x3f);
		c[2] = 0x80 | ((codepoint >> 6) & 0x3f);
		c[3] = 0x80 | (codepoint & 0x3f);

		in_left  -= 4;
		out_left -= 4;
		uc       += 4;
		c        += 4;
	}

	if (in_left == 1) {
		errno = EINVAL;
		goto error;
	}

	if (in_left > 1) {
		errno = E2BIG;
		goto error;
	}

	*inbytesleft = in_left;
	*outbytesleft = out_left;
	*inbuf  = (const char *)uc;
	*outbuf = (char *)c;

	return 0;

error:
	*inbytesleft = in_left;
	*outbytesleft = out_left;
	*inbuf  = (const char *)uc;
	*outbuf = (char *)c;
	return -1;
}


/*
  this takes a UTF16 munged sequence, modifies it according to the
  string2key rules, and produces a UTF16 sequence

The rules are:

    1) any 0x0000 characters are mapped to 0x0001

    2) convert any instance of 0xD800 - 0xDBFF (high surrogate)
       without an immediately following 0xDC00 - 0x0xDFFF (low surrogate) to
       U+FFFD (OBJECT REPLACEMENT CHARACTER).

    3) the same for any low surrogate that was not preceded by a high surrogate.

 */
static size_t utf16_munged_pull(void *cd, const char **inbuf, size_t *inbytesleft,
			       char **outbuf, size_t *outbytesleft)
{
	size_t in_left=*inbytesleft, out_left=*outbytesleft;
	uint8_t *c = (uint8_t *)*outbuf;
	const uint8_t *uc = (const uint8_t *)*inbuf;

	while (in_left >= 2 && out_left >= 2) {
		unsigned int codepoint = uc[0] | (uc[1]<<8);

		if (codepoint == 0) {
			codepoint = 1;
		}

		if ((codepoint & 0xfc00) == 0xd800) {
			/* a high surrogate */
			unsigned int codepoint2;
			if (in_left < 4) {
				codepoint = 0xfffd;
				goto codepoint16;
			}
			codepoint2 = uc[2] | (uc[3]<<8);
			if ((codepoint2 & 0xfc00) != 0xdc00) {
				/* high surrogate not followed by low
				   surrogate: convert to 0xfffd */
				codepoint = 0xfffd;
				goto codepoint16;
			}
			if (out_left < 4) {
				errno = E2BIG;
				goto error;
			}
			memcpy(c, uc, 4);
			in_left  -= 4;
			out_left -= 4;
			uc       += 4;
			c        += 4;
			continue;
		}

		if ((codepoint & 0xfc00) == 0xdc00) {
			/* low surrogate not preceded by high
			   surrogate: convert to 0xfffd */
			codepoint = 0xfffd;
		}

	codepoint16:
		c[0] = codepoint & 0xFF;
		c[1] = (codepoint>>8) & 0xFF;

		in_left  -= 2;
		out_left -= 2;
		uc  += 2;
		c   += 2;
		continue;
	}

	if (in_left == 1) {
		errno = EINVAL;
		goto error;
	}

	if (in_left > 1) {
		errno = E2BIG;
		goto error;
	}

	*inbytesleft = in_left;
	*outbytesleft = out_left;
	*inbuf  = (const char *)uc;
	*outbuf = (char *)c;

	return 0;

error:
	*inbytesleft = in_left;
	*outbytesleft = out_left;
	*inbuf  = (const char *)uc;
	*outbuf = (char *)c;
	return -1;
}



