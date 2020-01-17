/* 
   Unix SMB/CIFS implementation.
   charset defines
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

/* This is a public header file that is installed as part of Samba. 
 * If you remove any functions or change their signature, update 
 * the so version number. */

#ifndef __CHARSET_H__
#define __CHARSET_H__

#include <talloc.h>

/* this defines the charset types used in samba */
typedef enum {CH_UTF16LE=0, CH_UTF16=0, CH_UNIX, CH_DOS, CH_UTF8, CH_UTF16BE, CH_UTF16MUNGED} charset_t;

#define NUM_CHARSETS 7

/*
 * SMB UCS2 (16-bit unicode) internal type.
 * smb_ucs2_t is *always* in little endian format.
 */

typedef uint16_t smb_ucs2_t;

#ifdef WORDS_BIGENDIAN
#define UCS2_SHIFT 8
#else
#define UCS2_SHIFT 0
#endif

/* turn a 7 bit character into a ucs2 character */
#define UCS2_CHAR(c) ((c) << UCS2_SHIFT)

/*
 *   for each charset we have a function that pulls from that charset to
 *     a ucs2 buffer, and a function that pushes to a ucs2 buffer
 *     */

struct charset_functions {
	const char *name;
	size_t (*pull)(void *, const char **inbuf, size_t *inbytesleft,
				   char **outbuf, size_t *outbytesleft);
	size_t (*push)(void *, const char **inbuf, size_t *inbytesleft,
				   char **outbuf, size_t *outbytesleft);
	bool samba_internal_charset;
};

/* this type is used for manipulating unicode codepoints */
typedef uint32_t codepoint_t;

#define INVALID_CODEPOINT ((codepoint_t)-1)

/* generic iconv conversion structure */
typedef struct smb_iconv_s {
	size_t (*direct)(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft);
	size_t (*pull)(void *cd, const char **inbuf, size_t *inbytesleft,
		       char **outbuf, size_t *outbytesleft);
	size_t (*push)(void *cd, const char **inbuf, size_t *inbytesleft,
		       char **outbuf, size_t *outbytesleft);
	void *cd_direct, *cd_pull, *cd_push;
	char *from_name, *to_name;
} *smb_iconv_t;

/* string manipulation flags */
#define STR_TERMINATE 1
#define STR_UPPER 2
#define STR_ASCII 4
#define STR_UNICODE 8
#define STR_NOALIGN 16
#define STR_NO_RANGE_CHECK 32
#define STR_LEN8BIT 64
#define STR_TERMINATE_ASCII 128 /* only terminate if ascii */
#define STR_LEN_NOTERM 256 /* the length field is the unterminated length */

struct loadparm_context;
struct smb_iconv_handle;

char *strchr_m(const char *s, char c);
/**
 * Calculate the number of units (8 or 16-bit, depending on the
 * destination charset), that would be needed to convert the input
 * string which is expected to be in in src_charset encoding to the
 * destination charset (which should be a unicode charset).
 */
size_t strlen_m_ext_handle(struct smb_iconv_handle *ic,
			   const char *s, charset_t src_charset, charset_t dst_charset);
size_t strlen_m_ext(const char *s, charset_t src_charset, charset_t dst_charset);
size_t strlen_m_ext_term(const char *s, charset_t src_charset,
			 charset_t dst_charset);
size_t strlen_m_ext_term_null(const char *s,
			      charset_t src_charset,
			      charset_t dst_charset);
size_t strlen_m(const char *s);
size_t strlen_m_term(const char *s);
size_t strlen_m_term_null(const char *s);
char *alpha_strcpy(char *dest, const char *src, const char *other_safe_chars, size_t maxlength);
char *talloc_alpha_strcpy(TALLOC_CTX *mem_ctx,
			  const char *src,
			  const char *other_safe_chars);
void string_replace_m(char *s, char oldc, char newc);
bool strcsequal(const char *s1,const char *s2);
bool strequal_m(const char *s1, const char *s2);
int strncasecmp_m(const char *s1, const char *s2, size_t n);
int strncasecmp_m_handle(struct smb_iconv_handle *iconv_handle,
			 const char *s1, const char *s2, size_t n);
bool next_token(const char **ptr,char *buff, const char *sep, size_t bufsize);
int strcasecmp_m_handle(struct smb_iconv_handle *iconv_handle,
			const char *s1, const char *s2);
int strcasecmp_m(const char *s1, const char *s2);
size_t count_chars_m(const char *s, char c);
char *strupper_talloc(TALLOC_CTX *ctx, const char *src);
char *talloc_strdup_upper(TALLOC_CTX *ctx, const char *src);
char *strupper_talloc_n_handle(struct smb_iconv_handle *iconv_handle,
				TALLOC_CTX *ctx, const char *src, size_t n);
char *strupper_talloc_n(TALLOC_CTX *ctx, const char *src, size_t n);
 char *strlower_talloc_handle(struct smb_iconv_handle *iconv_handle,
			      TALLOC_CTX *ctx, const char *src);
char *strlower_talloc(TALLOC_CTX *ctx, const char *src);
bool strhasupper(const char *string);
bool strhaslower_handle(struct smb_iconv_handle *ic,
			const char *string);
bool strhaslower(const char *string);
bool strhasupper_handle(struct smb_iconv_handle *ic,
			const char *string);
char *strrchr_m(const char *s, char c);
char *strchr_m(const char *s, char c);
char *strstr_m(const char *src, const char *findstr);

bool push_ascii_talloc(TALLOC_CTX *ctx, char **dest, const char *src, size_t *converted_size);
bool push_ucs2_talloc(TALLOC_CTX *ctx, smb_ucs2_t **dest, const char *src, size_t *converted_size);
bool push_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src, size_t *converted_size);
bool pull_ascii_talloc(TALLOC_CTX *ctx, char **dest, const char *src, size_t *converted_size);
bool pull_ucs2_talloc(TALLOC_CTX *ctx, char **dest, const smb_ucs2_t *src, size_t *converted_size);
bool pull_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src, size_t *converted_size);
ssize_t push_string(void *dest, const char *src, size_t dest_len, int flags);
ssize_t pull_string(char *dest, const void *src, size_t dest_len, size_t src_len, int flags);

bool convert_string_talloc(TALLOC_CTX *ctx, 
			   charset_t from, charset_t to, 
			   void const *src, size_t srclen, 
			   void *dest, size_t *converted_size);

bool convert_string(charset_t from, charset_t to,
		      void const *src, size_t srclen, 
		      void *dest, size_t destlen,
		      size_t *converted_size);
bool convert_string_error(charset_t from, charset_t to,
			  void const *src, size_t srclen,
			  void *dest, size_t destlen,
			  size_t *converted_size);

struct smb_iconv_handle *get_iconv_handle(void);
struct smb_iconv_handle *get_iconv_testing_handle(TALLOC_CTX *mem_ctx, 
						  const char *dos_charset, 
						  const char *unix_charset,
						  bool use_builtin_handlers);
struct smb_iconv_handle *reinit_iconv_handle(TALLOC_CTX *mem_ctx,
				const char *dos_charset,
				const char *unix_charset);
void free_iconv_handle(void);

smb_iconv_t get_conv_handle(struct smb_iconv_handle *ic,
			    charset_t from, charset_t to);
const char *charset_name(struct smb_iconv_handle *ic, charset_t ch);

codepoint_t next_codepoint_ext(const char *str, size_t len,
			       charset_t src_charset, size_t *size);
codepoint_t next_codepoint(const char *str, size_t *size);
ssize_t push_codepoint(char *str, codepoint_t c);

/* codepoints */
codepoint_t next_codepoint_handle_ext(struct smb_iconv_handle *ic,
				      const char *str, size_t len,
				      charset_t src_charset,
				      size_t *size);
codepoint_t next_codepoint_handle(struct smb_iconv_handle *ic,
			    const char *str, size_t *size);
ssize_t push_codepoint_handle(struct smb_iconv_handle *ic,
				char *str, codepoint_t c);

codepoint_t toupper_m(codepoint_t val);
codepoint_t tolower_m(codepoint_t val);
bool islower_m(codepoint_t val);
bool isupper_m(codepoint_t val);
int codepoint_cmpi(codepoint_t c1, codepoint_t c2);

/* Iconv convenience functions */
struct smb_iconv_handle *smb_iconv_handle_reinit(TALLOC_CTX *mem_ctx,
							   const char *dos_charset,
							   const char *unix_charset,
							   bool use_builtin_handlers,
							   struct smb_iconv_handle *old_ic);

bool convert_string_handle(struct smb_iconv_handle *ic,
				charset_t from, charset_t to,
				void const *src, size_t srclen, 
				void *dest, size_t destlen, size_t *converted_size);
bool convert_string_error_handle(struct smb_iconv_handle *ic,
				 charset_t from, charset_t to,
				 void const *src, size_t srclen,
				 void *dest, size_t destlen,
				 size_t *converted_size);

bool convert_string_talloc_handle(TALLOC_CTX *ctx,
				       struct smb_iconv_handle *ic,
				       charset_t from, charset_t to, 
				       void const *src, size_t srclen, 
				       void *dest, size_t *converted_size);
/* iconv */
smb_iconv_t smb_iconv_open(const char *tocode, const char *fromcode);
int smb_iconv_close(smb_iconv_t cd);
size_t smb_iconv(smb_iconv_t cd, 
		 const char **inbuf, size_t *inbytesleft,
		 char **outbuf, size_t *outbytesleft);
smb_iconv_t smb_iconv_open_ex(TALLOC_CTX *mem_ctx, const char *tocode, 
			      const char *fromcode, bool use_builtin_handlers);

void smb_init_locale(void);

/* The following definitions come from util_unistr_w.c  */

size_t strlen_w(const smb_ucs2_t *src);
size_t strnlen_w(const smb_ucs2_t *src, size_t max);
smb_ucs2_t *strchr_w(const smb_ucs2_t *s, smb_ucs2_t c);
smb_ucs2_t *strchr_wa(const smb_ucs2_t *s, char c);
smb_ucs2_t *strrchr_w(const smb_ucs2_t *s, smb_ucs2_t c);
smb_ucs2_t *strnrchr_w(const smb_ucs2_t *s, smb_ucs2_t c, unsigned int n);
smb_ucs2_t *strstr_w(const smb_ucs2_t *s, const smb_ucs2_t *ins);
bool strlower_w(smb_ucs2_t *s);
bool strupper_w(smb_ucs2_t *s);
int strcasecmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b);
int strncasecmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b, size_t len);
int strcmp_wa(const smb_ucs2_t *a, const char *b);
smb_ucs2_t toupper_w(smb_ucs2_t v);

#endif /* __CHARSET_H__ */
