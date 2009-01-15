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
typedef enum {CH_UTF16=0, CH_UNIX, CH_DOS, CH_UTF8, CH_UTF16BE, CH_UTF16MUNGED} charset_t;

#define NUM_CHARSETS 6

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
	struct charset_functions *prev, *next;
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
struct smb_iconv_convenience;

/* replace some string functions with multi-byte
   versions */
#define strlower(s) strlower_m(s)
#define strupper(s) strupper_m(s)

char *strchr_m(const char *s, char c);
size_t strlen_m_term(const char *s);
size_t strlen_m_term_null(const char *s);
size_t strlen_m(const char *s);
char *alpha_strcpy(char *dest, const char *src, const char *other_safe_chars, size_t maxlength);
void string_replace_m(char *s, char oldc, char newc);
bool strcsequal_m(const char *s1,const char *s2);
bool strequal_m(const char *s1, const char *s2);
int strncasecmp_m(const char *s1, const char *s2, size_t n);
bool next_token(const char **ptr,char *buff, const char *sep, size_t bufsize);
int strcasecmp_m(const char *s1, const char *s2);
size_t count_chars_m(const char *s, char c);
void strupper_m(char *s);
void strlower_m(char *s);
char *strupper_talloc(TALLOC_CTX *ctx, const char *src);
char *talloc_strdup_upper(TALLOC_CTX *ctx, const char *src);
char *strupper_talloc_n(TALLOC_CTX *ctx, const char *src, size_t n);
char *strlower_talloc(TALLOC_CTX *ctx, const char *src);
bool strhasupper(const char *string);
bool strhaslower(const char *string);
char *strrchr_m(const char *s, char c);
char *strchr_m(const char *s, char c);

ssize_t push_ascii_talloc(TALLOC_CTX *ctx, char **dest, const char *src);
ssize_t push_ucs2_talloc(TALLOC_CTX *ctx, void **dest, const char *src);
ssize_t push_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src);
ssize_t pull_ascii_talloc(TALLOC_CTX *ctx, char **dest, const char *src);
ssize_t pull_ucs2_talloc(TALLOC_CTX *ctx, char **dest, const void *src);
ssize_t pull_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src);
ssize_t push_string(void *dest, const char *src, size_t dest_len, int flags);
ssize_t pull_string(char *dest, const void *src, size_t dest_len, size_t src_len, int flags);

ssize_t convert_string_talloc(TALLOC_CTX *ctx, 
				       charset_t from, charset_t to, 
				       void const *src, size_t srclen, 
				       void **dest);

ssize_t convert_string(charset_t from, charset_t to,
				void const *src, size_t srclen, 
				void *dest, size_t destlen);

ssize_t iconv_talloc(TALLOC_CTX *mem_ctx, 
				       smb_iconv_t cd,
				       void const *src, size_t srclen, 
				       void **dest);

extern struct smb_iconv_convenience *global_iconv_convenience;

codepoint_t next_codepoint(const char *str, size_t *size);

/* codepoints */
codepoint_t next_codepoint_convenience(struct smb_iconv_convenience *ic, 
			    const char *str, size_t *size);
ssize_t push_codepoint(struct smb_iconv_convenience *ic, 
				char *str, codepoint_t c);
codepoint_t toupper_m(codepoint_t val);
codepoint_t tolower_m(codepoint_t val);
int codepoint_cmpi(codepoint_t c1, codepoint_t c2);

/* Iconv convenience functions */
struct smb_iconv_convenience *smb_iconv_convenience_init(TALLOC_CTX *mem_ctx,
							 const char *dos_charset,
							 const char *unix_charset,
							 bool native_iconv);

ssize_t convert_string_convenience(struct smb_iconv_convenience *ic,
				charset_t from, charset_t to,
				void const *src, size_t srclen, 
				void *dest, size_t destlen);
ssize_t convert_string_talloc_convenience(TALLOC_CTX *ctx, 
				       struct smb_iconv_convenience *ic, 
				       charset_t from, charset_t to, 
				       void const *src, size_t srclen, 
				       void **dest);
/* iconv */
smb_iconv_t smb_iconv_open(const char *tocode, const char *fromcode);
int smb_iconv_close(smb_iconv_t cd);
size_t smb_iconv(smb_iconv_t cd, 
		 const char **inbuf, size_t *inbytesleft,
		 char **outbuf, size_t *outbytesleft);
smb_iconv_t smb_iconv_open_ex(TALLOC_CTX *mem_ctx, const char *tocode, 
			      const char *fromcode, bool native_iconv);

void load_case_tables(void);
bool charset_register_backend(const void *_funcs);

#endif /* __CHARSET_H__ */
