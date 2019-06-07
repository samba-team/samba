/*
 * Samba Unix/Linux SMB client library
 *
 * Copyright (C) Gregor Beck 2010
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @brief  Parser for dot.reg files
 * @file   reg_parse.c
 * @author Gregor Beck <gb@sernet.de>
 * @date   Jun 2010
 *
 */

#include "includes.h"
#include "system/filesys.h"
#include "cbuf.h"
#include "srprs.h"
#include "reg_parse_internal.h"
#include "reg_parse.h"
#include "reg_format.h"

#include <stdio.h>
#include <talloc.h>
#include <stdbool.h>
#include <string.h>
#include <regex.h>
#include <assert.h>
#include <stdint.h>

enum reg_parse_state {
	STATE_DEFAULT,
	STATE_KEY_OPEN,
	STATE_VAL_HEX_CONT,
	STATE_VAL_SZ_CONT
};

struct reg_parse {
	struct reg_format_callback reg_format_callback;
	cbuf* key;
	cbuf* valname;
	uint32_t   valtype;
	cbuf* valblob;
	cbuf* tmp;
	struct reg_parse_callback call;
	int ret;
	int linenum;
	enum reg_parse_state state;
	struct reg_parse_options* opt;
	smb_iconv_t str2UTF16;
	unsigned flags;
};

/**
 * @defgroup action Action
 * @{
 */
static bool act_key(struct reg_parse* p, cbuf* keyname, bool del)
{
	const char* name = cbuf_gets(keyname, 0);
	cbuf_swap(p->key, keyname);

	assert(p->state == STATE_DEFAULT || p->state == STATE_KEY_OPEN);
	p->state = del ? STATE_DEFAULT : STATE_KEY_OPEN;

	assert(p->call.key);
	p->ret = p->call.key(p->call.data, &name, 1, del);
	return p->ret >= 0;
}

static bool value_callback(struct reg_parse* p)
{
	const char* name = cbuf_gets(p->valname,0);
	const uint8_t* val = (const uint8_t*)cbuf_gets(p->valblob,0);
	size_t len = cbuf_getpos(p->valblob);

	assert(p->call.val);
	p->ret = p->call.val(p->call.data, name, p->valtype, val, len);
	return p->ret >= 0;
}

static bool act_val_hex(struct reg_parse* p, cbuf* value, bool cont)
{
	cbuf_swap(p->valblob, value);
	assert((p->state == STATE_KEY_OPEN) || (p->state == STATE_VAL_HEX_CONT));

	if (cont) {
		p->state = STATE_VAL_HEX_CONT;
	} else {
		p->state = STATE_KEY_OPEN;

		switch (p->valtype) {
		case REG_EXPAND_SZ:
		case REG_MULTI_SZ:
			if (p->str2UTF16 != NULL) {
				char* dst = NULL;
				const char* src = cbuf_gets(p->valblob, 0);
				const size_t slen = cbuf_getpos(p->valblob);
				size_t dlen = iconvert_talloc(p,
							      p->str2UTF16,
							      src, slen,
							      &dst);
				if (dlen != -1) {
					cbuf_swapptr(p->valblob, &dst, dlen);
				} else {
					DEBUG(0, ("iconvert_talloc failed\n"));
					return false;
				}
				talloc_free(dst);
			}
		default:
			break;
		}
		return value_callback(p);
	}
	return true;
}

static bool act_val_dw(struct reg_parse* p, uint32_t val)
{
	assert(p->valtype == REG_DWORD);
	assert(p->state == STATE_KEY_OPEN);

	cbuf_clear(p->valblob);

	if (cbuf_putdw(p->valblob, val) < 0) {
		return false;
	}
	return value_callback(p);
}

static bool act_val_sz(struct reg_parse* p, cbuf* value, bool cont)
{
	cbuf_swap(p->valblob, value);

	assert(p->valtype == REG_SZ);
	assert((p->state == STATE_KEY_OPEN) || (p->state == STATE_VAL_SZ_CONT));

	if (cont) {
		p->state = STATE_VAL_SZ_CONT;
	} else {
		char* dst = NULL;
		size_t dlen;
		const char* src = cbuf_gets(p->valblob, 0);

		p->state = STATE_KEY_OPEN;


		if (convert_string_talloc(p->valblob, CH_UNIX, CH_UTF16LE,
					  src, strlen(src)+1,
					  &dst, &dlen))
		{
			cbuf_swapptr(p->valblob, &dst, dlen);
		} else {
			DEBUG(0, ("convert_string_talloc failed: >%s<\n"
				  "use it as is\t", src));
			return false;
		}
		talloc_free(dst);

		return value_callback(p);
	}
	return true;
}

static bool act_val_del(struct reg_parse* p)
{
	const char* name = cbuf_gets(p->valname, 0);

	assert(p->call.val_del);
	p->ret = p->call.val_del(p->call.data, name);
	return p->ret >= 0;
}

static bool act_comment (struct reg_parse* p, const char* txt)
{
	assert(p->call.comment);
	p->ret = p->call.comment(p->call.data, txt);
	return p->ret >= 0;
}
/**@}*/


static int nop_callback_key(void* private_data,
		const char* key[],
		size_t klen,
		bool del)
{
	return 0;
}

static int nop_callback_val(void* private_data,
		const char* name,
		uint32_t type,
		const uint8_t* data,
		size_t len)
{
	return 0;
}

static int nop_callback_del(void* data, const char* str)
{
	return 0;
}

struct reg_parse* reg_parse_new(const void* ctx,
				struct reg_parse_callback cb,
				const char* str_enc, unsigned flags)
{
	struct reg_parse* s = talloc_zero(ctx, struct reg_parse);
	if (s == NULL)
		return NULL;
	s->key     = cbuf_new(s);
	s->valname = cbuf_new(s);
	s->valblob = cbuf_new(s);
	s->tmp     = cbuf_new(s);
	if ( (s->tmp == NULL) || (s->valblob == NULL)
	     || (s->valname == NULL) || (s->key == NULL) )
	{
		goto fail;
	}

	s->reg_format_callback.writeline = (reg_format_callback_writeline_t)&reg_parse_line;
	s->reg_format_callback.data      = s;

	s->valtype = 0;
	if (cb.key == NULL) {
		cb.key = (reg_parse_callback_key_t)&nop_callback_key;
	}
	if (cb.val == NULL) {
		cb.val = (reg_parse_callback_val_t)&nop_callback_val;
	}
	if (cb.val_del == NULL) {
		cb.val_del = (reg_parse_callback_val_del_t)&nop_callback_del;
	}
	if (cb.comment == NULL) {
		cb.comment =
			(reg_parse_callback_comment_t)&nop_callback_del;
	}

	s->call = cb;
	s->linenum = 0;
	s->state = STATE_DEFAULT;
	s->flags = flags;

	if (str_enc && !set_iconv(&s->str2UTF16, "UTF-16LE", str_enc)) {
		DEBUG(0, ("reg_parse_new: failed to set encoding: %s",
			  str_enc));
		goto fail;
	}

	assert(&s->reg_format_callback == (struct reg_format_callback*)s);
	return s;
fail:
	set_iconv(&s->str2UTF16, NULL, NULL);
	talloc_free(s);
	return NULL;
}

/**
 * @defgroup parse Parser Primitive
 * @ingroup internal
 * @{
 */


static bool srprs_key(const char** ptr, cbuf* key, bool* del)
{
	const char* pos = *ptr;
	const char* closing_bracket_pos = NULL;
	size_t      closing_bracket_idx = 0;

	if (!srprs_skipws(&pos) || !srprs_char(&pos, '[')) {
		return false;
	}

	*del = srprs_char(&pos, '-');

	cbuf_clear(key);

	while (true) {
		while (srprs_charsetinv(&pos, "]\\", key))
			;

		switch (*pos) {

		case ']':
			closing_bracket_idx = cbuf_getpos(key);
			closing_bracket_pos = pos;
			cbuf_putc(key, ']');
			pos++;
			break;

		case '\\':
			cbuf_putc(key, '\\');
			/* n++; */
			/* cbuf_puts(subkeyidx, cbuf_getpos(key), sizeof(size_t)) */
			while (srprs_char(&pos,'\\'))
				;
			break;

		case '\0':
			if (closing_bracket_pos == NULL) {
				return false;
			}

			/* remove trailing backslash (if any) */
			if (*(closing_bracket_pos-1)=='\\') {
				closing_bracket_idx--;
			}

			cbuf_setpos(key, closing_bracket_idx);
			*ptr = closing_bracket_pos+1;
			return true;

		default:
			assert(false);
		}
	}
}

static bool srprs_val_name(const char** ptr, cbuf* name)
{
	const char* pos = *ptr;
	const size_t spos = cbuf_getpos(name);

	if ( !srprs_skipws(&pos) ) {
		goto fail;
	}

	if ( srprs_char(&pos, '@') ) {
		cbuf_puts(name, "", -1);
	}
	else if (!srprs_quoted_string(&pos, name, NULL)) {
		goto fail;
	}

	if (!srprs_skipws(&pos) || !srprs_char(&pos, '=')) {
		goto fail;
	}

	*ptr = pos;
	return true;

fail:
	cbuf_setpos(name, spos);
	return false;
}

static bool srprs_val_dword(const char** ptr, uint32_t* type, uint32_t* val)
{
	const char* pos = *ptr;

	if (!srprs_str(&pos, "dword:", -1)) {
		return false;
	}

	if (!srprs_hex(&pos, 8, val)) {
		return false;
	}

	*type = REG_DWORD;
	*ptr  = pos;
	return true;
}

static bool srprs_val_sz(const char** ptr, uint32_t* type, cbuf* val, bool* cont)
{
	if (!srprs_quoted_string(ptr, val, cont)) {
		return false;
	}

	*type = REG_SZ;
	return true;
}


static bool srprs_nl_no_eos(const char** ptr, cbuf* str, bool eof)
{
	const char* pos = *ptr;
	const size_t spos = cbuf_getpos(str);

	if( srprs_nl(&pos, str) && (eof || *pos != '\0')) {
		*ptr = pos;
		return true;
	}
	cbuf_setpos(str, spos);
	return false;
}


static bool srprs_eol_cont(const char** ptr, bool* cont)
{
	const char* pos = *ptr;
	bool bs = srprs_char(&pos, '\\');

	if (!srprs_eol(&pos, NULL)) {
		return false;
	}

	*cont = bs;
	*ptr = pos;
	return true;
}

/* matches the empty string, for zero length lists */
static bool srprs_val_hex_values(const char** ptr, cbuf* val, bool* cont)
{
	const char* pos = *ptr;
	unsigned u;

	do {
		if (!srprs_skipws(&pos) || !srprs_hex(&pos, 2, &u) || !srprs_skipws(&pos)) {
			break;
		}
		cbuf_putc(val, (char)u);
	} while(srprs_char(&pos, ','));

	*ptr = pos;

	if (srprs_skipws(&pos) && srprs_eol_cont(&pos, cont)) {
		*ptr = pos;
	}

	return true;
}

static bool srprs_val_hex(const char** ptr, uint32_t* ptype, cbuf* val,
		       bool* cont)
{
	const char* pos = *ptr;
	uint32_t type;

	if (!srprs_str(&pos, "hex", -1)) {
		return false;
	}

	if (srprs_char(&pos, ':')) {
		type = REG_BINARY;
	}
	else if (!srprs_char(&pos, '(') ||
		 !srprs_hex(&pos, 8, &type) ||
		 !srprs_char(&pos,')') ||
		 !srprs_char(&pos, ':'))
	{
		return false;
	}

	if (!srprs_val_hex_values(&pos, val, cont)) {
		return false;
	}

	*ptype = type;
	*ptr = pos;
	return true;
}


static bool srprs_comment(const char** ptr, cbuf* str)
{
	return srprs_char(ptr, ';') && srprs_line(ptr, str);
}

/**@}*/

int reg_parse_set_options(struct reg_parse* parser, const char* options)
{
	static const char* DEFAULT ="enc=unix,flags=0";

	int ret = 0;
	char *key, *val;
	void* ctx = talloc_new(parser);

	if (options == NULL) {
		options = DEFAULT;
	}

	while (srprs_option(&options, ctx, &key, &val)) {
		if ((strcmp(key, "enc") == 0) || (strcmp(key, "strenc") == 0)) {
		} else if ((strcmp(key, "flags") == 0) && (val != NULL)) {
			char* end = NULL;
			if (val != NULL) {
				parser->flags = strtol(val, &end, 0);
			}
			if ((end==NULL) || (*end != '\0')) {
				DEBUG(0, ("Invalid flags format: %s\n",
					  val ? val : "<NULL>"));
				ret = -1;
			}
		}
		/* else if (strcmp(key, "hive") == 0) { */
		/* 	if (strcmp(val, "short") == 0) { */
		/* 		f->hive_fmt = REG_FMT_SHORT_HIVES; */
		/* 	} else if (strcmp(val, "long") == 0) { */
		/* 		f->hive_fmt = REG_FMT_LONG_HIVES; */
		/* 	} else if (strcmp(val, "preserve") == 0) { */
		/* 		f->hive_fmt = REG_FMT_PRESERVE_HIVES; */
		/* 	} else { */
		/* 		DEBUG(0, ("Invalid hive format: %s\n", val)); */
		/* 		ret = -1; */
		/* 	} */
		/* } */
	}
	talloc_free(ctx);
	return ret;
}


int reg_parse_line(struct reg_parse* parser, const char* line)
{
	const char* pos;
	bool del=false;
	cbuf* tmp=cbuf_clear(parser->tmp);
	bool cb_ok = true;
	bool cont = true;

	if (!line) {
		return -4;
	}

	parser->linenum++;
	pos = line;

	switch (parser->state) {
	case STATE_VAL_HEX_CONT:
		if (srprs_val_hex_values(&pos, parser->valblob, &cont)) {
			cb_ok = act_val_hex(parser, parser->valblob, cont);
		}
		goto done;
	case STATE_VAL_SZ_CONT:
		if (srprs_quoted_string(&pos, parser->valblob, &cont)) {
			cb_ok = act_val_sz(parser, parser->valblob, cont);
		}
		goto done;
	default:
		cont = false;
	}

	if ( !srprs_skipws(&pos) ) {
		return -4;
	}

	/* empty line ?*/
	if ( srprs_eol(&pos, NULL) ) {
		return 0;
	}

	/* key line ?*/
	else if (srprs_key(&pos, tmp, &del)) {
		cb_ok = act_key(parser, tmp, del);
	}

	/* comment line ? */
	else if (srprs_comment(&pos, tmp)) {
		cb_ok = act_comment(parser, cbuf_gets(tmp, 0));
	}

	/* head line */
	else if ((parser->linenum == 1) && srprs_line(&pos, tmp) ) {
		/* cb_ok = act_head(parser, cbuf_gets(tmp, 0)); */
	}

	/* value line ?*/
	else if (srprs_val_name(&pos, tmp)) {
		uint32_t dw;
		cbuf_swap(parser->valname, tmp);
		cbuf_clear(tmp);

		if (parser->state != STATE_KEY_OPEN) {
			DEBUG(0, ("value \"%s\" without a key at line: %i",
				  cbuf_gets(parser->valname, 0), parser->linenum));
			return -3;
		}

		if (!srprs_skipws(&pos)) {
			return -4;
		}

		if (srprs_char(&pos, '-')) {
			cb_ok = act_val_del(parser);
		}
		else if (srprs_val_dword(&pos, &parser->valtype, &dw)) {
			cb_ok = act_val_dw(parser, dw);
		}
		else if (srprs_val_sz(&pos, &parser->valtype, tmp, &cont)) {
			cb_ok = act_val_sz(parser, tmp, cont);
		}
		else if (srprs_val_hex(&pos, &parser->valtype, tmp, &cont)){
			cb_ok = act_val_hex(parser, tmp, cont);
		}
		else {
			DEBUG(0, ("value \"%s\" parse error"
				  "at line: %i pos: %li : %s",
				  cbuf_gets(parser->valname, 0), parser->linenum,
				  (long int)(pos-line), pos));
			return -3;
		}
	}
	else {
		DEBUG(0, ("unrecognized line %i : %s\n", parser->linenum, line));
		return -3;
	}

done:
	if (!cb_ok)
		return -2;

	if (!srprs_skipws(&pos) || !srprs_eol(&pos, NULL)) {
		DEBUG(0, ("trailing garbage at line: %i pos: %li : %s\n",
			  parser->linenum, (long int)(pos-line), pos));
		return -1;
	}
	return 0;
}

/******************************************************************************/
/**
 * @addtogroup misc
 * @{
 */
static bool lookslike_utf16(const char* line, size_t len, bool* little_endian)
{
	static const uint16_t M_LE = 0xFF80;
	static const uint16_t M_BE = 0x80FF;
	uint16_t mask;
	bool le;

	size_t l = MIN(len/2, 64);
	const uint16_t* u = (const uint16_t*)line;
	int i;

	assert(len >= 2);

	if ( u[0] & M_LE ) {
		le = true;
		mask = M_LE;
	} else 	if ( u[0] & M_BE ) {
		le = false;
		mask = M_BE;
	} else {
		return false;
	}

	for (i=1; i<l; i++) {
		if ( u[i] & mask ) {
			return false;
		}
	}

	*little_endian = le;
	return true;
}

static bool lookslike_dos(const char* line, size_t len)
{
	int i;
	for (i=0; i<len; i++) {
		if ( (line[i] == '\0') || (line[i] & 0x80) ) {
			return false;
		}
		if ( (line[i] == '\r') && (i+1 < len) && (line[i+1] == '\n') ) {
			return true;
		}
	}
	return false;
}

static bool guess_charset(const char** ptr,
			  size_t* len,
			  const char** file_enc,
			  const char** str_enc)
{
	const char* charset = NULL;
	const char* pos = *ptr;

	if (*len < 4) {
		return false;
	}

	if (srprs_bom(&pos, &charset, NULL)) {
		size_t declen;
		if (pos < *ptr) {
			return false;
		}
		declen = (pos - *ptr);
		if (*len < declen) {
			return false;
		}
		*len -= declen;
		*ptr = pos;
		if (*file_enc == NULL) {
			*file_enc = charset;
		}
		else if( strcmp(*file_enc, charset) != 0 ) {
			DEBUG(0, ("file encoding forced to %s\n",
				  *file_enc));
		}
	}
	else if (*file_enc == NULL) {
		bool le;
		if (lookslike_utf16(*ptr, *len, &le)) {
			*file_enc = le ? "UTF-16LE" : "UTF-16BE";
		}
		else if (lookslike_dos(*ptr, *len)) {
			*file_enc = "dos";
		}
		else {
			*file_enc = "unix";
		}
	}

	if ((str_enc != NULL) && (*str_enc == NULL)) {
		*str_enc = ( strncmp(*ptr, "REGEDIT4", 8) == 0)
			? *file_enc
			: "UTF-16LE";
	}

	return true;
}
/**@}*/

struct reg_parse_fd_opt {
	const char* file_enc;
	const char* str_enc;
	unsigned flags;
	int fail_level;
};

static struct reg_parse_fd_opt
reg_parse_fd_opt(void* mem_ctx, const char* options)
{
	struct reg_parse_fd_opt ret = {
		.file_enc = NULL,
		.str_enc  = NULL,
		.flags    = 0,
	};

	void* ctx = talloc_new(mem_ctx);
	char *key, *val;

	if (options == NULL) {
		goto done;
	}

	while (srprs_option(&options, ctx, &key, &val)) {
		if (strcmp(key, "enc") == 0) {
			ret.file_enc = talloc_steal(mem_ctx, val);
			ret.str_enc  = ret.file_enc;
		} else if (strcmp(key, "strenc") == 0) {
			ret.str_enc = talloc_steal(mem_ctx, val);
		} else if (strcmp(key, "fileenc") == 0) {
			ret.file_enc = talloc_steal(mem_ctx, val);
		} else if ((strcmp(key, "flags") == 0) && (val != NULL)) {
			char* end = NULL;
			if (val != NULL) {
				ret.flags = strtol(val, &end, 0);
			}
			if ((end==NULL) || (*end != '\0')) {
				DEBUG(0, ("Invalid format \"%s\": %s\n",
					  key, val ? val : "<NULL>"));
			}
		} else if ((strcmp(key, "fail") == 0) && (val != NULL)) {
			char* end = NULL;
			if (val != NULL) {
				ret.fail_level = -strtol(val, &end, 0);
			}
			if ((end==NULL) || (*end != '\0')) {
				DEBUG(0, ("Invalid format \"%s\": %s\n",
					  key, val ? val : "<NULL>"));
			}
		}
	}
done:
	talloc_free(ctx);
	return ret;
}

static void display_iconv_error_bytes(const char *inbuf, size_t len)
{
	size_t i;
	for (i = 0; i < 4 && i < len; i++) {
		DEBUGADD(0, ("<%02x>", (unsigned char)inbuf[i]));
	}
	DEBUGADD(0, ("\n"));
}

int reg_parse_fd(int fd, const struct reg_parse_callback* cb, const char* opts)
{
	void* mem_ctx            = talloc_stackframe();
	cbuf* line               = cbuf_new(mem_ctx);
	smb_iconv_t cd           = (smb_iconv_t)-1;
	struct reg_parse* parser = NULL;
	char buf_in[1024];
	char buf_out[1025] = { 0 };
	ssize_t nread;
	const char* iptr;
	char* optr;
        size_t ilen;
	size_t olen;
	size_t avail_osize = sizeof(buf_out)-1;
	size_t space_to_read = sizeof(buf_in);
	int ret = -1;
	bool eof = false;
	size_t linecount = 0;

	struct reg_parse_fd_opt opt = reg_parse_fd_opt(mem_ctx, opts);

	if (cb == NULL) {
		DBG_ERR("NULL callback\n");
		ret = -1;
		goto done;
	}

	nread = read(fd, buf_in, space_to_read);
	if (nread < 0) {
		DBG_ERR("read failed: %s\n", strerror(errno));
		ret = -1;
		goto done;
	}
	if (nread == 0) {
		/* Empty file. */
		eof = true;
		goto done;
	}

	iptr = buf_in;
	ilen = nread;

	if (!guess_charset(&iptr, &ilen,
			   &opt.file_enc, &opt.str_enc))
	{
		DBG_ERR("reg_parse_fd: failed to guess encoding\n");
		ret = -1;
		goto done;
	}

	if (ilen == 0) {
		/* File only contained charset info. */
		eof = true;
		ret = -1;
		goto done;
	}

	DBG_DEBUG("reg_parse_fd: encoding file: %s str: %s\n",
		  opt.file_enc, opt.str_enc);


	if (!set_iconv(&cd, "unix", opt.file_enc)) {
		DBG_ERR("reg_parse_fd: failed to set file encoding %s\n",
			  opt.file_enc);
		ret = -1;
		goto done;
	}

	parser = reg_parse_new(mem_ctx, *cb, opt.str_enc, opt.flags);
	if (parser == NULL) {
		ret = -1;
		goto done;
	}

	/* Move input data to start of buf_in. */
	if (iptr > buf_in) {
		memmove(buf_in, iptr, ilen);
		iptr = buf_in;
	}

	optr = buf_out;
	/* Leave last byte for null termination. */
	olen = avail_osize;

	/*
	 * We read from buf_in (iptr), iconv converting into
	 * buf_out (optr).
	 */

	while (!eof) {
		const char *pos;
		size_t nconv;

		if (olen == 0) {
			/* We're out of possible room. */
			DBG_ERR("no room in output buffer\n");
			ret = -1;
			goto done;
		}
		nconv = smb_iconv(cd, &iptr, &ilen, &optr, &olen);
		if (nconv == (size_t)-1) {
			bool valid_err = false;
			if (errno == EINVAL) {
				valid_err = true;
			}
			if (errno == E2BIG) {
				valid_err = true;
			}
			if (!valid_err) {
				DBG_ERR("smb_iconv error in file at line %zu: ",
					  linecount);
				display_iconv_error_bytes(iptr, ilen);
				ret = -1;
				goto done;
			}
			/*
			 * For valid errors process the
			 * existing buffer then continue.
			 */
		}

		/*
		 * We know this is safe as we have an extra
		 * enforced zero byte at the end of buf_out.
		 */
		*optr = '\0';
		pos = buf_out;

		while (srprs_line(&pos, line) && srprs_nl_no_eos(&pos, line, eof)) {
			int retval;

			/* Process all lines we got. */
			retval = reg_parse_line(parser, cbuf_gets(line, 0));
			if (retval < opt.fail_level) {
				DBG_ERR("reg_parse_line %zu fail %d\n",
					linecount,
					retval);
				ret = -1;
				goto done;
			}
			cbuf_clear(line);
			linecount++;
		}
		if (pos > buf_out) {
			/*
			 * The output data we have
			 * processed starts at buf_out
			 * and ends at pos.
			 * The unprocessed output
			 * data starts at pos and
			 * ends at optr.
			 *
			 *  <------ sizeof(buf_out) - 1------------->|0|
			 *  <--------- avail_osize------------------>|0|
			 *  +----------------------+-------+-----------+
			 *  |                      |       |         |0|
			 *  +----------------------+-------+-----------+
			 *  ^                      ^       ^
			 *  |                      |       |
			 * buf_out               pos      optr
			 */
			size_t unprocessed_len;

			/* Paranoia checks. */
			if (optr < pos) {
				ret = -1;
				goto done;
			}
			unprocessed_len = optr - pos;

			/* Paranoia checks. */
			if (avail_osize < unprocessed_len) {
				ret = -1;
				goto done;
			}
			/* Move down any unprocessed data. */
			memmove(buf_out, pos, unprocessed_len);

			/*
			 * After the move, reset the output length.
			 *
			 *  <------ sizeof(buf_out) - 1------------->|0|
			 *  <--------- avail_osize------------------>|0|
			 *  +----------------------+-------+-----------+
			 *  |       |                                |0|
			 *  +----------------------+-------+-----------+
			 *  ^       ^
			 *  |       optr
			 * buf_out
			 */
			optr = buf_out + unprocessed_len;
			/*
			 * Calculate the new output space available
			 * for iconv.
			 * We already did the paranoia check for this
			 * arithmetic above.
			 */
			olen = avail_osize - unprocessed_len;
		}

		/*
		 * Move any unprocessed data to the start of
		 * the input buffer (buf_in).
		 */
		if (ilen > 0 && iptr > buf_in) {
			memmove(buf_in, iptr, ilen);
		}

		/* Is there any space to read more input ? */
		if (ilen >= sizeof(buf_in)) {
			/* No space. Nothing was converted. Error. */
			DBG_ERR("no space in input buffer\n");
			ret = -1;
			goto done;
		}

		space_to_read = sizeof(buf_in) - ilen;

		/* Read the next chunk from the file. */
		nread = read(fd, buf_in + ilen, space_to_read);
		if (nread < 0) {
			DBG_ERR("read failed: %s\n", strerror(errno));
			ret = -1;
			goto done;
		}
		if (nread == 0) {
			/* Empty file. */
			eof = true;
			continue;
		}

		/* Paranoia check. */
		if (nread + ilen < ilen) {
			ret = -1;
			goto done;
		}

		/* Paranoia check. */
		if (nread + ilen > sizeof(buf_in)) {
			ret = -1;
			goto done;
		}

		iptr = buf_in;
		ilen = nread + ilen;
	}

	ret = 0;

done:

	set_iconv(&cd, NULL, NULL);
	if (parser) {
		set_iconv(&parser->str2UTF16, NULL, NULL);
	}
	talloc_free(mem_ctx);
	return ret;
}

int reg_parse_file(const char* fname, const struct reg_parse_callback* cb,
		   const char* opt)
{
	int ret = -1;
	int fd;

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		DEBUG(0, ("reg_parse_file: open %s failed: %s\n", fname,
			  strerror(errno)));
		return -1;
	}

	ret = reg_parse_fd(fd, cb, opt);

	close(fd);
	return ret;
}

/* static struct registry_key *find_regkey_by_hnd(pipes_struct *p, */
/* 					       struct policy_handle *hnd) */
/* { */
/* 	struct registry_key *regkey = NULL; */

/* 	if(!find_policy_by_hnd(p,hnd,(void **)(void *)&regkey)) { */
/* 		DEBUG(2,("find_regkey_index_by_hnd: Registry Key not found: ")); */
/* 		return NULL; */
/* 	} */

/* 	return regkey; */
/* } */
