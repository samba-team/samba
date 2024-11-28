/*
 *  Unix SMB implementation.
 *  Functions for understanding conditional ACEs
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/conditional_ace.h"
#include "libcli/security/security.h"
#include "libcli/security/conditional_ace.h"
#include "libcli/security/claims-conversions.h"
#include "lib/util/tsort.h"
#include "lib/util/bytearray.h"


/* We're only dealing with utf-8 here. Honestly. */
#undef strncasecmp


#define SDDL_FLAG_EXPECTING_UNARY_OP          1
#define SDDL_FLAG_EXPECTING_BINARY_OP         2
#define SDDL_FLAG_EXPECTING_BINARY_LOGIC_OP   4
#define SDDL_FLAG_EXPECTING_LOCAL_ATTR        8
#define SDDL_FLAG_EXPECTING_NON_LOCAL_ATTR   16
#define SDDL_FLAG_EXPECTING_LITERAL          32
#define SDDL_FLAG_EXPECTING_PAREN            64
#define SDDL_FLAG_EXPECTING_PAREN_LITERAL   128
#define SDDL_FLAG_NOT_EXPECTING_END_PAREN   256

#define SDDL_FLAG_DEVICE                    512

#define SDDL_FLAG_IS_UNARY_OP               (1 << 20)
#define SDDL_FLAG_IS_BINARY_OP              (1 << 21)


#define SDDL_FLAGS_EXPR_START (SDDL_FLAG_EXPECTING_UNARY_OP | \
			       SDDL_FLAG_EXPECTING_LOCAL_ATTR | \
			       SDDL_FLAG_EXPECTING_NON_LOCAL_ATTR | \
			       SDDL_FLAG_EXPECTING_PAREN)

#define SDDL_FLAGS_MEMBER_OP (SDDL_FLAG_EXPECTING_LITERAL | \
			      SDDL_FLAG_EXPECTING_PAREN_LITERAL | \
			      SDDL_FLAG_IS_UNARY_OP)

#define SDDL_FLAGS_RELATIONAL_OP (SDDL_FLAG_EXPECTING_LITERAL | \
				  SDDL_FLAG_EXPECTING_PAREN_LITERAL |  \
				  SDDL_FLAG_EXPECTING_NON_LOCAL_ATTR | \
				  SDDL_FLAG_IS_BINARY_OP)

#define SDDL_FLAGS_CONTAINS_OP (SDDL_FLAG_EXPECTING_LITERAL | \
				SDDL_FLAG_EXPECTING_NON_LOCAL_ATTR |    \
				SDDL_FLAG_IS_BINARY_OP)

#define SDDL_FLAGS_EXISTS_OP (SDDL_FLAG_EXPECTING_LOCAL_ATTR | \
			      SDDL_FLAG_EXPECTING_NON_LOCAL_ATTR | \
			      SDDL_FLAG_IS_UNARY_OP)

#define SDDL_FLAGS_LOGIC_OP (SDDL_FLAG_EXPECTING_LOCAL_ATTR | \
			     SDDL_FLAG_EXPECTING_NON_LOCAL_ATTR | \
			     SDDL_FLAG_EXPECTING_PAREN | \
			     SDDL_FLAG_EXPECTING_UNARY_OP | \
			     SDDL_FLAG_IS_BINARY_OP)

#define SDDL_FLAGS_ATTRIBUTE (SDDL_FLAG_EXPECTING_BINARY_OP | \
			      SDDL_FLAG_EXPECTING_BINARY_LOGIC_OP)

#define SDDL_FLAGS_LITERAL SDDL_FLAG_EXPECTING_BINARY_LOGIC_OP

#define SDDL_FLAGS_PAREN_END (SDDL_FLAG_EXPECTING_BINARY_LOGIC_OP | \
			      SDDL_FLAG_EXPECTING_BINARY_OP)

enum {
	SDDL_NOT_AN_OP = 0,
	SDDL_PRECEDENCE_EXISTS,
	SDDL_PRECEDENCE_COMMON,
	SDDL_PRECEDENCE_NOT,
	SDDL_PRECEDENCE_AND,
	SDDL_PRECEDENCE_OR,
	SDDL_PRECEDENCE_PAREN_END,
	SDDL_PRECEDENCE_PAREN_START,
};

struct ace_condition_sddl_compiler_context {
	TALLOC_CTX *mem_ctx;
	const uint8_t *sddl;
	uint32_t length;
	uint32_t offset;
	uint32_t stack_depth;
	uint32_t max_program_length;
	uint32_t approx_size;
	struct ace_condition_script *program;
	struct ace_condition_token *stack;
	struct ace_condition_token *target;
	uint32_t *target_len;
	const char *message;
	uint32_t message_offset;
	struct dom_sid *domain_sid;
	uint32_t state;
	uint8_t last_token_type;
	bool allow_device;
};

struct sddl_data {
	const char *name;
	uint32_t flags;
	uint8_t op_precedence;
	uint8_t nargs;
};

static const struct sddl_data sddl_strings[256] = {
	/* operators */
	[CONDITIONAL_ACE_TOKEN_MEMBER_OF] = {
		"Member_of",
		SDDL_FLAGS_MEMBER_OP,
		SDDL_PRECEDENCE_COMMON,
		1
	},
	[CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF] = {
		"Device_Member_of",
		SDDL_FLAGS_MEMBER_OP|SDDL_FLAG_DEVICE,
		SDDL_PRECEDENCE_COMMON,
		1
	},
	[CONDITIONAL_ACE_TOKEN_MEMBER_OF_ANY] = {
		/* [MS-DTYP] says "_Any", but windows prefers '_any' */
		"Member_of_any",
		SDDL_FLAGS_MEMBER_OP,
		SDDL_PRECEDENCE_COMMON,
		1
	},
	[CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF_ANY] = {
		"Device_Member_of_Any",
		SDDL_FLAGS_MEMBER_OP|SDDL_FLAG_DEVICE,
		SDDL_PRECEDENCE_COMMON,
		1
	},
	[CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF] = {
		"Not_Member_of",
		SDDL_FLAGS_MEMBER_OP,
		SDDL_PRECEDENCE_COMMON,
		1
	},
	[CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF] = {
		"Not_Device_Member_of",
		SDDL_FLAGS_MEMBER_OP|SDDL_FLAG_DEVICE,
		SDDL_PRECEDENCE_COMMON,
		1
	},
	[CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF_ANY] = {
		"Not_Member_of_Any",
		SDDL_FLAGS_MEMBER_OP,
		SDDL_PRECEDENCE_COMMON,
		1
	},
	[CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF_ANY] = {
		"Not_Device_Member_of_Any",
		SDDL_FLAGS_MEMBER_OP|SDDL_FLAG_DEVICE,
		SDDL_PRECEDENCE_COMMON,
		1
	},
	[CONDITIONAL_ACE_TOKEN_EQUAL] = {
		"==",
		SDDL_FLAGS_RELATIONAL_OP,
		SDDL_PRECEDENCE_COMMON,
		2
	},
	[CONDITIONAL_ACE_TOKEN_NOT_EQUAL] = {
		"!=",
		SDDL_FLAGS_RELATIONAL_OP,
		SDDL_PRECEDENCE_COMMON,
		2
	},
	[CONDITIONAL_ACE_TOKEN_LESS_THAN] = {
		"<",
		SDDL_FLAGS_RELATIONAL_OP,
		SDDL_PRECEDENCE_COMMON,
		2
	},
	[CONDITIONAL_ACE_TOKEN_LESS_OR_EQUAL] = {
		"<=",
		SDDL_FLAGS_RELATIONAL_OP,
		SDDL_PRECEDENCE_COMMON,
		2
	},
	[CONDITIONAL_ACE_TOKEN_GREATER_THAN] = {
		">",
		SDDL_FLAGS_RELATIONAL_OP,
		SDDL_PRECEDENCE_COMMON,
		2
	},
	[CONDITIONAL_ACE_TOKEN_GREATER_OR_EQUAL] = {
		">=",
		SDDL_FLAGS_RELATIONAL_OP,
		SDDL_PRECEDENCE_COMMON,
		2
	},
	[CONDITIONAL_ACE_TOKEN_CONTAINS] = {
		"Contains",
		SDDL_FLAGS_CONTAINS_OP,
		SDDL_PRECEDENCE_COMMON,
		2
	},
	[CONDITIONAL_ACE_TOKEN_ANY_OF] = {
		"Any_of",
		SDDL_FLAGS_CONTAINS_OP,
		SDDL_PRECEDENCE_COMMON,
		2
	},
	[CONDITIONAL_ACE_TOKEN_NOT_CONTAINS] = {
		"Not_Contains",
		SDDL_FLAGS_CONTAINS_OP,
		SDDL_PRECEDENCE_COMMON,
		2
	},
	[CONDITIONAL_ACE_TOKEN_NOT_ANY_OF] = {
		"Not_Any_of",
		SDDL_FLAGS_CONTAINS_OP,
		SDDL_PRECEDENCE_COMMON,
		2
	},
	[CONDITIONAL_ACE_TOKEN_AND] = {
		"&&",
		SDDL_FLAGS_LOGIC_OP,
		SDDL_PRECEDENCE_AND,
		2
	},
	[CONDITIONAL_ACE_TOKEN_OR] = {
		"||",
		SDDL_FLAGS_LOGIC_OP,
		SDDL_PRECEDENCE_OR,
		2
	},
	[CONDITIONAL_ACE_TOKEN_NOT] = {
		"!",
		(SDDL_FLAG_EXPECTING_PAREN |
		 SDDL_FLAG_EXPECTING_NON_LOCAL_ATTR |
		 SDDL_FLAG_IS_UNARY_OP),
		SDDL_PRECEDENCE_NOT,
		1
	},
	[CONDITIONAL_ACE_TOKEN_EXISTS] = {
		"Exists",
		SDDL_FLAGS_EXISTS_OP,
		SDDL_PRECEDENCE_EXISTS,
		1
	},
	[CONDITIONAL_ACE_TOKEN_NOT_EXISTS] = {
		"Not_Exists",
		SDDL_FLAGS_EXISTS_OP,
		SDDL_PRECEDENCE_EXISTS,
		1
	},
	/* pseudo-operator pseudo-tokens */
	[CONDITIONAL_ACE_SAMBA_SDDL_PAREN] = {
		"(",
		0,
		SDDL_PRECEDENCE_PAREN_START,
		0
	},
	[CONDITIONAL_ACE_SAMBA_SDDL_PAREN_END] = {
		")",
		SDDL_FLAGS_PAREN_END,
		SDDL_PRECEDENCE_PAREN_END,
		0
	},

	/*
	 * non-operators.
	 * The names here are only used for error messages.
	 *
	 * some of them will never actually be encountered (e.g. 8-bit
	 * integers).
	 */
	[CONDITIONAL_ACE_TOKEN_INT8] = {
		.name = "8-bit integer",
		.flags = SDDL_FLAGS_LITERAL,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_TOKEN_INT16] = {
		"16-bit integer",
		SDDL_FLAGS_LITERAL,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_TOKEN_INT32] = {
		"32-bit integer",
		SDDL_FLAGS_LITERAL,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_TOKEN_INT64] = {
		"64-bit integer",
		SDDL_FLAGS_LITERAL,
		SDDL_NOT_AN_OP,
		0
	},

	[CONDITIONAL_ACE_TOKEN_UNICODE] = {
		"unicode",
		SDDL_FLAGS_LITERAL,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_TOKEN_OCTET_STRING] = {
		"byte string",
		SDDL_FLAGS_LITERAL,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_TOKEN_COMPOSITE] = {
		"composite list",
		SDDL_FLAGS_LITERAL,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_TOKEN_SID] = {
		"SID",
		SDDL_FLAGS_LITERAL,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_LOCAL_ATTRIBUTE] = {
		"local attribute",
		SDDL_FLAGS_ATTRIBUTE,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_USER_ATTRIBUTE] = {
		"user attribute",
		SDDL_FLAGS_ATTRIBUTE,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_RESOURCE_ATTRIBUTE] = {
		"resource attribute",
		SDDL_FLAGS_ATTRIBUTE,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_DEVICE_ATTRIBUTE] = {
		"device attribute",
		SDDL_FLAGS_ATTRIBUTE|SDDL_FLAG_DEVICE,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_SAMBA_RESULT_BOOL] = {
		"boolean result",
		0,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_SAMBA_RESULT_NULL] = {
		"null result",
		0,
		SDDL_NOT_AN_OP,
		0
	},
	[CONDITIONAL_ACE_SAMBA_RESULT_ERROR] = {
		"error result",
		0,
		SDDL_NOT_AN_OP,
		0
	},
};

struct sddl_attr_type{
	const char *name;
	uint8_t code;
};

/*
 * These are the prefixes for non-local attribute types. [MS-DTYP]
 * styles them in title case ("@User."), but Windows itself seems to
 * prefer all-caps, so that is how we render them.
 */
static const struct sddl_attr_type sddl_attr_types[] = {
	{"USER.", CONDITIONAL_ACE_USER_ATTRIBUTE},
	{"RESOURCE.", CONDITIONAL_ACE_RESOURCE_ATTRIBUTE},
	{"DEVICE.", CONDITIONAL_ACE_DEVICE_ATTRIBUTE},
};


struct sddl_write_context {
	TALLOC_CTX *mem_ctx;
	char *sddl;
	size_t len;
	size_t alloc_len;
};

static bool sddl_write(struct sddl_write_context *ctx,
		       const char *s)
{
	size_t len = strlen(s);
	if (ctx->alloc_len - ctx->len <= len ||
	    ctx->sddl == NULL) {
		size_t old = ctx->alloc_len;
		ctx->alloc_len = old + MAX(old / 2, len + 50);
		if (ctx->alloc_len <= old ||
		    ctx->alloc_len - ctx->len <= len) {
			return false;
		}
		ctx->sddl = talloc_realloc(ctx->mem_ctx, ctx->sddl,
					   char, ctx->alloc_len);

		if (ctx->sddl == NULL) {
			return false;
		}
	}
	memcpy(ctx->sddl + ctx->len, s, len);
	ctx->len += len;
	ctx->sddl[ctx->len] = 0;
	return true;
}

/*
 * This is a helper function to create a representation of a
 * conditional ACE. This is not SDDL, more like a disassembly,
 * but it uses some of the same tables.
 */
char *debug_conditional_ace(TALLOC_CTX *mem_ctx,
			    struct ace_condition_script *program)
{
	size_t i;
	size_t depth = 0;
	char stack[] = "          ";
	char line[120];
	struct sddl_write_context ctx = {
		.mem_ctx = mem_ctx
	};

	for (i = 0; i < program->length; i++) {
		struct ace_condition_token *tok = &program->tokens[i];
		struct sddl_data s = sddl_strings[tok->type];
		char *utf8 = NULL;
		int utf8_len;
		char type;
		char nom[40];
		snprintf(nom, sizeof(nom), "\033[1;33m%20s\033[0m", s.name);
		switch (tok->type) {
		case CONDITIONAL_ACE_TOKEN_INT8:
		case CONDITIONAL_ACE_TOKEN_INT16:
		case CONDITIONAL_ACE_TOKEN_INT32:
		case CONDITIONAL_ACE_TOKEN_INT64:
			if (tok->data.int64.sign > 3 ||
			    tok->data.int64.base > 3) {
				goto error;
			}
			snprintf(line, sizeof(line),
				 "%s  %"PRIi64" %c%c\n",
				 nom,
				 tok->data.int64.value,
				 "?+-_"[tok->data.int64.sign],
				 "?odh"[tok->data.int64.base]
				);
			type = 'i';
			break;

		case CONDITIONAL_ACE_TOKEN_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF_ANY:
			snprintf(line, sizeof(line),
				 "%s  bool\n",
				 nom
				);
			type = 'b';
			break;

		case CONDITIONAL_ACE_TOKEN_EQUAL:
		case CONDITIONAL_ACE_TOKEN_NOT_EQUAL:
		case CONDITIONAL_ACE_TOKEN_LESS_THAN:
		case CONDITIONAL_ACE_TOKEN_LESS_OR_EQUAL:
		case CONDITIONAL_ACE_TOKEN_GREATER_THAN:
		case CONDITIONAL_ACE_TOKEN_GREATER_OR_EQUAL:
		case CONDITIONAL_ACE_TOKEN_CONTAINS:
		case CONDITIONAL_ACE_TOKEN_ANY_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_CONTAINS:
		case CONDITIONAL_ACE_TOKEN_NOT_ANY_OF:
		case CONDITIONAL_ACE_TOKEN_AND:
		case CONDITIONAL_ACE_TOKEN_OR:
			snprintf(line, sizeof(line),
				 "%s  bool\n",
				 nom
				);
			type = 'b';
			break;

		case CONDITIONAL_ACE_TOKEN_EXISTS:
		case CONDITIONAL_ACE_TOKEN_NOT_EXISTS:
		case CONDITIONAL_ACE_TOKEN_NOT:
			snprintf(line, sizeof(line),
				 "%s  bool\n",
				 nom
				);
			type = 'b';
			break;

		case CONDITIONAL_ACE_LOCAL_ATTRIBUTE:
		case CONDITIONAL_ACE_USER_ATTRIBUTE:
		case CONDITIONAL_ACE_RESOURCE_ATTRIBUTE:
		case CONDITIONAL_ACE_DEVICE_ATTRIBUTE:
			snprintf(line, sizeof(line),
				 "%s.%s  (any type)\n",
				 nom,
				 tok->data.unicode.value
				);
			type = '?';
			break;

		case CONDITIONAL_ACE_TOKEN_UNICODE:
			snprintf(line, sizeof(line),
				 "%s.%s  (any type)\n",
				 nom,
				 tok->data.unicode.value
				);
			type = 'u';
			break;

		case CONDITIONAL_ACE_TOKEN_OCTET_STRING: {
			char hex[21];
			utf8_len = MIN(tok->data.bytes.length, 9);
			hex_encode_buf(hex, tok->data.bytes.data, utf8_len);

			snprintf(line, sizeof(line),
				 "%s %.*s (%d)\n",
				 nom, utf8_len * 2, hex, utf8_len);
			type = 'o';
			break;
		}
		case CONDITIONAL_ACE_TOKEN_SID:
			utf8 = sddl_encode_sid(mem_ctx,
					       &tok->data.sid.sid,
					       NULL);
			snprintf(line, sizeof(line),
				 "%s (%s)\n",
				 nom, utf8);
			type = 'S';
			break;
		case CONDITIONAL_ACE_TOKEN_COMPOSITE:
			snprintf(line, sizeof(line),
				 "%s %"PRIu32" direct members\n",
				 nom, tok->data.composite.n_members);
			type = 'C';
			break;

		case CONDITIONAL_ACE_TOKEN_INVALID_OR_PADDING:
			snprintf(line, sizeof(line),
				 "%s\n", nom);
			type = '0';
			break;
		default:
			snprintf(line, sizeof(line),
				 "unknown opcode %#02x\n", tok->type);
			type = '!';
			break;
		}

		if (s.nargs > depth) {
			snprintf(nom, sizeof(nom),
				 "UNDER: -%zu", s.nargs - depth);
			depth = 0;
			sddl_write(&ctx, nom);
		} else if (depth >= strlen(stack)) {
			snprintf(nom, sizeof(nom),
				 "depth %zu", s.nargs - depth);
			depth -= (s.nargs - 1);
			sddl_write(&ctx, nom);
		} else {
			depth -= s.nargs;
			stack[depth] = type;
			depth++;
			if (depth < strlen(stack)) {
				stack[depth] = ' ';
			}
			sddl_write(&ctx, stack);
		}
		sddl_write(&ctx, line);
	}
	if (depth == 1 && stack[0] == 'b') {
		snprintf(line, sizeof(line),
			 "\033[1;32mGOOD: finishes on a single bool\033[0m\n");
	} else {
		snprintf(line, sizeof(line),
			 "\033[1;31mBAD: should finish with a bool\033[0m\n");
	}
	sddl_write(&ctx, line);
	return ctx.sddl;

  error:
	TALLOC_FREE(ctx.sddl);
	return NULL;
}


struct sddl_node {
	struct ace_condition_token *tok;
	struct sddl_node *lhs;
	struct sddl_node *rhs;
	bool wants_parens;
};

static bool sddl_write_int(struct sddl_write_context *ctx,
			   const struct ace_condition_token *tok)
{
	int64_t v = tok->data.int64.value;
	uint8_t sign = tok->data.int64.sign;
	uint8_t base = tok->data.int64.base;
	char buf[26]; /* oct(1<<63) + sign + \0 */
	char sign_char;
	if (sign > CONDITIONAL_ACE_INT_SIGN_NONE ||
	    base > CONDITIONAL_ACE_INT_BASE_16) {
		return false;
	}

	/*
	 * we have 9 combinations of base/sign (+ some invalid combinations of
	 * actual sign vs claimed sign).
	 */
	if (sign == CONDITIONAL_ACE_INT_SIGN_NONE) {
		/* octal and hex will end up unsigned! */
		if (base == CONDITIONAL_ACE_INT_BASE_8) {
			snprintf(buf, sizeof(buf), "0%"PRIo64, v);
		} else if (base == CONDITIONAL_ACE_INT_BASE_10) {
			snprintf(buf, sizeof(buf), "%"PRId64, v);
		} else {
			snprintf(buf, sizeof(buf), "0x%"PRIx64, v);
		}
		return sddl_write(ctx, buf);
	}
	if (sign == CONDITIONAL_ACE_INT_SIGN_POSITIVE && v < 0) {
		return false;
	}
	if (sign == CONDITIONAL_ACE_INT_SIGN_NEGATIVE && v > 0) {
		/* note we allow "-0", because we will parse it. */
		return false;
	}
	sign_char = (sign == CONDITIONAL_ACE_INT_SIGN_NEGATIVE) ? '-' : '+';
	/*
	 * We can use "%+ld" for the decimal sign (except -0), but
	 * "%+lx" and "%+lo" are invalid because %o and %x are
	 * unsigned.
	 */
	if (base == CONDITIONAL_ACE_INT_BASE_10) {
		if (v == 0) {
			snprintf(buf, sizeof(buf), "%c0", sign_char);
		} else {
			snprintf(buf, sizeof(buf), "%+"PRId64, v);
		}
		return sddl_write(ctx, buf);
	}

	if (v == INT64_MIN) {
		/*
		 * llabs(INT64_MIN) will be undefined.
		 * The lengths we must go to to round trip!
		 */
		if (base == CONDITIONAL_ACE_INT_BASE_8) {
			return sddl_write(ctx, "-01000000000000000000000");
		}
		return sddl_write(ctx, "-0x8000000000000000");
	}

	if (base == CONDITIONAL_ACE_INT_BASE_8) {
		snprintf(buf, sizeof(buf), "%c0%llo", sign_char, llabs(v));
	} else {
		snprintf(buf, sizeof(buf), "%c0x%llx", sign_char, llabs(v));
	}
	return sddl_write(ctx, buf);
}


static bool sddl_should_escape_utf16(uint16_t c)
{
	if (c <= ' ' || c > 126) {
		return true;
	}

	switch (c) {
	case '!':
	case '"':
	case '&':
	case '(':
	case ')':
	case '<':
	case '=':
	case '>':
	case '|':
	case '%':
		return true;
	}

	return false;
}

static bool sddl_encode_attr_name(TALLOC_CTX *mem_ctx,
				  const char *src,
				  char **dest,
				  size_t *dest_len)
{
	size_t i, j;
	bool ok;
	uint16_t *utf16 = NULL;
	char *escaped = NULL;
	size_t utf16_byte_len;
	size_t utf16_len;
	size_t src_len = strlen(src);
	size_t escapees;
	size_t required;
	*dest = NULL;

	/*
	 * Writing the string escapes can only really happen in
	 * utf-16.
	 */
	ok = convert_string_talloc(mem_ctx,
				   CH_UTF8, CH_UTF16LE,
				   src, src_len,
				   &utf16, &utf16_byte_len);
	if (!ok) {
		return false;
	}
	utf16_len = utf16_byte_len / 2;

	escapees = 0;
	for (i = 0; i < utf16_len; i++) {
		uint16_t c = utf16[i];
		if (sddl_should_escape_utf16(c)) {
			escapees++;
		}
		if (c == 0) {
			/* we can't have '\0' (or "%0000") in a name. */
			TALLOC_FREE(utf16);
			return false;
		}
	}

	required = src_len + escapees * 5;
	escaped = talloc_size(mem_ctx, required + 1);
	if (escaped == NULL) {
		TALLOC_FREE(utf16);
		return false;
	}

	if (escapees == 0) {
		/* there is nothing to escape: the original string is fine */
		memcpy(escaped, src, src_len);
		escaped[src_len] = '\0';
		*dest = escaped;
		*dest_len = src_len;
		TALLOC_FREE(utf16);
		return true;
	}

	for (i = 0, j = 0; i < utf16_len && j < required; i++) {
		uint16_t c = utf16[i];
		if (sddl_should_escape_utf16(c)) {
			if (j + 5 >= required) {
				TALLOC_FREE(escaped);
				TALLOC_FREE(utf16);
				return false;
			}
			snprintf(escaped + j, 6, "%%%04x", c);
			j += 5;
		} else {
			escaped[j] = c;
			j++;
		}
	}
	escaped[j] = '\0';

	*dest = escaped;
	*dest_len = j;

	TALLOC_FREE(utf16);
	return true;
}

static bool sddl_write_attr(struct sddl_write_context *ctx,
			    struct ace_condition_token *tok)
{
	char *name = NULL;
	size_t name_len;
	size_t i;
	bool ok = sddl_encode_attr_name(ctx->mem_ctx,
					tok->data.local_attr.value,
					&name, &name_len);
	if (!ok) {
		return false;
	}
	for (i = 0; i < ARRAY_SIZE(sddl_attr_types); i++) {
		struct sddl_attr_type x = sddl_attr_types[i];
		if (x.code == tok->type) {
			ok = sddl_write(ctx, "@");
			if (! ok) {
				return false;
			}
			ok = sddl_write(ctx, x.name);
			if (! ok) {
				return false;
			}
			break;
		}
	}

	ok = sddl_write(ctx, name);
	talloc_free(name);
	return ok;
}


static bool sddl_write_unicode(struct sddl_write_context *ctx,
			       const struct ace_condition_token *tok)
{
	char *quoted = NULL;
	bool ok;
	/*
	 * We rely on tok->data.unicode.value being
	 * nul-terminated.
	 */
	if (strchr(tok->data.unicode.value, '"') != NULL) {
		/*
		 * There is a double quote in this string, but SDDL
		 * has no mechanism for escaping these (or anything
		 * else) in unicode strings.
		 *
		 * The only thing to do is fail.
		 *
		 * This cannot happen with an ACE created from SDDL,
		 * because the same no-escapes rule applies on the way
		 * in.
		 */
		return false;
	}

	quoted = talloc_asprintf(ctx->mem_ctx, "\"%s\"",
				 tok->data.unicode.value);
	if (quoted == NULL) {
		return false;
	}
	ok = sddl_write(ctx, quoted);
	TALLOC_FREE(quoted);
	return ok;
}

static bool sddl_write_octet_string(struct sddl_write_context *ctx,
				    const struct ace_condition_token *tok)
{
	bool ok;
	char *hex  = hex_encode_talloc(ctx->mem_ctx,
				       tok->data.bytes.data,
				       tok->data.bytes.length);
	ok = sddl_write(ctx, "#");
	if (!ok) {
		return false;
	}
	ok = sddl_write(ctx, hex);
	talloc_free(hex);
	return ok;
}

/*
 * For octet strings, the Resource attribute ACE SDDL differs from conditional
 * ACE SDDL, lacking the leading '#'.
 */
static bool sddl_write_ra_octet_string(struct sddl_write_context *ctx,
				       const struct ace_condition_token *tok)
{
	bool ok;
	char *hex  = hex_encode_talloc(ctx->mem_ctx,
				       tok->data.bytes.data,
				       tok->data.bytes.length);
	ok = sddl_write(ctx, hex);
	talloc_free(hex);
	return ok;
}


static bool sddl_write_sid(struct sddl_write_context *ctx,
			   const struct ace_condition_token *tok)
{
	bool ok;
	char *sddl = NULL;
	char *sid = sddl_encode_sid(ctx->mem_ctx,
				    &tok->data.sid.sid,
				    NULL);
	if (sid == NULL) {
		return false;
	}
	sddl = talloc_asprintf(ctx->mem_ctx, "SID(%s)", sid);
	if (sddl == NULL) {
		talloc_free(sid);
		return false;
	}
	ok = sddl_write(ctx, sddl);
	talloc_free(sid);
	talloc_free(sddl);
	return ok;
}

static bool sddl_write_composite(struct sddl_write_context *ctx,
				 struct ace_condition_token *tok)
{
	/*
	 * Looks like {1, 2, 3, "four", {"woah, nesting", {6}}, SID(BA)}.
	 */
	struct ace_condition_composite *c = &tok->data.composite;
	uint32_t i;
	bool ok;
	ok = sddl_write(ctx, "{");
	if (!ok) {
		return false;
	}
	for (i = 0;  i < c->n_members; i++) {
		struct ace_condition_token *t = &c->tokens[i];
		if (i > 0) {
			ok = sddl_write(ctx, ", ");
			if (!ok) {
				return false;
			}
		}
		switch (t->type) {
		case CONDITIONAL_ACE_TOKEN_INT8:
		case CONDITIONAL_ACE_TOKEN_INT16:
		case CONDITIONAL_ACE_TOKEN_INT32:
		case CONDITIONAL_ACE_TOKEN_INT64:
			ok = sddl_write_int(ctx, t);
			break;
		case CONDITIONAL_ACE_TOKEN_UNICODE:
			ok = sddl_write_unicode(ctx, t);
			break;
		case CONDITIONAL_ACE_TOKEN_OCTET_STRING:
			ok = sddl_write_octet_string(ctx, t);
			break;
		case CONDITIONAL_ACE_TOKEN_SID:
			ok = sddl_write_sid(ctx, t);
			break;
		case CONDITIONAL_ACE_TOKEN_COMPOSITE:
			return false;
		default:
			return false;
		}
		if (!ok) {
			return false;
		}
	}
	ok = sddl_write(ctx, "}");
	return ok;
}

static bool sddl_write_node(struct sddl_write_context *ctx,
			    struct sddl_node *node)
{
	struct ace_condition_token *tok = node->tok;
	switch (tok->type) {
		case CONDITIONAL_ACE_TOKEN_INT8:
		case CONDITIONAL_ACE_TOKEN_INT16:
		case CONDITIONAL_ACE_TOKEN_INT32:
		case CONDITIONAL_ACE_TOKEN_INT64:
			return sddl_write_int(ctx, tok);

		case CONDITIONAL_ACE_TOKEN_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_EQUAL:
		case CONDITIONAL_ACE_TOKEN_NOT_EQUAL:
		case CONDITIONAL_ACE_TOKEN_LESS_THAN:
		case CONDITIONAL_ACE_TOKEN_LESS_OR_EQUAL:
		case CONDITIONAL_ACE_TOKEN_GREATER_THAN:
		case CONDITIONAL_ACE_TOKEN_GREATER_OR_EQUAL:
		case CONDITIONAL_ACE_TOKEN_CONTAINS:
		case CONDITIONAL_ACE_TOKEN_ANY_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_CONTAINS:
		case CONDITIONAL_ACE_TOKEN_NOT_ANY_OF:
		case CONDITIONAL_ACE_TOKEN_AND:
		case CONDITIONAL_ACE_TOKEN_OR:
		case CONDITIONAL_ACE_TOKEN_EXISTS:
		case CONDITIONAL_ACE_TOKEN_NOT_EXISTS:
		case CONDITIONAL_ACE_TOKEN_NOT:
			return sddl_write(ctx, sddl_strings[tok->type].name);

		case CONDITIONAL_ACE_LOCAL_ATTRIBUTE:
		case CONDITIONAL_ACE_USER_ATTRIBUTE:
		case CONDITIONAL_ACE_RESOURCE_ATTRIBUTE:
		case CONDITIONAL_ACE_DEVICE_ATTRIBUTE:
			return sddl_write_attr(ctx, tok);

		case CONDITIONAL_ACE_TOKEN_UNICODE:
			return sddl_write_unicode(ctx, tok);

		case CONDITIONAL_ACE_TOKEN_OCTET_STRING:
			return sddl_write_octet_string(ctx, tok);

		case CONDITIONAL_ACE_TOKEN_SID:
			return sddl_write_sid(ctx, tok);

		case CONDITIONAL_ACE_TOKEN_COMPOSITE:
			return sddl_write_composite(ctx, tok);

		case CONDITIONAL_ACE_TOKEN_INVALID_OR_PADDING:
			/*
			 * This is only expected at the very end, which we
			 * can't (and don't need to) check here, but we can at
			 * least ensure it's the end of a sub-expression.
			 */
			return (node->rhs == NULL);
		default:
			return false;
		}
	/* not expecting to get here */
	return false;
}


static inline bool sddl_wants_outer_parens(struct sddl_node *node)
{
	/*
	 * Binary ops (having a LHS) are always parenthesised "(a == 2)"
	 *
	 * Member-of ops are too, for some reason.
	 */
	return (node->lhs != NULL ||
		node->tok->type == CONDITIONAL_ACE_TOKEN_MEMBER_OF ||
		node->tok->type == CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF ||
		node->tok->type == CONDITIONAL_ACE_TOKEN_MEMBER_OF_ANY ||
		node->tok->type == CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF_ANY ||
		node->tok->type == CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF ||
		node->tok->type == CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF ||
		node->tok->type == CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF_ANY ||
		node->tok->type == CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF_ANY);
}


static inline bool sddl_wants_inner_parens(struct sddl_node *node,
					   struct sddl_node *child)
{
	/*
	 * logical operators are serialised with parentheses around their
	 * arguments (for NOT it is obligatory).
	 */
	if (node->tok->type != CONDITIONAL_ACE_TOKEN_NOT &&
	    node->tok->type != CONDITIONAL_ACE_TOKEN_AND &&
	    node->tok->type != CONDITIONAL_ACE_TOKEN_OR) {
		return false;
	}
	if (sddl_wants_outer_parens(child)) {
		return false;
	}
	return true;
}


static void sddl_tree_resolve_parens(struct sddl_node *node)
{
	if (sddl_wants_outer_parens(node)) {
		node->wants_parens = true;
	}
	if (node->lhs != NULL) {
		bool p = sddl_wants_inner_parens(node, node->lhs);
		node->lhs->wants_parens = p;
		sddl_tree_resolve_parens(node->lhs);
	}
	if (node->rhs != NULL) {
		bool p = sddl_wants_inner_parens(node, node->rhs);
		node->rhs->wants_parens = p;
		sddl_tree_resolve_parens(node->rhs);
	}
}

static bool sddl_tree_to_sddl(struct sddl_write_context *ctx,
			      struct sddl_node *node)
{
	bool ok;
	if (node->wants_parens) {
		ok = sddl_write(ctx, "(");
		if (! ok) {
			return false;
		}
	}

	if (node->lhs != NULL) {
		ok = sddl_tree_to_sddl(ctx, node->lhs);
		if (! ok) {
			return false;
		}
		ok = sddl_write(ctx, " ");
		if (!ok) {
			return false;
		}
	}

	ok = sddl_write_node(ctx, node);
	if (!ok) {
		return false;
	}
	if (node->rhs != NULL) {
		/* NOT is a special case: "!(x)", not "! (x)" */
		if (node->tok->type != CONDITIONAL_ACE_TOKEN_NOT) {
			ok = sddl_write(ctx, " ");
			if (!ok) {
				return false;
			}
		}

		ok = sddl_tree_to_sddl(ctx, node->rhs);
		if (! ok) {
			return false;
		}
	}
	if (node->wants_parens) {
		ok = sddl_write(ctx, ")");
		if (!ok) {
			return false;
		}
	}
	return true;
}

/*
 * Convert conditional ACE conditions into SDDL conditions.
 *
 * @param mem_ctx
 * @param program
 * @return a string or NULL on error.
 */
char *sddl_from_conditional_ace(TALLOC_CTX *mem_ctx,
				struct ace_condition_script *program)
{
	size_t i;
	char *sddl = NULL;
	struct sddl_node *nodes = NULL;
	struct sddl_node **trees = NULL;
	size_t n_trees = 0;
	struct ace_condition_token *tok = NULL;
	struct sddl_data s;
	bool ok;
	struct sddl_write_context ctx = {
		.mem_ctx = mem_ctx
	};

	if (program->length == 0) {
		/*
		 * The empty program is a special case.
		 */
		return talloc_strdup(mem_ctx, "()");
	}
	nodes = talloc_zero_array(mem_ctx,
				  struct sddl_node,
				  program->length);
	if (nodes == NULL) {
		talloc_free(sddl);
		return NULL;
	}
	trees = talloc_array(mem_ctx,
			     struct sddl_node*,
			     program->length);
	if (trees == NULL) {
		talloc_free(sddl);
		talloc_free(nodes);
		return NULL;
	}

	/*
	 * This loop constructs a tree, which we then traverse to get the
	 * SDDL. Consider this transformation:
	 *
	 * {A, B, ==, C, D, ==, &&}  =>  "((A == B) && (C == D))"
	 *
	 * We keep an array of sub-trees, and add to it in sequence. When the
	 * thing we're adding takes arguments, we pop those off the tree list.
	 * So it would go through this sequence:
	 *
	 * len  items
	 * 1:     A
	 * 2:     A, B
	 * 1:     ==(A, B)
	 * 2:     ==(A, B), C
	 * 3:     ==(A, B), C, D
	 * 2:     ==(A, B), ==(C, D)
	 * 1      &&(==(A, B), ==(C, D))
	 *
	 * Without building a tree it would be difficult to know how many
	 * parentheses to put before A.
	 *
	 * (A == B == C) should become
	 * {A B == C ==} which should be the same as
	 * ((A == B) == C)
	 */

	for (i = 0; i < program->length; i++) {
		tok = &program->tokens[i];
		s = sddl_strings[tok->type];
		nodes[i].tok = tok;
		if (s.nargs > n_trees) {
			goto error;
		}
		if (s.nargs >= 1) {
			/*
			 * Read this note if you're trying to follow
			 * [MS-DTYP]. MS-DTYP uses 'LHS' to describe the
			 * operand of unary operators even though they are
			 * always displayed on the right of the operator. It
			 * makes everything much simpler to use rhs
			 * instead.
			 */
			n_trees--;
			nodes[i].rhs = trees[n_trees];

			if (s.nargs == 2) {
				n_trees--;
				nodes[i].lhs = trees[n_trees];
			}
		}
		trees[n_trees] = &nodes[i];
		n_trees++;
	}

	if (n_trees != 1) {
		goto error;
	}

	/*
	 * First we walk the tree to work out where to put parentheses (to
	 * match the canonical Windows representation).
	 *
	 * Doing it in the same traverse as the writing would be possible but
	 * trickier to get right.
	 */
	sddl_tree_resolve_parens(trees[0]);
	trees[0]->wants_parens = true;

	/*
	 * Clamber over the tree, writing the string.
	 */
	ok = sddl_tree_to_sddl(&ctx, trees[0]);

	if (! ok) {
		goto error;
	}

	talloc_free(trees);
	talloc_free(nodes);
	return ctx.sddl;

  error:
	talloc_free(sddl);
	talloc_free(trees);
	talloc_free(nodes);
	return NULL;
}



static void comp_error(struct ace_condition_sddl_compiler_context *comp,
		       const char *fmt, ...) PRINTF_ATTRIBUTE(2,3);

static void comp_error(struct ace_condition_sddl_compiler_context *comp,
		       const char *fmt, ...)
{
	char *msg = NULL;
	va_list ap;
	va_start(ap, fmt);
	msg = talloc_vasprintf(comp->mem_ctx, fmt, ap);
	va_end(ap);
	if (msg == NULL) {
		goto fail;
	}

	if (comp->message == NULL) {
		/*
		 * Previously unset message; prepend the position.
		 *
		 * This is the common case.
		 */
		comp->message_offset = comp->offset;
		comp->message = msg;
		return;
	}
	/*
	 * There's a message already so we'll try to append.
	 * This is unlikely to happen.
	 */
	comp->message = talloc_asprintf(comp->mem_ctx,
					"%s AND THEN %s",
					comp->message,
					msg);
	TALLOC_FREE(msg);
	if (comp->message == NULL) {
		goto fail;
	}
	DBG_NOTICE("%s\n", comp->message);
	return;
fail:
	comp->message = talloc_strdup(comp->mem_ctx,
				      "failed to set error message");
	DBG_WARNING("%s\n", comp->message);
}




/*
conditional-ace = "(" conditional-ace-type ";" [ace-flag-string] ";" ace-rights
";" [object- guid] ";" [inherit-object-guid] ";" sid-string ";" "(" cond-expr
")" ")"

wspace = 1*(%x09-0D / %x20)

literal-SID = "SID(" sid-string ")"

term = [wspace] (memberof-op / exists-op / rel-op / contains-op / anyof-op /
attr-name / rel- op2) [wspace]

cond-expr = term / term [wspace] ("||" / "&&" ) [wspace] cond-expr / (["!"]
[wspace] "(" cond-expr ")")

memberof-op = ( "Member_of" / "Not_Member_of" / "Member_of_Any" /
"Not_Member_of_Any" / "Device_Member_of" / "Device_Member_of_Any" /
"Not_Device_Member_of" / "Not_Device_Member_of_Any" ) wspace sid-array

exists-op = ( "Exists" / "Not_Exists") wspace attr-name

rel-op = attr-name [wspace] ("<" / "<=" / ">" / ">=") [wspace] (attr-name2 /
value) ; only scalars

rel-op2 = attr-name [wspace] ("==" / "!=") [wspace] ( attr-name2 / value-array )
; scalar or list

contains-op = attr-name wspace ("Contains" / "Not_Contains") wspace (attr-name2
/ value- array)

anyof-op = attr-name wspace ("Any_of" / "Not_Any_of") wspace (attr-name2 /
value-array)


attr-name1 = attr-char1 *(attr-char1 / "@")

attr-char1 = 1*(ALPHA / DIGIT / ":" / "." / "/" / "_")



attr-name2 = ("@user." / "@device." / "@resource.") 1*attr-char2
; new prefixed name form
attr-char2 = attr-char1 / lit-char
attr-name = attr-name1 / attr-name2
 */



static inline bool is_wspace(uint8_t c)
{
	/* wspace := %x09-0D | %x20 */
	return (c == ' ' || c == '\x09' || c == '\x0A' ||
		c == '\x0B' || c == '\x0C' || c == '\x0D');
}

static inline bool is_attr_char1(uint8_t c)
{
	/*
	 * attr-char1 = 1*(ALPHA / DIGIT / ":" / "." / "/" / "_")
	 * (ALPHA and DIGIT being ASCII only).
	 *
	 * These are used for local attributes, which we don't really
	 * expect to see in Samba AD.
	 *
	 * One example is "WIN://SYSAPPID", which is used in conditional ACEs
	 * that seem to relate to software installers; another is
	 * "APPID://PATH", used by Windows Applocker.
	 */
	return (((c >= 'a') && (c <= 'z')) ||
		((c >= 'A') && (c <= 'Z')) ||
		((c >= '0') && (c <= '9')) ||
		c == ':' || c == '.' || c == '/' || c == '_');
}


static ssize_t read_attr2_string(
	struct ace_condition_sddl_compiler_context *comp,
	struct ace_condition_unicode *dest)
{
	/*
	 * our SDDL is utf-8, but we need to convert to utf-16 and
	 * parse the escapes, then back to utf-8, because that's how
	 * the claims will appear.
	 *
	 * attr_char2 is used for attribute names that follow "@Class."
	 * specifiers. They can consume 5 characters to specify a single code
	 * unit, using "%1234" style escapes. Certain characters must be
	 * encoded this way, while others must be literal values. Because the
	 * %1234 refers to a utf-16 code unit, we really need to do the work
	 * in that codespace.
	 */
	bool ok;
	uint16_t *utf16 = NULL;
	size_t utf16_byte_len;
	size_t utf16_chars;
	size_t utf8_len;
	size_t src_len;
	ssize_t i, j;
	ssize_t max_len = comp->length - comp->offset;
	const uint8_t *src = comp->sddl + comp->offset;

	for (i = 0; i < max_len; i++) {
		uint8_t c = src[i];
		/*
		 * A double‐byte that must be escaped but isn't tells us that
		 * the attribute name has ended.
		 *
		 * The exception is '%', which must also be escaped
		 * (as "%0025"), but is obviously still expected in
		 * the escaped string.
		 */
		if (strchr("!&()><=| \"", c) != NULL || is_wspace(c)) {
			break;
		}
	}
	if (i == max_len) {
		/* too long, because we need at least one ')' */
		comp_error(comp, "interminable attribute name");
		return -1;
	}
	if (i == 0) {
		/* too short! like "User.>= 4" */
		comp_error(comp, "empty attribute name");
		return -1;
	}

	if (unlikely(i > CONDITIONAL_ACE_MAX_LENGTH)) {
		/*
		 * This is imprecise; the limit for the whole ACL is 64k.
		 * However there could be many escapes in the SDDL name which
		 * would reduce down to single utf16 code units in the
		 * compiled string.
		 */
		comp_error(comp, "attribute is way too long (%zu)", i);
		return -1;
	}

	src_len = i;

	ok = convert_string_talloc(comp->mem_ctx,
				   CH_UTF8, CH_UTF16LE,
				   src, src_len,
				   &utf16, &utf16_byte_len);
	if (!ok) {
		comp_error(comp, "could not convert to utf-16");
		return -1;
	}
	/*
	 * utf16_byte_len is in bytes, we want to count uint16s.
	 */
	utf16_chars = utf16_byte_len / 2;

	/* now the escapes. */
	for (i = 0, j = 0;
	     j < utf16_chars && i < utf16_chars;
	     j++) {
		uint16_t c = utf16[i];
		if (c == '%') {
			uint16_t v = 0;
			size_t end = i + 5;
			/*
			 * we need to read 4 hex characters.
			 * hex_byte() won't help because that is 8-bit.
			 */
			if (end > utf16_chars) {
				comp_error(comp,
					   "insufficient room for %% escape");
				talloc_free(utf16);
				return -1;
			}
			for (i++; i < end; i++) {
				v <<= 4;
				c = utf16[i];
				if (c >= '0' && c <= '9') {
					v += c - '0';
				} else if (c >= 'A' && c <= 'F') {
					v += c - 'A' + 10;
				} else if (c >= 'a' && c <= 'f') {
					v += c - 'a' + 10;
				} else {
					comp_error(comp, "invalid %% escape");
					talloc_free(utf16);
					return -1;
				}
			}
			/*
			 * from MS-DTYP 2.5.1.1 Syntax (text, not ABNF), some
			 * characters must be literals, not escaped.
			 */
			if ((v >= '0' && v <= '9') ||
			    (v >= 'A' && v <= 'Z') ||
			    (v >= 'a' && v <= 'z') ||
			    (v < 127 &&
			     strchr("#$'*+-;?@[\\]^_`{}~:/.", v) != NULL)) {
				comp_error(comp, "invalid %% escape: "
					   "'%%%04x' should be literal '%c'",
					   v, v);
				talloc_free(utf16);
				return -1;
			}
			utf16[j] = v;
			continue;
		}
		/*
		 * Note the characters "!&()><=|% \"" must be escaped per
		 * [MS-DTYP], but as we found the bounds of this string using
		 * those in utf-8 at the top of this function, we are not
		 * going to find them in the utf-16 now.
		 *
		 * Also, per [MS-DTYP], un-escaped whitespace is allowed, but
		 * effectively disallowed by Samba.
		 */
		utf16[j] = utf16[i];
		i++;
	}

	ok = convert_string_talloc(comp->mem_ctx,
				   CH_UTF16LE, CH_UTF8,
				   utf16, j * 2,
				   &dest->value, &utf8_len);
	TALLOC_FREE(utf16);
	if (!ok) {
		comp_error(comp, "could not convert to utf-16");
		return -1;
	}

	/* returning bytes consumed, not necessarily the length of token */
	return src_len;
}



static bool eat_whitespace(struct ace_condition_sddl_compiler_context *comp,
			   bool trailing)
{
	/*
	 * Advance the offset to the first non-whitespace character.
	 *
	 * If trailing is false, there has to be something before the end of
	 * the string.
	 */
	while (comp->offset < comp->length) {
		if (! is_wspace(comp->sddl[comp->offset])) {
			break;
		}
		comp->offset++;
	}
	if ((!trailing) && comp->offset == comp->length) {
		comp_error(comp, "input ends unexpectedly");
		return false;
	}
	return true;
}

static bool pop_sddl_token(struct ace_condition_sddl_compiler_context *comp,
			   struct ace_condition_token *token);

static bool write_sddl_token(struct ace_condition_sddl_compiler_context *comp,
			     struct ace_condition_token token);

static bool pop_write_sddl_token(
	struct ace_condition_sddl_compiler_context *comp);


static bool flush_stack_tokens(struct ace_condition_sddl_compiler_context *comp,
			       uint8_t type)
{
	bool ok;
	uint8_t precedence = sddl_strings[type].op_precedence;
	if (precedence == SDDL_PRECEDENCE_PAREN_START) {
		/* paren has a special role */
		return true;
	}
	/*
	 * Any operators on the top of the stack that have a "higher"
	 * precedence (tighter binding) to this one get popped off and written
	 * to the output. "higher" is in quotes because it means lower enum
	 * value.
	 *
	 * This works for binary operators, for example, with "(a == b == c)"
	 * (which is equivalent to "((a == b) == c)" via the left-to-right
	 * rule), we have:
	 * TOKEN dest  PROGRAM            STACK
	 *   (
	 *   a    p
	 *   ==   s       a
	 *   b    p       a                ==
	 *   ==   s       a b              ==
	 *                                        flush stack
	 *        s->p    a b              == ==
	 *   c    p       a b ==
	 *   )            a b == c         ==
	 *                                        flush stack
	 *                a b == c ==
	 *
	 * but it is not right for unary operators, as in "(!(!(Exists
	 * a)))". As it turns out though, >= works for the unary
	 * operators and syntactic rules we have.
	 */
	while (comp->stack_depth > 0) {
		struct ace_condition_token *op =
			&comp->stack[comp->stack_depth - 1];
		if(sddl_strings[op->type].op_precedence > precedence) {
			break;
		}
		if(sddl_strings[op->type].op_precedence == precedence &&
		   sddl_strings[op->type].flags & SDDL_FLAG_IS_UNARY_OP) {
			break;
		}

		ok = pop_write_sddl_token(comp);
		if (! ok) {
			comp_error(comp,
				   "could not flush '%s' to program",
				   sddl_strings[op->type].name);
			return false;
		}
	}
	return true;
}

static bool push_sddl_token(struct ace_condition_sddl_compiler_context *comp,
			    struct ace_condition_token token)
{
	if (comp->stack_depth >= CONDITIONAL_ACE_MAX_TOKENS - 1) {
		comp_error(comp, "excessive recursion");
		return false;
	}
	if (sddl_strings[token.type].op_precedence == SDDL_NOT_AN_OP) {
		comp_error(comp,
			   "wrong kind of token for the SDDL stack: %s",
			   sddl_strings[token.type].name);
		return false;
	}
	/*
	 * Any operators on the top of the stack that have a "greater" or
	 * equal precedence to this one get popped off and written to the
	 * output.
	 */
	flush_stack_tokens(comp, token.type);

	token.data.op.sddl_position = comp->offset;

	comp->stack[comp->stack_depth] = token;
	comp->stack_depth++;
	if (token.type != CONDITIONAL_ACE_SAMBA_SDDL_PAREN) {
		comp->last_token_type = token.type;
	}
	return true;
}

static bool pop_sddl_token(struct ace_condition_sddl_compiler_context *comp,
			    struct ace_condition_token *token)
{
	if (comp->stack_depth == 0) {
		comp_error(comp, "misbalanced expression");
		return false;
	}
	comp->stack_depth--;
	*token = comp->stack[comp->stack_depth];
	return true;
}


static bool write_sddl_token(struct ace_condition_sddl_compiler_context *comp,
			     struct ace_condition_token token)
{
	/*
	 * This is adding a token to the program. Normally it will be to the
	 * main program list, but if we are constructing a composite list, then
	 * will be redirected there (via comp->target).
	 *
	 * We also conservatively track the overall size, so we don't waste
	 * time compiling something that is way too big.
	 */
	DBG_INFO("writing %"PRIu32" %x %s\n",
		 *comp->target_len,
		 token.type,
		 sddl_strings[token.type].name);
	comp->approx_size++;
	if (comp->approx_size > CONDITIONAL_ACE_MAX_TOKENS) {
		comp_error(comp, "program is too long "
			   "(over %d tokens)",
			   CONDITIONAL_ACE_MAX_TOKENS);
		return false;
	}
	if (token.type != CONDITIONAL_ACE_SAMBA_SDDL_PAREN) {
		comp->last_token_type = token.type;
	}
	comp->target[*comp->target_len] = token;
	(*comp->target_len)++;
	return true;
}

static bool pop_write_sddl_token(
	struct ace_condition_sddl_compiler_context *comp)
{
	bool ok;
	struct ace_condition_token token = {};
	ok = pop_sddl_token(comp, &token);
	if (!ok) {
		comp_error(comp, "could not pop from op stack");
		return false;
	}
	if (comp->target != comp->program->tokens) {
		comp_error(comp, "compiler is seriously confused");
		return false;
	}

	ok =  write_sddl_token(comp, token);
	if (!ok) {
		comp_error(comp,
			   "could not write '%s' to program",
			   sddl_strings[token.type].name);
		return false;
	}
	DBG_INFO("    written '%s'\n", sddl_strings[token.type].name);
	return true;
}



static bool parse_expression(struct ace_condition_sddl_compiler_context *comp);
static bool parse_composite(struct ace_condition_sddl_compiler_context *comp);




static bool parse_oppy_op(struct ace_condition_sddl_compiler_context *comp)
{
	/*
	 * These ones look like operators and are operators.
	 */
	bool ok;
	struct ace_condition_token token = {};
	uint8_t c, d;
	uint32_t flag = SDDL_FLAG_EXPECTING_BINARY_OP;

	if (comp->offset + 1 >= comp->length) {
		comp_error(comp, "syntax error");
		return false;
	}

	token.data.sddl_op.start = comp->offset;

	/*
	 * These are all one or two characters long, and we always have room
	 * to peek ahead.
	 */
	c = comp->sddl[comp->offset];
	d = comp->sddl[comp->offset + 1];

	if (c == '!') {
		if (d == '=') {
			comp->offset++;
			token.type = CONDITIONAL_ACE_TOKEN_NOT_EQUAL;

		} else {
			token.type = CONDITIONAL_ACE_TOKEN_NOT;
			flag = SDDL_FLAG_EXPECTING_UNARY_OP;
		}
	} else if (c == '=' && d == '=') {
		comp->offset++;
		token.type = CONDITIONAL_ACE_TOKEN_EQUAL;
	} else if (c == '>') {
		if (d == '=') {
			comp->offset++;
			token.type = CONDITIONAL_ACE_TOKEN_GREATER_OR_EQUAL;

		} else {
			token.type = CONDITIONAL_ACE_TOKEN_GREATER_THAN;
		}
	} else if (c == '<') {
		if (d == '=') {
			comp->offset++;
			token.type = CONDITIONAL_ACE_TOKEN_LESS_OR_EQUAL;

		} else {
			token.type = CONDITIONAL_ACE_TOKEN_LESS_THAN;
		}
	} else if (c == '&' && d == '&') {
		comp->offset++;
		token.type = CONDITIONAL_ACE_TOKEN_AND;
		flag = SDDL_FLAG_EXPECTING_BINARY_LOGIC_OP;
	} else if (c == '|' && d == '|') {
		comp->offset++;
		token.type = CONDITIONAL_ACE_TOKEN_OR;
		flag = SDDL_FLAG_EXPECTING_BINARY_LOGIC_OP;
	} else {
		comp_error(comp, "unknown operator");
		return false;
	}

	if ((comp->state & flag) == 0) {
		comp_error(comp, "unexpected operator");
		return false;
	}

	comp->offset++;

	ok = push_sddl_token(comp, token);
	if (!ok) {
		return false;
	}

	ok = eat_whitespace(comp, true);
	return ok;
}

static bool parse_unicode(struct ace_condition_sddl_compiler_context *comp)
{
	/*
	 * This looks like "hello" (including the double quotes).
	 *
	 * Fortunately (for now), there is no mechanism for escaping
	 * double quotes in conditional ace strings, so we can simply
	 * look for the second quote without worrying about things
	 * like «\\\"».
	 */
	struct ace_condition_token token = {};
	char *s = NULL;
	const uint8_t *src = NULL;
	char *utf16 = NULL;
	size_t len, max_len;
	bool ok;
	if (comp->sddl[comp->offset] != '"') {
		comp_error(comp, "was expecting '\"' for Unicode string");
		return false;
	}
	comp->offset++;
	src = comp->sddl + comp->offset;
	max_len = comp->length - comp->offset;
	/* strnchr */
	for (len = 0; len < max_len; len++) {
		if (src[len] == '"') {
			break;
		}
	}
	if (len == max_len) {
		comp_error(comp, "unterminated unicode string");
		return false;
	}

	/*
	 * Look, this is wasteful, but it probably doesn't matter. We want to
	 * check that the string we're putting into the descriptor is valid,
	 * or we'll see errors down the track.
	 */
	ok = convert_string_talloc(comp->mem_ctx,
				   CH_UTF8, CH_UTF16LE,
				   src, len,
				   &utf16, NULL);
	if (!ok) {
		comp_error(comp, "not valid unicode");
		return false;
	}
	TALLOC_FREE(utf16);

	s = talloc_array_size(comp->mem_ctx, 1, len + 1);
	if (s == NULL) {
		comp_error(comp, "allocation error");
		return false;
	}
	memcpy(s, src, len);
	s[len] = 0;
	comp->offset += len + 1;	/* +1 for the final quote */
	token.type = CONDITIONAL_ACE_TOKEN_UNICODE;
	token.data.unicode.value = s;

	return write_sddl_token(comp, token);
}


static bool parse_octet_string(struct ace_condition_sddl_compiler_context *comp)
{
	/*
	 * This looks like '#hhhh...', where each 'hh' is hex for a byte, with
	 * the weird and annoying complication that '#' can be used to mean
	 * '0'.
	 */
	struct ace_condition_token token = {};
	size_t length, i;

	if (comp->sddl[comp->offset] != '#') {
		comp_error(comp, "was expecting '#' for octet string");
		return false;
	}
	comp->offset++;
	length = strspn((const char*)(comp->sddl + comp->offset),
			"#0123456789abcdefABCDEF");

	if (length & 1) {
		comp_error(comp, "octet string has odd number of hex digits");
		return false;
	}

	length /= 2;

	token.data.bytes = data_blob_talloc_zero(comp->mem_ctx, length);
	token.type = CONDITIONAL_ACE_TOKEN_OCTET_STRING;

	for (i = 0; i < length; i++) {
		/*
		 * Why not just strhex_to_str()?
		 *
		 * Because we need to treat '#' as '0' in octet string values,
		 * so all of the following are the same
		 * (equaling {0x10, 0x20, 0x30, 0x0}).
		 *
		 *  #10203000
		 *  #10203###
		 *  #1#2#3###
		 *  #10203#00
		 */
		bool ok;
		char pair[2];
		size_t j = comp->offset + i * 2;
		pair[0] = (comp->sddl[j]     == '#') ? '0' : comp->sddl[j];
		pair[1] = (comp->sddl[j + 1] == '#') ? '0' : comp->sddl[j + 1];

		ok = hex_byte(pair, &token.data.bytes.data[i]);
		if (!ok) {
			talloc_free(token.data.bytes.data);
			comp_error(comp, "inexplicable error in octet string");
			return false;
		}
	}
	comp->offset += length * 2;
	return write_sddl_token(comp, token);
}


static bool parse_ra_octet_string(struct ace_condition_sddl_compiler_context *comp)
{
	/*
	 * Resource attribute octet strings resemble conditional ace octet
	 * strings, but have some important differences:
	 *
	 * 1. The '#' at the start is optional, and if present is
	 * counted as a zero.
	 *
	 * 2. An odd number of characters is implicitly left-padded with a zero.
	 *
	 * That is, "abc" means "0abc", "#12" means "0012", "f##"
	 * means "0f00", and "##" means 00.
	 */
	struct ace_condition_token token = {};
	size_t string_length, bytes_length, i, j;
	bool ok;
	char pair[2];

	string_length = strspn((const char*)(comp->sddl + comp->offset),
			"#0123456789abcdefABCDEF");

	bytes_length = (string_length + 1) / 2;

	if (bytes_length == 0) {
		comp_error(comp, "zero length octet bytes");
		return false;
	}

	token.data.bytes = data_blob_talloc_zero(comp->mem_ctx, bytes_length);
	if (token.data.bytes.data == NULL) {
		return false;
	}
	token.type = CONDITIONAL_ACE_TOKEN_OCTET_STRING;

	j = comp->offset;
	i = 0;
	if (string_length & 1) {
		/*
		 * An odd number of characters means the first
		 * character gains an implicit 0 for the high nybble.
		 */
		pair[0] = 0;
		pair[1] = (comp->sddl[0] == '#') ? '0' : comp->sddl[0];

		ok = hex_byte(pair, &token.data.bytes.data[i]);
		if (!ok) {
			goto fail;
		}
		j++;
		i++;
	}

	for (; i < bytes_length; i++) {
		/*
		 * Why not just strhex_to_str() ?
		 *
		 * Because we need to treat '#' as '0' in octet string values.
		 */
		if (comp->length - j < 2) {
			goto fail;
		}

		pair[0] = (comp->sddl[j]     == '#') ? '0' : comp->sddl[j];
		pair[1] = (comp->sddl[j + 1] == '#') ? '0' : comp->sddl[j + 1];

		ok = hex_byte(pair, &token.data.bytes.data[i]);
		if (!ok) {
			goto fail;
		}
		j += 2;
	}
	comp->offset = j;
	return write_sddl_token(comp, token);

fail:
	comp_error(comp, "inexplicable error in octet string");
	talloc_free(token.data.bytes.data);
	return false;
}


static bool parse_sid(struct ace_condition_sddl_compiler_context *comp)
{
	struct dom_sid *sid = NULL;
	const uint8_t *sidstr = NULL;
	struct ace_condition_token token = {};
	size_t end;
	if (comp->length - comp->offset < 7) {
		/* minimum: "SID(AA)" */
		comp_error(comp, "no room for a complete SID");
		return false;
	}
	/* conditional ACE SID string */
	if (comp->sddl[comp->offset    ] != 'S' ||
	    comp->sddl[comp->offset + 1] != 'I' ||
	    comp->sddl[comp->offset + 2] != 'D' ||
	    comp->sddl[comp->offset + 3] != '(') {
		comp_error(comp, "malformed SID() constructor");
		return false;
	}
	comp->offset += 4;

	sidstr = comp->sddl + comp->offset;

	sid = sddl_decode_sid(comp->mem_ctx,
			      (const char **)&sidstr,
			      comp->domain_sid);

	if (sid == NULL) {
		comp_error(comp, "could not parse SID");
		return false;
	}
	end = sidstr - comp->sddl;
	if (end >= comp->length || end < comp->offset) {
		comp_error(comp, "apparent overflow in SID parsing");
		return false;
	}
	comp->offset = end;
	/*
	 * offset is now at the end of the SID, but we need to account
	 * for the ')'.
	 */
	if (comp->sddl[comp->offset] != ')') {
		comp_error(comp, "expected ')' to follow SID");
		return false;
	}
	comp->offset++;

	token.type = CONDITIONAL_ACE_TOKEN_SID;
	token.data.sid.sid = *sid;
	return write_sddl_token(comp, token);
}



static bool parse_ra_sid(struct ace_condition_sddl_compiler_context *comp)
{
	struct dom_sid *sid = NULL;
	const uint8_t *sidstr = NULL;
	struct ace_condition_token token = {};
	size_t end;

	if ((comp->state & SDDL_FLAG_EXPECTING_LITERAL) == 0) {
		comp_error(comp, "did not expect a SID here");
		return false;
	}
	/*
	 *  Here we are parsing a resource attribute ACE which doesn't
	 *  have the SID() wrapper around the SID string (unlike a
	 *  conditional ACE).
	 *
	 * The resource ACE doesn't need this because there is no
	 * ambiguity with local attribute names, besides which the
	 * type has already been specified earlier in the ACE.
	 */
	if (comp->length - comp->offset < 2){
		comp_error(comp, "no room for a complete SID");
		return false;
	}

	sidstr = comp->sddl + comp->offset;

	sid = sddl_decode_sid(comp->mem_ctx,
			      (const char **)&sidstr,
			      comp->domain_sid);

	if (sid == NULL) {
		comp_error(comp, "could not parse SID");
		return false;
	}
	end = sidstr - comp->sddl;
	if (end >= comp->length || end < comp->offset) {
		comp_error(comp, "apparent overflow in SID parsing");
		return false;
	}
	comp->offset = end;
	token.type = CONDITIONAL_ACE_TOKEN_SID;
	token.data.sid.sid = *sid;
	return write_sddl_token(comp, token);
}


static bool parse_int(struct ace_condition_sddl_compiler_context *comp)
{
	/*
	 * This one is relatively simple. strtoll() does the work.
	 */
	long long v;
	struct ace_condition_token token = {};
	const char *start = (const char *)comp->sddl + comp->offset;
	char *end = NULL;
	const char *first_digit = start;
	size_t len;
	errno = 0;
	v = strtoll(start, &end, 0);
	if (errno != 0) {
		comp_error(comp, "bad integer: %s", strerror(errno));
		return false;
	}
	len = end - start;

	if (len == 0) {
		comp_error(comp, "unexpected non-integer");
		return false;
	}
	if (comp->offset + len > comp->length) {
		comp_error(comp, "impossible integer length: %zu!", len);
		return false;
	}

	comp->offset += len;

	/*
	 * Record the base and sign, which are used for recreating the SDDL.
	 *
	 * 'Sign' indicates whether there is a '+' or '-' sign. Base indicates
	 * whether the number was in hex, octal, or decimal. These make no
	 * difference to the evaluation of the ACE, just the display.
	 *
	 * This would not work reliably if eat_whitespace() is not called
	 * before parse_int(), but a) we know it is, and b) we don't *really*
	 * care if we lose these display hints.
	 */
	if (*start == '-') {
		token.data.int64.sign = CONDITIONAL_ACE_INT_SIGN_NEGATIVE;
		first_digit++;
	} else if (*start == '+') {
		token.data.int64.sign = CONDITIONAL_ACE_INT_SIGN_POSITIVE;
		first_digit++;
	} else {
		token.data.int64.sign = CONDITIONAL_ACE_INT_SIGN_NONE;
	}
	if (*first_digit == '0' && (end - first_digit) > 1) {
		if ((end - first_digit > 2) &&
		    (first_digit[1] == 'x' ||
		     first_digit[1] == 'X')) {
			token.data.int64.base = CONDITIONAL_ACE_INT_BASE_16;
		} else {
			token.data.int64.base = CONDITIONAL_ACE_INT_BASE_8;
		}
	} else {
		token.data.int64.base = CONDITIONAL_ACE_INT_BASE_10;
	}

	token.data.int64.value = v;
	token.type = CONDITIONAL_ACE_TOKEN_INT64;
	return write_sddl_token(comp, token);
}


static bool parse_uint(struct ace_condition_sddl_compiler_context *comp)
{
	struct ace_condition_token *tok = NULL;
	bool ok = parse_int(comp);
	if (ok == false) {
		return false;
	}
	/*
	 * check that the token's value is positive.
	 */
	if (comp->target_len == 0) {
		return false;
	}
	tok = &comp->target[*comp->target_len - 1];
	if (tok->type != CONDITIONAL_ACE_TOKEN_INT64) {
		return false;
	}
	if (tok->data.int64.value < 0) {
		comp_error(comp, "invalid resource ACE value for unsigned TU claim");
		return false;
	}
	return true;
}


static bool parse_bool(struct ace_condition_sddl_compiler_context *comp)
{
	struct ace_condition_token *tok = NULL;
	bool ok = parse_int(comp);
	if (ok == false || comp->target_len == 0) {
		return false;
	}
	/*
	 * check that the token is 0 or 1.
	 */
	tok = &comp->target[*comp->target_len - 1];
	if (tok->type != CONDITIONAL_ACE_TOKEN_INT64) {
		return false;
	}
	if (tok->data.int64.value != 0 && tok->data.int64.value != 1) {
		comp_error(comp, "invalid resource ACE Boolean value");
		return false;
	}
	return true;
}


static bool could_be_an_int(struct ace_condition_sddl_compiler_context *comp)
{
	const char *start = (const char*)(comp->sddl + comp->offset);
	char* end = NULL;

	if ((comp->state & SDDL_FLAG_EXPECTING_LITERAL) == 0) {
		return false;
	}

	errno = 0;
	/*
	 * See, we don't care about the strtoll return value, only
	 * whether it succeeds or not and what it finds at the end. If
	 * it succeeds, parse_int() will do it again for the value.
	 *
	 * Note that an out of range int will raise ERANGE (probably
	 * 34), so it will be read as a local attribute.
	 */
	strtoll(start, &end, 0);
	if (errno != 0 ||
	    end == start ||
	    end >= (const char*)comp->sddl + comp->length) {
		return false;
	}
	/*
	 * We know *some* characters form an int, but if we run right
	 * into other attr1 characters (basically, letters), we won't
	 * count it as an int.
	 *
	 * For example, the "17" in "17p" is not an int. The "17" in
	 * "17||" is.
	 */
	if (is_attr_char1(*end)) {
		return false;
	}
	return true;
}


static bool parse_word(struct ace_condition_sddl_compiler_context *comp)
{
	/*
	 * Sometimes a bare word must be a local attribute, while in other
	 * cases it could also be a member-of or exists operator. Sometimes it
	 * could actually be a SID, which we discover when we've read as far
	 * as "SID(". Sometimes it might be a literal integer (attribute
	 * names can also consist entirely of digits).
	 *
	 * When it is an operator name, we have the complication that a match
	 * does not necessarily end the token. Consider "Member_of_Any" which
	 * contains the operator "Member_of". According to [MS-DTYP], a space
	 * is not necessary between the operator and the next token, but it
	 * does seem to be required for Windows 2022.
	 *
	 * Also, "Member_of" et. al. *could* be valid local attributes, which
	 * would make "(Member_of == 123)" a valid expression that we will
	 * fail to parse. This is not much of an issue for Samba AD where
	 * local attributes are not used.
	 *
	 * Operators are matched case-insensitively.
	 *
	 * There's another kind of attribute that starts with a '@', which we
	 * deal with in parse_attr2(). Those ones have full unicode glory;
	 * these ones are ASCII only.
	 */
	size_t i, j, k;
	bool ok;
	uint8_t candidates[8];
	size_t n_candidates = 0;
	struct ace_condition_token token = {};
	bool expecting_unary = comp->state & SDDL_FLAG_EXPECTING_UNARY_OP;
	bool expecting_binary = comp->state & SDDL_FLAG_EXPECTING_BINARY_OP;
	bool expecting_attr = comp->state & SDDL_FLAG_EXPECTING_LOCAL_ATTR;
	bool expecting_literal = comp->state & SDDL_FLAG_EXPECTING_LITERAL;
	const uint8_t *start = comp->sddl + comp->offset;
	uint8_t c = start[0];
	char *s = NULL;
	if (! is_attr_char1(*start)) {
		/* we shouldn't get here, because we peeked first */
		return false;
	}

	/*
	 *  We'll look for a SID first, because it simplifies the rest.
	 */
	if (expecting_literal &&
	    comp->offset + 4 < comp->length &&
	    start[0] == 'S' &&
	    start[1] == 'I' &&
	    start[2] == 'D' &&
	    start[3] == '(') {
		/* actually, we are parsing a SID. */
		return parse_sid(comp);
	}

	if (expecting_binary || expecting_unary) {
		/*
		 * Collect up the operators that can possibly be used
		 * here, including only those that start with the
		 * current letter and have the right arity/syntax.
		 *
		 * We don't expect more than 5 (for 'N', beginning the
		 * "Not_..." unary ops), and we'll winnow them down as
		 * we progress through the word.
		 */
		int uc = toupper(c);
		for (i = 0; i < 256; i++) {
			const struct sddl_data *d = &sddl_strings[i];
			if (sddl_strings[i].op_precedence != SDDL_NOT_AN_OP &&
			    uc == toupper((unsigned char)d->name[0])) {
				if (d->flags & SDDL_FLAG_IS_UNARY_OP) {
					if (!expecting_unary) {
						continue;
					}
				} else if (!expecting_binary) {
					continue;
				}
				candidates[n_candidates] = i;
				n_candidates++;
				if (n_candidates == ARRAY_SIZE(candidates)) {
					/* impossible, really. */
					return false;
				}
			}
		}
	} else if (could_be_an_int(comp)) {
		/*
		 * if looks like an integer, and we expect an integer, it is
		 * an integer. If we don't expect an integer, it is a local
		 * attribute with a STUPID NAME. Or an error.
		 */
		return parse_int(comp);
	} else if (! expecting_attr) {
		comp_error(comp, "did not expect this word here");
		return false;
	}

	i = 1;
	while (comp->offset + i < comp->length) {
		c = start[i];
		if (! is_attr_char1(c)) {
			break;
		}
		if (n_candidates != 0) {
			/*
			 * Filter out candidate operators that no longer
			 * match.
			 */
			int uc = toupper(c);
			k = 0;
			for (j = 0; j < n_candidates; j++) {
				size_t o = candidates[j];
				uint8_t c2 = sddl_strings[o].name[i];
				if (uc == toupper(c2)) {
					candidates[k] = candidates[j];
					k++;
				}
			}
			n_candidates = k;
		}
		i++;
	}

	/*
	 * We have finished and there is a complete word. If it could be an
	 * operator we'll assume it is one.
	 *
	 * A complication is we could have matched more than one operator, for
	 * example "Member_of" and "Member_of_Any", so we have to look through
	 * the list of candidates for the one that ends.
	 */
	if (n_candidates != 0) {
		for (j = 0; j < n_candidates; j++) {
			size_t o = candidates[j];
			if (sddl_strings[o].name[i] == '\0') {
				/* it is this one */

				if (!comp->allow_device &&
				    (sddl_strings[o].flags & SDDL_FLAG_DEVICE))
				{
					comp_error(
						comp,
						"a device‐relative expression "
						"will never evaluate to true "
						"in this context (did you "
						"intend a user‐relative "
						"expression?)");
					return false;
				}

				token.type = o;
				token.data.sddl_op.start = comp->offset;
				comp->offset += i;
				ok = push_sddl_token(comp, token);
				return ok;
			}
		}
	}
	/*
	 * if looks like an integer, and we expect an integer, it is
	 * an integer. If we don't expect an integer, it is a local
	 * attribute with a STUPID NAME.
	 */
	if (could_be_an_int(comp)) {
		return parse_int(comp);
	}

	if (! expecting_attr) {
		comp_error(comp, "word makes no sense here");
		return false;
	}
	/* it's definitely an attribute name */
	token.type = CONDITIONAL_ACE_LOCAL_ATTRIBUTE;
	if (comp->offset + i >= comp->length) {
		comp_error(comp, "missing trailing ')'?");
		return false;
	}

	s = talloc_memdup(comp->mem_ctx, start, i + 1);
	if (s == NULL) {
		comp_error(comp, "allocation error");
		return false;
	}
	s[i] = 0;
	token.data.local_attr.value = s;
	comp->offset += i;
	return write_sddl_token(comp, token);
}

static bool parse_attr2(struct ace_condition_sddl_compiler_context *comp)
{
	/*
	 * Attributes in the form @class.attr
	 *
	 * class can be "User", "Device", or "Resource", case insensitive.
	 */
	size_t i;
	bool ok;
	size_t len;
	struct ace_condition_token token = {};

	if ((comp->state & SDDL_FLAG_EXPECTING_NON_LOCAL_ATTR) == 0) {
		comp_error(comp, "did not expect @attr here");
		return false;
	}
	if (comp->sddl[comp->offset] != '@') {
		comp_error(comp, "Expected '@'");
		return false;
	}
	comp->offset++;

	for (i = 0; i < ARRAY_SIZE(sddl_attr_types); i++) {
		int ret;
		size_t attr_len = strlen(sddl_attr_types[i].name);
		if (attr_len >= comp->length - comp->offset) {
			continue;
		}
		ret = strncasecmp(sddl_attr_types[i].name,
				  (const char *) (comp->sddl + comp->offset),
				  attr_len);
		if (ret == 0) {
			const uint8_t code = sddl_attr_types[i].code;

			if (!comp->allow_device &&
			    (sddl_strings[code].flags & SDDL_FLAG_DEVICE))
			{
				comp_error(comp,
					   "a device attribute is not "
					   "applicable in this context (did "
					   "you intend a user attribute?)");
				return false;
			}

			token.type = code;
			comp->offset += attr_len;
			break;
		}
	}
	if (i == ARRAY_SIZE(sddl_attr_types)) {
		comp_error(comp, "unknown attribute class");
		return false;
	}

	/*
	 * Now we are past the class and the '.', and into the
	 * attribute name. The attribute name can be almost
	 * anything, but some characters need to be escaped.
	 */

	len = read_attr2_string(comp, &token.data.unicode);
	if (len == -1) {
		/* read_attr2_string has set a message */
		return false;
	}
	ok = write_sddl_token(comp, token);
	if (! ok) {
		return false;
	}
	comp->offset += len;
	ok = eat_whitespace(comp, false);
	return ok;
}

static bool parse_literal(struct ace_condition_sddl_compiler_context *comp,
			  bool in_composite)
{
	uint8_t c = comp->sddl[comp->offset];
	if (!(comp->state & SDDL_FLAG_EXPECTING_LITERAL)) {
		comp_error(comp, "did not expect to be parsing a literal now");
		return false;
	}
	switch(c) {
	case '#':
		return parse_octet_string(comp);
	case '"':
		return parse_unicode(comp);
	case 'S':
		return parse_sid(comp);
	case '{':
		if (in_composite) {
			/* nested composites are not supported */
			return false;
		} else {
			return parse_composite(comp);
		}
	default:
		if (strchr("1234567890-+", c) != NULL) {
			return parse_int(comp);
		}
	}
	if (c > 31 && c < 127) {
		comp_error(comp,
			   "unexpected byte 0x%02x '%c' parsing literal", c, c);
	} else {
		comp_error(comp, "unexpected byte 0x%02x parsing literal", c);
	}
	return false;
}


static bool parse_composite(struct ace_condition_sddl_compiler_context *comp)
{
	/*
	 * This jumps into a different parser, expecting a comma separated
	 * list of literal values, which might include nested literal
	 * composites.
	 *
	 * To handle the nesting, we redirect the pointers that determine
	 * where write_sddl_token() writes.
	 */
	bool ok;
	bool first = true;
	struct ace_condition_token token = {
		.type = CONDITIONAL_ACE_TOKEN_COMPOSITE
	};
	uint32_t start = comp->offset;
	size_t alloc_size;
	struct ace_condition_token *old_target = comp->target;
	uint32_t *old_target_len = comp->target_len;

	if (comp->sddl[start] != '{') {
		comp_error(comp, "expected '{' for composite list");
		return false;
	}
	if (!(comp->state & SDDL_FLAG_EXPECTING_LITERAL)) {
		comp_error(comp, "did not expect '{' for composite list");
		return false;
	}
	comp->offset++; /* past '{' */

	/*
	 * the worst case is one token for every two bytes: {1,1,1}, and we
	 * allocate for that (counting commas and finding '}' gets hard because
	 * string literals).
	 */
	alloc_size = MIN((comp->length - start) / 2 + 1,
			 CONDITIONAL_ACE_MAX_LENGTH);

	token.data.composite.tokens = talloc_array(
		comp->mem_ctx,
		struct ace_condition_token,
		alloc_size);
	if (token.data.composite.tokens == NULL) {
		comp_error(comp, "allocation failure");
		return false;
	}

	comp->target = token.data.composite.tokens;
	comp->target_len = &token.data.composite.n_members;

	/*
	 * in this loop we are looking for:
	 *
	 * a) possible whitespace.
	 * b) a comma (or terminating '}')
	 * c) more possible whitespace
	 * d) a literal
	 *
	 * Failures use a goto to reset comp->target, just in case we ever try
	 * continuing after error.
	 */
	while (comp->offset < comp->length) {
		uint8_t c;
		ok = eat_whitespace(comp, false);
		if (! ok) {
			goto fail;
		}
		c = comp->sddl[comp->offset];
		if (c == '}') {
			comp->offset++;
			break;
		}
		if (!first) {
			if (c != ',') {
				comp_error(comp,
					   "malformed composite (expected comma)");
				goto fail;
			}
			comp->offset++;

			ok = eat_whitespace(comp, false);
			if (! ok) {
				goto fail;
			}
		}
		first = false;
		if (*comp->target_len >= alloc_size) {
			comp_error(comp,
				   "Too many tokens in composite "
				   "(>= %"PRIu32" tokens)",
				   *comp->target_len);
			goto fail;
		}
		ok = parse_literal(comp, true);
		if (!ok) {
			goto fail;
		}
	}
	comp->target = old_target;
	comp->target_len = old_target_len;
	write_sddl_token(comp, token);
	return true;
fail:
	talloc_free(token.data.composite.tokens);
	comp->target = old_target;
	comp->target_len = old_target_len;
	return false;
}


static bool parse_paren_literal(struct ace_condition_sddl_compiler_context *comp)
{
	bool ok;
	if (comp->sddl[comp->offset] != '(') {
		comp_error(comp, "expected '('");
		return false;
	}
	comp->offset++;
	ok = parse_literal(comp, false);
	if (!ok) {
		return false;
	}
	if (comp->sddl[comp->offset] != ')') {
		comp_error(comp, "expected ')'");
		return false;
	}
	comp->offset++;
	return true;
}

static bool parse_expression(struct ace_condition_sddl_compiler_context *comp)
{
	/*
	 * This expects a parenthesised expression.
	 */
	bool ok;
	struct ace_condition_token token = {};
	uint32_t start = comp->offset;

	if (comp->state & SDDL_FLAG_EXPECTING_PAREN_LITERAL) {
		/*
		 * Syntactically we allow parentheses to wrap a
		 * literal value after a Member_of or >= op, but we
		 * want to remember that it just wants a single
		 * literal, not a general expression.
		 */
		return parse_paren_literal(comp);
	}

	if (comp->sddl[start] != '(') {
		comp_error(comp, "expected '('");
		return false;
	}

	if (!(comp->state & SDDL_FLAG_EXPECTING_PAREN)) {
		comp_error(comp, "did not expect '('");
		return false;
	}

	token.type = CONDITIONAL_ACE_SAMBA_SDDL_PAREN;
	token.data.sddl_op.start = start;
	ok = push_sddl_token(comp, token);
	if (!ok) {
		return false;
	}
	comp->offset++; /* over the '(' */
	comp->state = SDDL_FLAGS_EXPR_START;
	DBG_INFO("%3"PRIu32": (\n", comp->offset);

	comp->state |= SDDL_FLAG_NOT_EXPECTING_END_PAREN;

	while (comp->offset < comp->length) {
		uint8_t c;
		ok = eat_whitespace(comp, false);
		if (! ok) {
			return false;
		}
		c = comp->sddl[comp->offset];
		if (c == '(') {
			ok = parse_expression(comp);
		} else if (c == ')') {
			if (comp->state & (SDDL_FLAG_IS_BINARY_OP |
					   SDDL_FLAG_IS_UNARY_OP)) {
				/*
				 * You can't have "(a ==)" or "(!)"
				 */
				comp_error(comp,
					   "operator lacks right hand argument");
				return false;
			}
			if (comp->state & SDDL_FLAG_NOT_EXPECTING_END_PAREN) {
				/*
				 * You can't have "( )"
				 */
				comp_error(comp, "empty expression");
				return false;
			}
			break;
		} else if (c == '@') {
			ok = parse_attr2(comp);
		} else if (strchr("!<>=&|", c)) {
			ok = parse_oppy_op(comp);
		} else if (is_attr_char1(c)) {
			ok = parse_word(comp);
		} else if (comp->state & SDDL_FLAG_EXPECTING_LITERAL) {
			ok = parse_literal(comp, false);
		} else {
			if (c > 31 && c < 127) {
				comp_error(comp,
					   "unexpected byte 0x%02x '%c'", c, c);
			} else {
				comp_error(comp, "unexpected byte 0x%02x", c);
			}
			ok = false;
		}

		if (! ok) {
			return false;
		}
		/*
		 * what did we just find? Set what we expect accordingly.
		 */
		comp->state = sddl_strings[comp->last_token_type].flags;
		DBG_INFO("%3"PRIu32": %s\n",
			comp->offset,
			sddl_strings[comp->last_token_type].name);
	}
	ok = eat_whitespace(comp, false);
	if (!ok) {
		return false;
	}

	if (comp->sddl[comp->offset] != ')') {
		comp_error(comp, "expected ')' to match '(' at %"PRIu32, start);
		return false;
	}
	/*
	 * we won't comp->offset++ until after these other error checks, so
	 * that their messages have consistent locations.
	 */
	ok = flush_stack_tokens(comp, CONDITIONAL_ACE_SAMBA_SDDL_PAREN_END);
	if (!ok) {
		return false;
	}
	if (comp->stack_depth == 0) {
		comp_error(comp, "mysterious nesting error between %"
			   PRIu32" and here",
			   start);
		return false;
	}
	token = comp->stack[comp->stack_depth - 1];
	if (token.type != CONDITIONAL_ACE_SAMBA_SDDL_PAREN) {
		comp_error(comp, "nesting error between %"PRIu32" and here",
			   start);
		return false;
	}
	if (token.data.sddl_op.start != start) {
		comp_error(comp, "')' should match '(' at %"PRIu32
			   ", not %"PRIu32,
			   token.data.sddl_op.start, start);
		return false;
	}
	comp->stack_depth--;
	DBG_INFO("%3"PRIu32": )\n", comp->offset);

	comp->offset++;  /* for the ')' */
	comp->last_token_type = CONDITIONAL_ACE_SAMBA_SDDL_PAREN_END;
	comp->state = sddl_strings[comp->last_token_type].flags;

	ok = eat_whitespace(comp, true);
	return ok;
}



static bool init_compiler_context(
	TALLOC_CTX *mem_ctx,
	struct ace_condition_sddl_compiler_context *comp,
	const enum ace_condition_flags ace_condition_flags,
	const char *sddl,
	size_t max_length,
	size_t max_stack)
{
	struct ace_condition_script *program = NULL;

	comp->sddl = (const uint8_t*)sddl;
	comp->mem_ctx = mem_ctx;

	program = talloc_zero(mem_ctx, struct ace_condition_script);
	if (program == NULL) {
		return false;
	}
	/*
	 * For the moment, we allocate for the worst case up front.
	 */
	program->tokens = talloc_array(program,
				       struct ace_condition_token,
				       max_length);
	if (program->tokens == NULL) {
		TALLOC_FREE(program);
		return false;
	}
	comp->program = program;
	comp->stack = talloc_array(program,
				   struct ace_condition_token,
				   max_stack + 1);
	if (comp->stack == NULL) {
		TALLOC_FREE(program);
		return false;
	}
	comp->target = program->tokens;
	comp->target_len = &program->length;
	comp->length = strlen(sddl);
	comp->state =  SDDL_FLAG_EXPECTING_PAREN;
	comp->allow_device = ace_condition_flags & ACE_CONDITION_FLAG_ALLOW_DEVICE;
	return true;
}

/*
 * Compile SDDL conditional ACE conditions.
 *
 * @param mem_ctx
 * @param sddl - the string to be parsed
 * @param ace_condition_flags - flags controlling compiler behaviour
 * @param message - on error, a pointer to a compiler message
 * @param message_offset - where the error occurred
 * @param consumed_length - how much of the SDDL was used
 * @return a struct ace_condition_script (or NULL).
 */
struct ace_condition_script * ace_conditions_compile_sddl(
	TALLOC_CTX *mem_ctx,
	const enum ace_condition_flags ace_condition_flags,
	const char *sddl,
	const char **message,
	size_t *message_offset,
	size_t *consumed_length)
{
	bool ok;
	struct ace_condition_sddl_compiler_context comp = {};

	*message = NULL;
	*message_offset = 0;

	ok = init_compiler_context(mem_ctx,
				   &comp,
				   ace_condition_flags,
				   sddl,
				   CONDITIONAL_ACE_MAX_LENGTH,
				   CONDITIONAL_ACE_MAX_TOKENS);
	if (!ok) {
		return NULL;
	}

	ok = parse_expression(&comp);
	if (!ok) {
		goto error;
	}
	if (comp.stack_depth != 0) {
		comp_error(&comp, "incomplete expression");
		goto error;
	}
	if (consumed_length != NULL) {
		*consumed_length = comp.offset;
	}
	*message = comp.message;
	*message_offset = comp.message_offset;
	return comp.program;
  error:
	*message = comp.message;
	*message_offset = comp.message_offset;
	TALLOC_FREE(comp.program);
	return NULL;
}



static bool parse_resource_attr_list(
	struct ace_condition_sddl_compiler_context *comp,
	char attr_type_char)
{
	/*
	 * This is a bit like parse_composite() above, but with the following
	 * differences:
	 *
	 * - it doesn't want '{...}' around the list.
	 * - if there is just one value, it is not a composite
	 * - all the values must be the expected type.
	 * - there is no nesting.
	 * - SIDs are not written with SID(...) around them.
	 */
	bool ok;
	bool first = true;
	struct ace_condition_token composite = {
		.type = CONDITIONAL_ACE_TOKEN_COMPOSITE
	};
	uint32_t start = comp->offset;
	size_t alloc_size;
	struct ace_condition_token *old_target = comp->target;
	uint32_t *old_target_len = comp->target_len;

	comp->state = SDDL_FLAG_EXPECTING_LITERAL;

	/*
	 * the worst case is one token for every two bytes: {1,1,1}, and we
	 * allocate for that (counting commas and finding '}' gets hard because
	 * string literals).
	 */
	alloc_size = MIN((comp->length - start) / 2 + 1,
			 CONDITIONAL_ACE_MAX_LENGTH);

	composite.data.composite.tokens = talloc_array(
		comp->mem_ctx,
		struct ace_condition_token,
		alloc_size);
	if (composite.data.composite.tokens == NULL) {
		comp_error(comp, "allocation failure");
		return false;
	}

	comp->target = composite.data.composite.tokens;
	comp->target_len = &composite.data.composite.n_members;

	/*
	 * in this loop we are looking for:
	 *
	 * a) possible whitespace.
	 * b) a comma (or terminating ')')
	 * c) more possible whitespace
	 * d) a literal, of the right type (checked after)
	 *
	 * Failures use a goto to reset comp->target, just in case we ever try
	 * continuing after error.
	 */
	while (comp->offset < comp->length) {
		uint8_t c;
		ok = eat_whitespace(comp, false);
		if (! ok) {
			goto fail;
		}
		c = comp->sddl[comp->offset];
		if (c == ')') {
			break;
		}
		if (!first) {
			if (c != ',') {
				comp_error(comp,
					   "malformed resource attribute ACE "
					   "(expected comma)");
				goto fail;
			}
			comp->offset++;

			ok = eat_whitespace(comp, false);
			if (! ok) {
				goto fail;
			}
		}
		first = false;
		if (*comp->target_len >= alloc_size) {
			comp_error(comp,
				   "Too many tokens in resource attribute ACE "
				   "(>= %"PRIu32" tokens)",
				   *comp->target_len);
			goto fail;
		}
		switch(attr_type_char) {
		case 'X':
			ok = parse_ra_octet_string(comp);
			break;
		case 'S':
			ok = parse_unicode(comp);
			break;
		case 'U':
			ok = parse_uint(comp);
			break;
		case 'B':
			ok = parse_bool(comp);
			break;
		case 'I':
			ok = parse_int(comp);
			break;
		case 'D':
			ok = parse_ra_sid(comp);
			break;
		default:
			/* it's a mystery we got this far */
			comp_error(comp,
				   "unknown attribute type T%c",
				   attr_type_char);
			goto fail;
		}
		if (!ok) {
			goto fail;
		}

		if (*comp->target_len == 0) {
			goto fail;
		}
	}
	comp->target = old_target;
	comp->target_len = old_target_len;

	/*
	 * If we only ended up collecting one token into the composite, we
	 * write that instead.
	 */
	if (composite.data.composite.n_members == 1) {
		ok = write_sddl_token(comp, composite.data.composite.tokens[0]);
		talloc_free(composite.data.composite.tokens);
	} else {
		ok = write_sddl_token(comp, composite);
	}
	if (! ok) {
		goto fail;
	}

	return true;
fail:
	comp->target = old_target;
	comp->target_len = old_target_len;
	TALLOC_FREE(composite.data.composite.tokens);
	return false;
}



struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *sddl_decode_resource_attr (
	TALLOC_CTX *mem_ctx,
	const char *str,
	size_t *length)
{
	/*
	 * Resource attribute ACEs define claims in object SACLs. They look like
	 *
	 *  "(RA; «flags» ;;;;WD;( «attribute-data» ))"
	 *
	 * attribute-data = DQUOTE 1*attr-char2 DQUOTE "," \
	 *     ( TI-attr / TU-attr / TS-attr / TD-attr / TX-attr / TB-attr )
	 * TI-attr = "TI" "," attr-flags *("," int-64)
	 * TU-attr = "TU" "," attr-flags *("," uint-64)
	 * TS-attr = "TS" "," attr-flags *("," char-string)
	 * TD-attr = "TD" "," attr-flags *("," sid-string)
	 * TX-attr = "TX" "," attr-flags *("," octet-string)
	 * TB-attr = "TB" "," attr-flags *("," ( "0" / "1" ) )
	 *
	 * and the data types are *mostly* parsed in the SDDL way,
	 * though there are significant differences for octet-strings.
	 *
	 * At this point we only have the "(«attribute-data»)".
	 *
	 * What we do is set up a conditional ACE compiler to be expecting a
	 * literal, and ask it to parse the strings between the commas. It's a
	 * hack.
	 */
	bool ok;
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim = NULL;
	struct ace_condition_sddl_compiler_context comp = {};
	char attr_type;
	struct ace_condition_token *tok;
	uint32_t flags;
	size_t len;
	struct ace_condition_unicode attr_name = {};

	ok = init_compiler_context(mem_ctx,
				   &comp,
				   ACE_CONDITION_FLAG_ALLOW_DEVICE,
				   str,
				   3,
				   3);
	if (!ok) {
		return NULL;
	}
	if (comp.length < 6 || comp.length > CONDITIONAL_ACE_MAX_LENGTH) {
		DBG_WARNING("invalid resource attribute: '%s'\n", str);
		goto error;
	}
	/*
	 *  Resource attribute ACEs list SIDs in a bare form "S-1-2-3", while
	 *  conditional ACEs use a wrapper syntax "SID(S-1-2-3)". As almost
	 *  everything is the same, we are reusing the conditional ACE parser,
	 *  with a flag set to tell the SID parser which form to expect.
	 */

	/* Most examples on the web have leading whitespace */
	ok = eat_whitespace(&comp, false);
	if (!ok) {
		return NULL;
	}
	if (comp.sddl[comp.offset] != '(' ||
	    comp.sddl[comp.offset + 1] != '"') {
		DBG_WARNING("invalid resource attribute --  expected '(\"'\n");
		goto error;
	}
	comp.offset += 2;

	/*
	 * Read the name. Here we are not reading a token into comp->program,
	 * just into a unicode blob.
	 */
	len = read_attr2_string(&comp, &attr_name);

	if (len == -1) {
		DBG_WARNING("invalid resource attr name: %s\n", str);
		goto error;
	}
	comp.offset += len;

	ok = eat_whitespace(&comp, false);
	if (comp.offset + 6 > comp.length) {
		DBG_WARNING("invalid resource attribute (too short): '%s'\n",
			    str);
		goto error;
	}
	/*
	 * now we have the name. Next comes '",«T[IUSDXB]»,' followed
	 * by the flags, which are a 32 bit number.
	 */
	if (comp.sddl[comp.offset] != '"' ||
	    comp.sddl[comp.offset + 1] != ','||
	    comp.sddl[comp.offset + 2] != 'T') {
		DBG_WARNING("expected '\",T[IUSDXB]' after attr name\n");
		goto error;
	}
	attr_type = comp.sddl[comp.offset + 3];

	if (comp.sddl[comp.offset + 4] != ',') {
		DBG_WARNING("expected ',' after attr type\n");
		goto error;
	}
	comp.offset += 5;
	comp.state = SDDL_FLAG_EXPECTING_LITERAL;
	ok = parse_literal(&comp, false);
	if (!ok ||
	    comp.program->length != 1) {
		DBG_WARNING("invalid attr flags: %s\n", str);
		goto error;
	}

	tok = &comp.program->tokens[0];
	if (tok->type != CONDITIONAL_ACE_TOKEN_INT64 ||
	    tok->data.int64.value < 0 ||
	    tok->data.int64.value > UINT32_MAX) {
		DBG_WARNING("invalid attr flags (want 32 bit int): %s\n", str);
		goto error;
	}
	flags = tok->data.int64.value;
	if (flags & 0xff00) {
		DBG_WARNING("invalid attr flags, "
			    "stepping on reserved 0xff00 range: %s\n",
			    str);
		goto error;
	}
	if (comp.offset + 3 > comp.length) {
		DBG_WARNING("invalid resource attribute (too short): '%s'\n",
			    str);
		goto error;
	}
	if (comp.sddl[comp.offset] != ',') {
		DBG_WARNING("invalid resource attribute ace\n");
		goto error;
	}
	comp.offset++;

	ok = parse_resource_attr_list(&comp, attr_type);
	if (!ok || comp.program->length != 2) {
		DBG_WARNING("invalid attribute type or value: T%c, %s\n",
			    attr_type, str);
		goto error;
	}
	if (comp.sddl[comp.offset] != ')') {
		DBG_WARNING("expected trailing ')'\n");
		goto error;
	}
	comp.offset++;
	*length = comp.offset;

	ok = ace_token_to_claim_v1(mem_ctx,
				   attr_name.value,
				   &comp.program->tokens[1],
				   &claim,
				   flags);
	if (!ok) {
		goto error;
	}
	TALLOC_FREE(comp.program);
	return claim;
  error:
	TALLOC_FREE(comp.program);
	return NULL;
}


static bool write_resource_attr_from_token(struct sddl_write_context *ctx,
					   const struct ace_condition_token *tok)
{
	/*
	 * this is a helper for sddl_resource_attr_from_claim(),
	 * recursing into composites if necessary.
	 */
	bool ok;
	char *sid = NULL;
	size_t i;
	const struct ace_condition_composite *c = NULL;
	switch (tok->type) {
	case CONDITIONAL_ACE_TOKEN_INT64:
		/*
		 * Note that this includes uint and bool claim types,
		 * but we don't check the validity of the ranges (0|1
		 * and >=0, respectively), rather we trust the claim
		 * to be self-consistent in this regard. Going the
		 * other way, string-to-claim, we do check.
		 */
		return sddl_write_int(ctx, tok);

	case CONDITIONAL_ACE_TOKEN_UNICODE:
		return sddl_write_unicode(ctx, tok);

	case CONDITIONAL_ACE_TOKEN_SID:
		/* unlike conditional ACE, SID does not have a "SID()" wrapper. */
		sid = sddl_encode_sid(ctx->mem_ctx, &tok->data.sid.sid, NULL);
		if (sid == NULL) {
			return false;
		}
		return sddl_write(ctx, sid);

	case CONDITIONAL_ACE_TOKEN_OCTET_STRING:
		return sddl_write_ra_octet_string(ctx, tok);

	case CONDITIONAL_ACE_TOKEN_COMPOSITE:
		/*
		 * write each token, separated by commas. If there
		 * were nested composites, this would flatten them,
		 * but that isn't really possible because the token we
		 * are dealing with came from a claim, which has no
		 * facility for nesting.
		 */
		c = &tok->data.composite;
		for(i = 0; i < c->n_members; i++) {
			ok = write_resource_attr_from_token(ctx, &c->tokens[i]);
			if (!ok) {
				return false;
			}
			if (i != c->n_members - 1) {
				ok = sddl_write(ctx, ",");
				if (!ok) {
					return false;
				}
			}
		}
		return true;
	default:
		/* We really really don't expect to get here */
		return false;
	}
}

char *sddl_resource_attr_from_claim(
	TALLOC_CTX *mem_ctx,
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim)
{
	char *s = NULL;
	char attr_type;
	bool ok;
	struct ace_condition_token tok = {};
	struct sddl_write_context ctx = {};
	TALLOC_CTX *tmp_ctx = NULL;
	char *name = NULL;
	size_t name_len;

	switch(claim->value_type) {
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
		attr_type = 'I';
		break;
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
		attr_type = 'U';
		break;
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
		attr_type = 'S';
		break;
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
		attr_type = 'D';
		break;
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
		attr_type = 'B';
		break;
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
		attr_type = 'X';
		break;
	default:
		return NULL;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NULL;
	}
	ctx.mem_ctx = tmp_ctx;

	ok = claim_v1_to_ace_composite_unchecked(tmp_ctx, claim, &tok);
	if (!ok) {
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	/* this will construct the proper string in ctx.sddl */
	ok = write_resource_attr_from_token(&ctx, &tok);
	if (!ok) {
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	/* escape the claim name */
	ok = sddl_encode_attr_name(tmp_ctx,
				   claim->name,
				   &name, &name_len);

	if (!ok) {
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	s = talloc_asprintf(mem_ctx,
			    "(\"%s\",T%c,0x%x,%s)",
			    name,
			    attr_type,
			    claim->flags,
			    ctx.sddl);
	TALLOC_FREE(tmp_ctx);
	return s;
}


struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *parse_sddl_literal_as_claim(
	TALLOC_CTX *mem_ctx,
	const char *name,
	const char *str)
{
	/*
	 * For testing purposes (and possibly for client tools), we
	 * want to be able to create claim literals, and we might as
	 * well use the SDDL syntax. So we pretend to be parsing SDDL
	 * for one literal.
	 */
	bool ok;
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim = NULL;
	struct ace_condition_sddl_compiler_context comp = {};

	ok = init_compiler_context(mem_ctx,
				   &comp,
				   ACE_CONDITION_FLAG_ALLOW_DEVICE,
				   str,
				   2,
				   2);
	if (!ok) {
		return NULL;
	}

	comp.state = SDDL_FLAG_EXPECTING_LITERAL;
	ok = parse_literal(&comp, false);

	if (!ok) {
		goto error;
	}
	if (comp.program->length != 1) {
		goto error;
	}

	ok = ace_token_to_claim_v1(mem_ctx,
				   name,
				   &comp.program->tokens[0],
				   &claim,
				   0);
	if (!ok) {
		goto error;
	}
	TALLOC_FREE(comp.program);
	return claim;
  error:
	TALLOC_FREE(comp.program);
	return NULL;
}
