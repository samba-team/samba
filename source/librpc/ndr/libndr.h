/* 
   Unix SMB/CIFS implementation.
   rpc interface definitions
   Copyright (C) Andrew Tridgell 2003
   
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

#ifndef __LIBNDR_H__
#define __LIBNDR_H__

#define _PRINTF_ATTRIBUTE(a,b) 

#include "librpc/gen_ndr/misc.h"
#include "librpc/gen_ndr/security.h"

/*
  this provides definitions for the libcli/rpc/ MSRPC library
*/


/*
  this is used by the token store/retrieve code
*/
struct ndr_token_list {
	struct ndr_token_list *next, *prev;
	const void *key;
	uint32_t value;
};

/* this is the base structure passed to routines that 
   parse MSRPC formatted data 

   note that in Samba4 we use separate routines and structures for
   MSRPC marshalling and unmarshalling. Also note that these routines
   are being kept deliberately very simple, and are not tied to a
   particular transport
*/
struct ndr_pull {
	uint32_t flags; /* LIBNDR_FLAG_* */
	uint8_t *data;
	uint32_t data_size;
	uint32_t offset;

	uint32_t relative_base_offset;
	struct ndr_token_list *relative_base_list;

	struct ndr_token_list *relative_list;
	struct ndr_token_list *array_size_list;
	struct ndr_token_list *array_length_list;
	struct ndr_token_list *switch_list;

	TALLOC_CTX *current_mem_ctx;

	/* this is used to ensure we generate unique reference IDs
	   between request and reply */
	uint32_t ptr_count;
};

struct ndr_pull_save {
	uint32_t data_size;
	uint32_t offset;
	struct ndr_pull_save *next;
};

/* structure passed to functions that generate NDR formatted data */
struct ndr_push {
	uint32_t flags; /* LIBNDR_FLAG_* */
	uint8_t *data;
	uint32_t alloc_size;
	uint32_t offset;

	uint32_t relative_base_offset;
	struct ndr_token_list *relative_base_list;

	struct ndr_token_list *switch_list;
	struct ndr_token_list *relative_list;
	struct ndr_token_list *nbt_string_list;
	struct ndr_token_list *full_ptr_list;

	/* this is used to ensure we generate unique reference IDs */
	uint32_t ptr_count;
};

struct ndr_push_save {
	uint32_t offset;
	struct ndr_push_save *next;
};


/* structure passed to functions that print IDL structures */
struct ndr_print {
	uint32_t flags; /* LIBNDR_FLAG_* */
	uint32_t depth;
	struct ndr_token_list *switch_list;
	void (*print)(struct ndr_print *, const char *, ...) PRINTF_ATTRIBUTE(2,3);
	void *private_data;
};

#define LIBNDR_FLAG_BIGENDIAN  (1<<0)
#define LIBNDR_FLAG_NOALIGN    (1<<1)

#define LIBNDR_FLAG_STR_ASCII		(1<<2)
#define LIBNDR_FLAG_STR_LEN4		(1<<3)
#define LIBNDR_FLAG_STR_SIZE4		(1<<4)
#define LIBNDR_FLAG_STR_NOTERM		(1<<5)
#define LIBNDR_FLAG_STR_NULLTERM	(1<<6)
#define LIBNDR_FLAG_STR_SIZE2		(1<<7)
#define LIBNDR_FLAG_STR_BYTESIZE	(1<<8)
#define LIBNDR_FLAG_STR_FIXLEN32	(1<<9)
#define LIBNDR_FLAG_STR_CONFORMANT	(1<<10)
#define LIBNDR_FLAG_STR_CHARLEN		(1<<11)
#define LIBNDR_FLAG_STR_UTF8		(1<<12)
#define LIBNDR_FLAG_STR_FIXLEN15	(1<<13)
#define LIBNDR_STRING_FLAGS		(0x7FFC)


#define LIBNDR_FLAG_REF_ALLOC    (1<<20)
#define LIBNDR_FLAG_REMAINING    (1<<21)
#define LIBNDR_FLAG_ALIGN2       (1<<22)
#define LIBNDR_FLAG_ALIGN4       (1<<23)
#define LIBNDR_FLAG_ALIGN8       (1<<24)

#define LIBNDR_ALIGN_FLAGS (LIBNDR_FLAG_ALIGN2|LIBNDR_FLAG_ALIGN4|LIBNDR_FLAG_ALIGN8)

#define LIBNDR_PRINT_ARRAY_HEX   (1<<25)
#define LIBNDR_PRINT_SET_VALUES  (1<<26)

/* used to force a section of IDL to be little-endian */
#define LIBNDR_FLAG_LITTLE_ENDIAN (1<<27)

/* used to check if alignment padding is zero */
#define LIBNDR_FLAG_PAD_CHECK     (1<<28)

/* set if an object uuid will be present */
#define LIBNDR_FLAG_OBJECT_PRESENT    (1<<30)

/* set to avoid recursion in ndr_size_*() calculation */
#define LIBNDR_FLAG_NO_NDR_SIZE		(1<<31)

/* useful macro for debugging with DEBUG */
#define NDR_PRINT_DEBUG(type, p) ndr_print_debug((ndr_print_fn_t)ndr_print_ ##type, #p, p)
#define NDR_PRINT_UNION_DEBUG(type, level, p) ndr_print_union_debug((ndr_print_fn_t)ndr_print_ ##type, #p, level, p)
#define NDR_PRINT_FUNCTION_DEBUG(type, flags, p) ndr_print_function_debug((ndr_print_function_t)ndr_print_ ##type, #type, flags, p)
#define NDR_PRINT_BOTH_DEBUG(type, p) NDR_PRINT_FUNCTION_DEBUG(type, NDR_BOTH, p)
#define NDR_PRINT_OUT_DEBUG(type, p) NDR_PRINT_FUNCTION_DEBUG(type, NDR_OUT, p)
#define NDR_PRINT_IN_DEBUG(type, p) NDR_PRINT_FUNCTION_DEBUG(type, NDR_IN | NDR_SET_VALUES, p)

/* useful macro for debugging in strings */
#define NDR_PRINT_STRUCT_STRING(ctx, type, p) ndr_print_struct_string(ctx, (ndr_print_fn_t)ndr_print_ ##type, #p, p)
#define NDR_PRINT_UNION_STRING(ctx, type, level, p) ndr_print_union_string(ctx, (ndr_print_fn_t)ndr_print_ ##type, #p, level, p)
#define NDR_PRINT_FUNCTION_STRING(ctx, type, flags, p) ndr_print_function_string(ctx, (ndr_print_function_t)ndr_print_ ##type, #type, flags, p)
#define NDR_PRINT_BOTH_STRING(ctx, type, p) NDR_PRINT_FUNCTION_STRING(ctx, type, NDR_BOTH, p)
#define NDR_PRINT_OUT_STRING(ctx, type, p) NDR_PRINT_FUNCTION_STRING(ctx, type, NDR_OUT, p)
#define NDR_PRINT_IN_STRING(ctx, type, p) NDR_PRINT_FUNCTION_STRING(ctx, type, NDR_IN | NDR_SET_VALUES, p)

#define NDR_BE(ndr) (((ndr)->flags & (LIBNDR_FLAG_BIGENDIAN|LIBNDR_FLAG_LITTLE_ENDIAN)) == LIBNDR_FLAG_BIGENDIAN)

enum ndr_err_code {
	NDR_ERR_SUCCESS = 0,
	NDR_ERR_ARRAY_SIZE,
	NDR_ERR_BAD_SWITCH,
	NDR_ERR_OFFSET,
	NDR_ERR_RELATIVE,
	NDR_ERR_CHARCNV,
	NDR_ERR_LENGTH,
	NDR_ERR_SUBCONTEXT,
	NDR_ERR_COMPRESSION,
	NDR_ERR_STRING,
	NDR_ERR_VALIDATE,
	NDR_ERR_BUFSIZE,
	NDR_ERR_ALLOC,
	NDR_ERR_RANGE,
	NDR_ERR_TOKEN,
	NDR_ERR_IPV4ADDRESS,
	NDR_ERR_INVALID_POINTER,
	NDR_ERR_UNREAD_BYTES
};

#define NDR_ERR_CODE_IS_SUCCESS(x) (x == NDR_ERR_SUCCESS)

#define NDR_ERR_HAVE_NO_MEMORY(x) do { \
	if (NULL == (x)) { \
		return NDR_ERR_ALLOC; \
	} \
} while (0)

enum ndr_compression_alg {
	NDR_COMPRESSION_MSZIP	= 2,
	NDR_COMPRESSION_XPRESS	= 3
};

/*
  flags passed to control parse flow
*/
#define NDR_SCALARS 1
#define NDR_BUFFERS 2

/*
  flags passed to ndr_print_*()
*/
#define NDR_IN 1
#define NDR_OUT 2
#define NDR_BOTH 3
#define NDR_SET_VALUES 4

#define NDR_PULL_NEED_BYTES(ndr, n) do { \
	if ((n) > ndr->data_size || ndr->offset + (n) > ndr->data_size) { \
		return ndr_pull_error(ndr, NDR_ERR_BUFSIZE, "Pull bytes %u", (unsigned)n); \
	} \
} while(0)

#define NDR_ALIGN(ndr, n) ndr_align_size(ndr->offset, n)

#define NDR_ROUND(size, n) (((size)+((n)-1)) & ~((n)-1))

#define NDR_PULL_ALIGN(ndr, n) do { \
	if (!(ndr->flags & LIBNDR_FLAG_NOALIGN)) { \
		if (ndr->flags & LIBNDR_FLAG_PAD_CHECK) { \
			ndr_check_padding(ndr, n); \
		} \
		ndr->offset = (ndr->offset + (n-1)) & ~(n-1); \
	} \
	if (ndr->offset > ndr->data_size) { \
		return ndr_pull_error(ndr, NDR_ERR_BUFSIZE, "Pull align %u", (unsigned)n); \
	} \
} while(0)

#define NDR_PUSH_NEED_BYTES(ndr, n) NDR_CHECK(ndr_push_expand(ndr, n))

#define NDR_PUSH_ALIGN(ndr, n) do { \
	if (!(ndr->flags & LIBNDR_FLAG_NOALIGN)) { \
		uint32_t _pad = ((ndr->offset + (n-1)) & ~(n-1)) - ndr->offset; \
		while (_pad--) NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, 0)); \
	} \
} while(0)

/* these are used to make the error checking on each element in libndr
   less tedious, hopefully making the code more readable */
#define NDR_CHECK(call) do { \
	enum ndr_err_code _status; \
	_status = call; \
	if (!NDR_ERR_CODE_IS_SUCCESS(_status)) { \
		return _status; \
	} \
} while (0)

#define NDR_PULL_GET_MEM_CTX(ndr) (ndr->current_mem_ctx)

#define NDR_PULL_SET_MEM_CTX(ndr, mem_ctx, flgs) do {\
	if ( !(flgs) || (ndr->flags & flgs) ) {\
		if (!(mem_ctx)) {\
			return ndr_pull_error(ndr, NDR_ERR_ALLOC, "NDR_PULL_SET_MEM_CTX(NULL): %s\n", __location__); \
		}\
		ndr->current_mem_ctx = discard_const(mem_ctx);\
	}\
} while(0)

#define _NDR_PULL_FIX_CURRENT_MEM_CTX(ndr) do {\
	if (!ndr->current_mem_ctx) {\
		ndr->current_mem_ctx = talloc_new(ndr);\
		if (!ndr->current_mem_ctx) {\
			return ndr_pull_error(ndr, NDR_ERR_ALLOC, "_NDR_PULL_FIX_CURRENT_MEM_CTX() failed: %s\n", __location__); \
		}\
	}\
} while(0)

#define NDR_PULL_ALLOC(ndr, s) do { \
	_NDR_PULL_FIX_CURRENT_MEM_CTX(ndr);\
	(s) = talloc_ptrtype(ndr->current_mem_ctx, (s)); \
	if (!(s)) return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Alloc %s failed: %s\n", # s, __location__); \
} while (0)

#define NDR_PULL_ALLOC_N(ndr, s, n) do { \
	_NDR_PULL_FIX_CURRENT_MEM_CTX(ndr);\
	(s) = talloc_array_ptrtype(ndr->current_mem_ctx, (s), n); \
	if (!(s)) return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Alloc %u * %s failed: %s\n", (unsigned)n, # s, __location__); \
} while (0)


#define NDR_PUSH_ALLOC_SIZE(ndr, s, size) do { \
       (s) = talloc_array(ndr, uint8_t, size); \
       if (!(s)) return ndr_push_error(ndr, NDR_ERR_ALLOC, "push alloc %u failed: %s\n", (unsigned)size, __location__); \
} while (0)

#define NDR_PUSH_ALLOC(ndr, s) do { \
       (s) = talloc_ptrtype(ndr, (s)); \
       if (!(s)) return ndr_push_error(ndr, NDR_ERR_ALLOC, "push alloc %s failed: %s\n", # s, __location__); \
} while (0)

/* these are used when generic fn pointers are needed for ndr push/pull fns */
typedef enum ndr_err_code (*ndr_push_flags_fn_t)(struct ndr_push *, int ndr_flags, const void *);
typedef enum ndr_err_code (*ndr_pull_flags_fn_t)(struct ndr_pull *, int ndr_flags, void *);
typedef void (*ndr_print_fn_t)(struct ndr_print *, const char *, const void *);
typedef void (*ndr_print_function_t)(struct ndr_print *, const char *, int, const void *);

extern const struct ndr_syntax_id ndr_transfer_syntax;
extern const struct ndr_syntax_id ndr64_transfer_syntax;

struct ndr_interface_call {
	const char *name;
	size_t struct_size;
	ndr_push_flags_fn_t ndr_push;
	ndr_pull_flags_fn_t ndr_pull;
	ndr_print_function_t ndr_print;
	bool async;
};

struct ndr_interface_string_array {
	uint32_t count;
	const char * const *names;
};

struct ndr_interface_table {
	const char *name;
	struct ndr_syntax_id syntax_id;
	const char *helpstring;
	uint32_t num_calls;
	const struct ndr_interface_call *calls;
	const struct ndr_interface_string_array *endpoints;
	const struct ndr_interface_string_array *authservices;
};

struct ndr_interface_list {
	struct ndr_interface_list *prev, *next;
	const struct ndr_interface_table *table;
};

#define NDR_SCALAR_PROTO(name, type) \
enum ndr_err_code ndr_push_ ## name(struct ndr_push *ndr, int ndr_flags, type v); \
enum ndr_err_code ndr_pull_ ## name(struct ndr_pull *ndr, int ndr_flags, type *v); \
void ndr_print_ ## name(struct ndr_print *ndr, const char *var_name, type v);

#define NDR_BUFFER_PROTO(name, type) \
enum ndr_err_code ndr_push_ ## name(struct ndr_push *ndr, int ndr_flags, const type *v); \
enum ndr_err_code ndr_pull_ ## name(struct ndr_pull *ndr, int ndr_flags, type *v); \
void ndr_print_ ## name(struct ndr_print *ndr, const char *var_name, const type *v);


#endif /* __LIBNDR_H__ */
