/* 
   Unix SMB/CIFS implementation.
   rpc interface definitions
   Copyright (C) Andrew Tridgell 2003
   
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

/*
  this provides definitions for the libcli/rpc/ MSRPC library
*/


/* this is the base structure passed to routines that 
   parse MSRPC formatted data 

   note that in Samba4 we use separate routines and structures for
   MSRPC marshalling and unmarshalling. Also note that these routines
   are being kept deliberately very simple, and are not tied to a
   particular transport
*/
struct ndr_pull {
	uint32 flags; /* LIBNDR_FLAG_* */
	char *data;
	uint32 data_size;
	uint32 offset;
	TALLOC_CTX *mem_ctx;
};

struct ndr_pull_save {
	uint32 data_size;
	uint32 offset;
};


/* structure passed to functions that generate NDR formatted data */
struct ndr_push {
	uint32 flags; /* LIBNDR_FLAG_* */
	char *data;
	uint32 alloc_size;
	uint32 offset;
	TALLOC_CTX *mem_ctx;
};

struct ndr_push_save {
	uint32 offset;
};


/* structure passed to functions that print IDL structures */
struct ndr_print {
	uint32 flags; /* LIBNDR_FLAG_* */
	TALLOC_CTX *mem_ctx;
	uint32 depth;
	void (*print)(struct ndr_print *, const char *, ...);
	void *private;
};

#define LIBNDR_FLAG_BIGENDIAN 1


/* useful macro for debugging */
#define NDR_PRINT_DEBUG(type, p) ndr_print_debug((ndr_print_fn_t)ndr_print_ ##type, #p, p)
#define NDR_PRINT_UNION_DEBUG(type, level, p) ndr_print_union_debug((ndr_print_union_fn_t)ndr_print_ ##type, #p, level, p)


enum ndr_err_code {
	NDR_ERR_CONFORMANT_SIZE,
	NDR_ERR_ARRAY_SIZE,
	NDR_ERR_BAD_SWITCH
};

/*
  flags passed to control parse flow
*/
#define NDR_SCALARS 1
#define NDR_BUFFERS 2

#define NDR_PULL_NEED_BYTES(ndr, n) do { \
	if ((n) > ndr->data_size || ndr->offset + (n) > ndr->data_size) { \
		return NT_STATUS_BUFFER_TOO_SMALL; \
	} \
} while(0)

#define NDR_PULL_ALIGN(ndr, n) do { \
	ndr->offset = (ndr->offset + (n-1)) & ~(n-1); \
	if (ndr->offset >= ndr->data_size) { \
		return NT_STATUS_BUFFER_TOO_SMALL; \
	} \
} while(0)

#define NDR_PUSH_NEED_BYTES(ndr, n) NDR_CHECK(ndr_push_expand(ndr, ndr->offset+(n)))

#define NDR_PUSH_ALIGN(ndr, n) do { \
	uint32 _pad = (ndr->offset & (n-1)); \
	while (_pad--) NDR_CHECK(ndr_push_uint8(ndr, 0)); \
} while(0)


/* these are used to make the error checking on each element in libndr
   less tedious, hopefully making the code more readable */
#define NDR_CHECK(call) do { NTSTATUS _status; \
                             _status = call; \
                             if (!NT_STATUS_IS_OK(_status)) \
                                return _status; \
                        } while (0)


#define NDR_ALLOC_SIZE(ndr, s, size) do { \
	                       (s) = talloc(ndr->mem_ctx, size); \
                               if (!(s)) return NT_STATUS_NO_MEMORY; \
                           } while (0)

#define NDR_ALLOC(ndr, s) NDR_ALLOC_SIZE(ndr, s, sizeof(*(s)))


#define NDR_ALLOC_N_SIZE(ndr, s, n, elsize) do { \
				if ((n) == 0) { \
					(s) = NULL; \
				} else { \
					(s) = talloc(ndr->mem_ctx, (n) * elsize); \
					if (!(s)) return NT_STATUS_NO_MEMORY; \
				} \
                           } while (0)

#define NDR_ALLOC_N(ndr, s, n) NDR_ALLOC_N_SIZE(ndr, s, n, sizeof(*(s)))

/* these are used when generic fn pointers are needed for ndr push/pull fns */
typedef NTSTATUS (*ndr_push_fn_t)(struct ndr_push *, void *);
typedef NTSTATUS (*ndr_pull_fn_t)(struct ndr_pull *, void *);

typedef NTSTATUS (*ndr_push_flags_fn_t)(struct ndr_push *, int ndr_flags, void *);
typedef NTSTATUS (*ndr_pull_flags_fn_t)(struct ndr_pull *, int ndr_flags, void *);
typedef void (*ndr_print_fn_t)(struct ndr_print *, const char *, void *);
typedef void (*ndr_print_union_fn_t)(struct ndr_print *, const char *, uint16, void *);

/* now pull in the individual parsers */
#include "librpc/ndr/ndr_sec.h"
#include "librpc/ndr/ndr_misc.h"
#include "librpc/ndr/ndr_echo.h"
#include "librpc/ndr/ndr_lsa.h"
#include "librpc/ndr/ndr_dfs.h"
#include "librpc/ndr/ndr_spoolss.h"
