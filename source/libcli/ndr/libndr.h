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

#define NDR_BASE_MARSHALL_SIZE 1024



#define LIBNDR_FLAG_BIGENDIAN 1


/* these are used to make the error checking on each element in libndr
   less tedious, hopefully making the code more readable */
#define NDR_CHECK(call) do { NTSTATUS _status; \
                             _status = call; \
                             if (!NT_STATUS_IS_OK(_status)) \
                                return _status; \
                        } while (0)


#define NDR_ALLOC(ndr, s) do { \
	                       (s) = talloc(ndr->mem_ctx, sizeof(*(s))); \
                               if (!(s)) return NT_STATUS_NO_MEMORY; \
                           } while (0)

#define NDR_ALLOC_N(ndr, s, n) do { \
				if ((n) == 0) { \
					(s) = NULL; \
				} else { \
					(s) = talloc(ndr->mem_ctx, (n) * sizeof(*(s))); \
					if (!(s)) return NT_STATUS_NO_MEMORY; \
				} \
                           } while (0)

/* these are used when generic fn pointers are needed for ndr push/pull fns */
typedef NTSTATUS (*ndr_push_fn_t)(struct ndr_push *, void *);
typedef NTSTATUS (*ndr_pull_fn_t)(struct ndr_pull *, void *);

/* now pull in the individual parsers */
#include "libcli/ndr/ndr_sec.h"
#include "libcli/ndr/ndr_echo.h"
