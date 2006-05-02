/* 
   Unix SMB/CIFS implementation.

   Swig interface to libcli_nbt library.

   Copyright (C) 2006 Tim Potter <tpot@samba.org>

     ** NOTE! The following LGPL license applies to the tdb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

%module libcli_nbt

%{

#include "includes.h"
#include "lib/talloc/talloc.h"
#include "lib/events/events.h"
#include "libcli/nbt/libnbt.h"

/* Undo strcpy safety macro as it's used by swig )-: */

#undef strcpy

%}

%apply bool { BOOL };
%apply int { uint8_t };
%apply int { int8_t };
%apply unsigned int { uint16_t };
%apply int { int16_t };

%typemap(in) uint32_t {
	if (PyLong_Check($input))
		$1 = PyLong_AsUnsignedLong($input);
	else if (PyInt_Check($input))
		$1 = PyInt_AsLong($input);
	else {
		PyErr_SetString(PyExc_TypeError,"Expected a long or an int");
		return NULL;
	}
}

%typemap(out) uint32_t {
	$result = PyLong_FromUnsignedLong($1);
}

%apply unsigned long long { uint64_t };
%apply long long { int64_t };

%typemap(in) NTSTATUS {
        if (PyLong_Check($input))
                $1 = NT_STATUS(PyLong_AsUnsignedLong($input));
        else if (PyInt_Check($input))
                $1 = NT_STATUS(PyInt_AsLong($input));
        else {
                PyErr_SetString(PyExc_TypeError, "Expected a long or an int");
                return NULL;
        }
}

%typemap(out) NTSTATUS {
        $result = PyLong_FromUnsignedLong(NT_STATUS_V($1));
}

TALLOC_CTX *talloc_init(char *name);
int talloc_free(TALLOC_CTX *ptr);

/* Function prototypes */

struct event_context *event_context_init(TALLOC_CTX *mem_ctx);

struct nbt_name_socket *nbt_name_socket_init(TALLOC_CTX *mem_ctx, 
					     struct event_context *event_ctx);

enum nbt_name_type {
	NBT_NAME_CLIENT=0x00,
	NBT_NAME_MS=0x01,
	NBT_NAME_USER=0x03,
	NBT_NAME_SERVER=0x20,
	NBT_NAME_PDC=0x1B,
	NBT_NAME_LOGON=0x1C,
	NBT_NAME_MASTER=0x1D,
	NBT_NAME_BROWSER=0x1E
};

struct nbt_name {
	const char *name;
	const char *scope;
	enum nbt_name_type type;
};

%rename(data_in) in;
%rename(data_out) out;

struct nbt_name_query {
	struct {
		struct nbt_name name;
		const char *dest_addr;
		BOOL broadcast;
		BOOL wins_lookup;
		int timeout; /* in seconds */
		int retries;
	} in;
	struct {
		const char *reply_from;
		struct nbt_name name;
		int16_t num_addrs;
		const char **reply_addrs;
	} out;
};

%include "carrays.i"
%array_functions(char *, char_ptr_array);

%rename(do_nbt_name_query) nbt_name_query;

NTSTATUS nbt_name_query(struct nbt_name_socket *nbtsock, 
			TALLOC_CTX *mem_ctx, struct nbt_name_query *io);

void lp_load(void);
