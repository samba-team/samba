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
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

%module libcli_nbt

%{

#include "includes.h"
#include "lib/talloc/talloc.h"
#include "libcli/nbt/libnbt.h"
#include "param/param.h"
#include "lib/events/events.h"

/* Undo strcpy safety macro as it's used by swig )-: */

#undef strcpy

%}

%import "stdint.i"
%import "../util/errors.i"
%import "../../lib/talloc/talloc.i"
%import "../../lib/events/events.i"

/* Function prototypes */
struct nbt_name_socket *nbt_name_socket_init(TALLOC_CTX *mem_ctx, 
					     struct event_context *event_ctx,
                         struct smb_iconv_convenience *iconv_convenience);

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
		bool broadcast;
		bool wins_lookup;
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

NTSTATUS do_nbt_name_query(struct nbt_name_socket *nbtsock, 
		  	   TALLOC_CTX *mem_ctx, struct nbt_name_query *io);

%{
NTSTATUS do_nbt_name_query(struct nbt_name_socket *nbtsock, 
		  	   TALLOC_CTX *mem_ctx, struct nbt_name_query *io)
{
	return nbt_name_query(nbtsock, mem_ctx, io);
}
%}
