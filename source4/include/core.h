/* 
   Unix SMB/CIFS implementation.
   Core Samba data types

   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Stefan Metzmacher			  2004
   Copyright (C) Jelmer Vernooij			  2005
   
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

#ifndef _SAMBA_CORE_H
#define _SAMBA_CORE_H

#define False (0)
#define True (1)
#define Auto (2)

typedef int BOOL;

/* used to hold an arbitrary blob of data */
typedef struct datablob {
	uint8_t *data;
	size_t length;
} DATA_BLOB;

struct data_blob_list_item {
	struct data_blob_list_item *prev,*next;
	DATA_BLOB blob;
};

/* by making struct ldb_val and DATA_BLOB the same, we can simplify
   a fair bit of code */
#define ldb_val datablob

/* 64 bit time (100 nanosec) 1601 - cifs6.txt, section 3.5, page 30, 4 byte aligned */
typedef uint64_t NTTIME;

typedef NTSTATUS (*init_module_fn) (void);

#endif /* _SAMBA_CORE_H */
