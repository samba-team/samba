/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines

   Copyright (C) Ralph Boehme 2015

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

#ifndef _MDSSVC_MARSHALLING_H
#define _MDSSVC_MARSHALLING_H

#include "dalloc.h"

#define MAX_SL_FRAGMENT_SIZE 0xFFFFF

/* Can be ored and used as flags */
#define SL_ENC_LITTLE_ENDIAN 1
#define SL_ENC_BIG_ENDIAN    2
#define SL_ENC_UTF_16        4

typedef DALLOC_CTX     sl_array_t;    /* an array of elements */
typedef DALLOC_CTX     sl_dict_t;     /* an array of key/value elements */
typedef DALLOC_CTX     sl_filemeta_t; /* contains one sl_array_t */
typedef int            sl_nil_t;      /* a nil element */
typedef bool           sl_bool_t;
typedef struct timeval sl_time_t;
typedef struct {
	char sl_uuid[16];
} sl_uuid_t;
typedef struct {
	uint16_t   ca_unkn1;
	uint32_t   ca_context;
	DALLOC_CTX *ca_cnids;
} sl_cnids_t; /* an array of CNIDs */

/******************************************************************************
 * Function declarations
 ******************************************************************************/

extern ssize_t sl_pack(DALLOC_CTX *query, char *buf, size_t bufsize);
extern bool sl_unpack(DALLOC_CTX *query, const char *buf, size_t bufsize);

#endif
