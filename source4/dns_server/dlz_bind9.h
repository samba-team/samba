/*
   Unix SMB/CIFS implementation.

   bind9 dlz driver for Samba

   Copyright (C) 2010 Andrew Tridgell

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

/*
  provide the minimal set of prototypes and defines for bind9 interop
  The aim is to not require the bind9 source when building the
  dlz_bind9 module
 */
typedef unsigned int isc_result_t;
typedef uint32_t dns_ttl_t;

#define DLZ_DLOPEN_VERSION 1

/* result codes */
#define ISC_R_SUCCESS			0
#define ISC_R_NOMEMORY			1
#define ISC_R_NOTFOUND			23
#define ISC_R_FAILURE			25

/* log levels */
#define ISC_LOG_INFO		(-1)
#define ISC_LOG_NOTICE		(-2)
#define ISC_LOG_WARNING 	(-3)
#define ISC_LOG_ERROR		(-4)
#define ISC_LOG_CRITICAL	(-5)

/* a couple of opaque structures */
struct dns_sdlzlookup;
typedef struct dns_sdlzlookup dns_sdlzlookup_t;
struct dns_sdlzallnodes;
typedef struct dns_sdlzallnodes dns_sdlzallnodes_t;
