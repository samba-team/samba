/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - 8.3 name routines

   Copyright (C) Andrew Tridgell 2004

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

#include "include/includes.h"
#include "vfs_posix.h"

#define FNV1_PRIME 0x01000193
/*the following number is a fnv1 of the string: idra@samba.org 2002 */
#define FNV1_INIT  0xa6b93095

/* 
   hash a string of the specified length. The string does not need to be
   null terminated 

   this hash needs to be fast with a low collision rate (what hash doesn't?)
*/
static uint32_t mangle_hash(const char *key)
{
	uint32_t value;
	codepoint_t c;
	size_t c_size;

	for (value = FNV1_INIT; 
	     (c=next_codepoint(key, &c_size)); 
	     key += c_size) {
		c = toupper_w(c);
                value *= (uint32_t)FNV1_PRIME;
                value ^= (uint32_t)c;
        }

	/* note that we force it to a 31 bit hash, to keep within the limits
	   of the 36^6 mangle space */
	return value & ~0x80000000;  
}

/*
  return the short name for a component of a full name
  TODO: this is obviously not very useful in its current form !
*/
char *pvfs_short_name_component(struct pvfs_state *pvfs, const char *name)
{
	const char *basechars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	uint32_t hash;
	char c1, c2;
	const char *ext;

	if (strlen(name) <= 12) {
		return talloc_strdup(pvfs, name);
	}

	hash = mangle_hash(name);
	ext = strrchr(name, '.');

	c1 = basechars[(hash/36)%36];
	c2 = basechars[hash%36];

	return talloc_asprintf(pvfs, "%.5s~%c%c%.4s", name, c1, c2, ext?ext:"");
	
}


/*
  return the short name for a given entry in a directory
  TODO: this is obviously not very useful in its current form !
*/
char *pvfs_short_name(struct pvfs_state *pvfs, TALLOC_CTX *mem_ctx, struct pvfs_filename *name)
{
	char *p = strrchr(name->full_name, '/');
	char *ret = pvfs_short_name_component(pvfs, p+1);
	talloc_steal(mem_ctx, ret);
	return ret;
}
