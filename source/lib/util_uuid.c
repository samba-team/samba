/* 
 *  Unix SMB/CIFS implementation.
 *  UUID server routines
 *  Copyright (C) Theodore Ts'o               1996, 1997,
 *  Copyright (C) Jim McDonough                     2002.
 *  Copyright (C) Andrew Tridgell                   2003.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

void uuid_generate_random(struct GUID *out)
{
	generate_random_buffer((unsigned char *)out, sizeof(struct GUID));
	out->clock_seq[0] = (out->clock_seq[0] & 0x3F) | 0x80;
	out->time_hi_and_version = (out->time_hi_and_version & 0x0FFF) | 0x4000;
}

BOOL uuid_all_zero(const struct GUID *u)
{
	if (u->time_low != 0 ||
	    u->time_mid != 0 ||
	    u->time_hi_and_version != 0 ||
	    u->clock_seq[0] != 0 ||
	    u->clock_seq[1] != 0 ||
	    !all_zero(u->node, 6)) {
		return False;
	}
	return True;
}

BOOL uuid_equal(const struct GUID *u1, const struct GUID *u2)
{
	if (u1->time_low != u2->time_low ||
	    u1->time_mid != u2->time_mid ||
	    u1->time_hi_and_version != u2->time_hi_and_version ||
	    u1->clock_seq[0] != u2->clock_seq[0] ||
	    u1->clock_seq[1] != u2->clock_seq[1] ||
	    memcmp(u1->node, u2->node, 6) != 0) {
		return False;
	}
	return True;
}

BOOL policy_handle_empty(struct policy_handle *h) 
{
	return (h->handle_type == 0 && uuid_all_zero(&h->uuid));
}

