/* 
   Unix SMB/CIFS implementation.

   routines to manipulate a "struct dom_sid"

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

#include "includes.h"

/*
  convert a string to a dom_sid, returning a talloc'd dom_sid
*/
struct dom_sid *dom_sid_parse_talloc(TALLOC_CTX *mem_ctx, const char *sidstr)
{
	struct dom_sid *ret;
	uint_t rev, ia, num_sub_auths, i;
	char *p;
  
	if (strncasecmp(sidstr, "S-", 2)) {
		return NULL;
	}

	sidstr += 2;

	rev = strtol(sidstr, &p, 10);
	if (*p != '-') {
		return NULL;
	}
	sidstr = p+1;

	ia = strtol(sidstr, &p, 10);
	if (p == sidstr) {
		return NULL;
	}
	sidstr = p;

	num_sub_auths = 0;
	for (i=0;sidstr[i];i++) {
		if (sidstr[i] == '-') num_sub_auths++;
	}

	ret = talloc_p(mem_ctx, struct dom_sid);
	if (!ret) {
		return NULL;
	}

	ret->sub_auths = talloc_array_p(mem_ctx, uint32_t, num_sub_auths);
	if (!ret->sub_auths) {
		return NULL;
	}

	ret->sid_rev_num = rev;
	ret->id_auth[0] = 0;
	ret->id_auth[0] = 0;
	ret->id_auth[1] = 0;
	ret->id_auth[2] = ia >> 24;
	ret->id_auth[3] = ia >> 16;
	ret->id_auth[4] = ia >> 8;
	ret->id_auth[5] = ia;
	ret->num_auths = num_sub_auths;

	for (i=0;i<num_sub_auths;i++) {
		if (sidstr[0] != '-') {
			return NULL;
		}
		sidstr++;
		ret->sub_auths[i] = strtol(sidstr, &p, 10);
		if (p == sidstr) {
			return NULL;
		}
		sidstr = p;
	}

	return ret;
}

/*
  convert a string to a dom_sid, returning a talloc'd dom_sid
*/
struct dom_sid *dom_sid_dup(TALLOC_CTX *mem_ctx, struct dom_sid *dom_sid)
{
	struct dom_sid *ret;
	int i;
	ret = talloc_p(mem_ctx, struct dom_sid);
	if (!ret) {
		return NULL;
	}

	ret->sub_auths = talloc_array_p(mem_ctx, uint32_t, dom_sid->num_auths);
	if (!ret->sub_auths) {
		return NULL;
	}

	ret->sid_rev_num = dom_sid->sid_rev_num;
	ret->id_auth[0] = dom_sid->id_auth[0];
	ret->id_auth[1] = dom_sid->id_auth[1];
	ret->id_auth[2] = dom_sid->id_auth[2];
	ret->id_auth[3] = dom_sid->id_auth[3];
	ret->id_auth[4] = dom_sid->id_auth[4];
	ret->id_auth[5] = dom_sid->id_auth[5];
	ret->num_auths = dom_sid->num_auths;

	for (i=0;i<dom_sid->num_auths;i++) {
		ret->sub_auths[i] = dom_sid->sub_auths[i];
	}

	return ret;
}

