/* 
   Unix SMB/CIFS implementation.

   security descriptror utility functions

   Copyright (C) Andrew Tridgell 		2004
      
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
#include "librpc/gen_ndr/ndr_security.h"

/*
  return a blank security descriptor (no owners, dacl or sacl)
*/
struct security_token *security_token_initialise(TALLOC_CTX *mem_ctx)
{
	struct security_token *st;

	st = talloc_p(mem_ctx, struct security_token);
	if (!st) {
		return NULL;
	}

	st->flags = 0;

	st->user_sid = NULL;
	st->group_sid = NULL;
	st->logon_sid = NULL;

	st->num_sids = 0;
	st->sids = NULL;

	st->num_restricted_sids = 0;
	st->restricted_sids = NULL;

	st->num_privileges = 0;
	st->privileges = NULL;

	st->dacl = NULL;

	return st;
}
