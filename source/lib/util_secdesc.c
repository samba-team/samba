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

/*
  return a blank security descriptor (no owners, dacl or sacl)
*/
struct security_descriptor *sd_initialise(TALLOC_CTX *mem_ctx)
{
	struct security_descriptor *sd;

	sd = talloc_p(mem_ctx, struct security_descriptor);
	if (!sd) {
		return NULL;
	}

	sd->revision = SD_REVISION;
	/* we mark as self relative, even though it isn't while it remains
	   a pointer in memory because this simplifies the ndr code later.
	   All SDs that we store/emit are in fact SELF_RELATIVE
	*/
	sd->type = SEC_DESC_SELF_RELATIVE;

	sd->owner_sid = NULL;
	sd->group_sid = NULL;
	sd->sacl = NULL;
	sd->dacl = NULL;

	return sd;
}

