/* 
   Unix SMB/CIFS implementation.

   security utility functions

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

#ifndef _SAMBA_SECURITY_H
#define _SAMBA_SECURITY_H

#include "librpc/gen_ndr/ndr_security.h"

struct security_token {
	struct dom_sid *user_sid;
	struct dom_sid *group_sid;
	uint32_t num_sids;
	struct dom_sid **sids;
	uint64_t privilege_mask;
};

#endif /* _SAMBA_SECURITY_H */
