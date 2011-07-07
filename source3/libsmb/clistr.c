/* 
   Unix SMB/CIFS implementation.
   client string routines
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003

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

#include "includes.h"
#include "libsmb/libsmb.h"

size_t clistr_pull_talloc(TALLOC_CTX *ctx,
			  const char *base,
			  uint16_t flags2,
			  char **pp_dest,
			  const void *src,
			  int src_len,
			  int flags)
{
	return pull_string_talloc(ctx,
				  base,
				  flags2,
				  pp_dest,
				  src,
				  src_len,
				  flags);
}
