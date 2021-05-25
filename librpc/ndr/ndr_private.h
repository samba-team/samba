/*
   Unix SMB/CIFS implementation.
   rpc interface definitions

   Copyright (C) Andrew Tridgell 2003

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

/* This is not a public header file that is installed as part of Samba.
 * 
 * Instead, this is to allow our python layer to get to the
 * NDR_TOKEN_MAX_LIST_SIZE
*/

#ifndef __NDR_PRIVATE_H__
#define __NDR_PRIVATE_H__

size_t ndr_token_max_list_size(void);

#endif
