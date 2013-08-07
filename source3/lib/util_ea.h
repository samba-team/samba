/*
   Unix SMB/CIFS implementation.
   SMB Extended attribute buffer handling
   Copyright (C) Jeremy Allison                 2005-2013
   Copyright (C) Tim Prouty			2008

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

#ifndef __LIB_UTIL_EA_H__
#define __LIB_UTIL_EA_H__

/****************************************************************************
 Read one EA list entry from a buffer.
****************************************************************************/

struct ea_list *read_ea_list_entry(TALLOC_CTX *ctx, const char *pdata, size_t data_size, size_t *pbytes_used);

/****************************************************************************
 Read a list of EA names and data from an incoming data buffer. Create an ea_list with them.
****************************************************************************/

struct ea_list *read_nttrans_ea_list(TALLOC_CTX *ctx, const char *pdata, size_t data_size);

#endif /* __LIB_UTIL_EA_H__ */
