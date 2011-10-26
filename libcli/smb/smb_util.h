/*
   Unix SMB/CIFS implementation.
   client file operations
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) James Myers 2003

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

char *attrib_string(TALLOC_CTX *mem_ctx, uint32_t attrib);
uint32_t unix_perms_to_wire(mode_t perms);
mode_t wire_perms_to_unix(uint32_t perms);
mode_t unix_filetype_from_wire(uint32_t wire_type);

bool smb_buffer_oob(uint32_t bufsize, uint32_t offset, uint32_t length);
