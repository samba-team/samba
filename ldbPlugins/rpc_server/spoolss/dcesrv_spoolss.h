/* 
   Unix SMB/CIFS implementation.

   endpoint server for the spoolss pipe - definitions

   Copyright (C) Tim Potter 2004
   
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

/*
  this type allows us to distinguish handle types
*/
enum spoolss_handle {
	SPOOLSS_HANDLE_SERVER,
	SPOOLSS_HANDLE_PRINTER
};

/*
  state asscoiated with a spoolss_OpenPrinter{,Ex}() operation
*/
struct spoolss_openprinter_state {
	int reference_count;
	void *openprinter_ctx;
	TALLOC_CTX *mem_ctx;
	uint32_t access_mask;
};
