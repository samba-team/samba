/*
   Unix SMB/CIFS implementation.
   Share Database of available printers.
   Copyright (C) Simo Sorce 2010

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

#ifndef _PRINTER_LIST_H_
#define _PRINTER_LIST_H_

bool printer_list_parent_init(void);

NTSTATUS printer_list_get_printer(TALLOC_CTX *mem_ctx,
				  const char *name,
				  const char **comment,
				  time_t *last_refresh);

NTSTATUS printer_list_set_printer(TALLOC_CTX *mem_ctx,
				  const char *name,
				  const char *comment,
				  time_t last_refresh);

NTSTATUS printer_list_get_last_refresh(time_t *last_refresh);
NTSTATUS printer_list_mark_reload(void);
NTSTATUS printer_list_clean_old(void);

NTSTATUS printer_list_run_fn(void (*fn)(const char *, const char *, void *),
			     void *private_data);

#endif /* _PRINTER_LIST_H_ */
