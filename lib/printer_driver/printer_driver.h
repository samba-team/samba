/*
   Unix SMB/CIFS implementation.

   Copyright (C) Guenther Deschner 2016

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

struct spoolss_AddDriverInfo8;
NTSTATUS driver_inf_parse(TALLOC_CTX *mem_ctx,
			  const char *core_driver_inf,
			  const char *filename,
			  const char *environment,
			  const char *driver_name,
			  struct spoolss_AddDriverInfo8 *r,
			  const char **source_disk_name);
NTSTATUS driver_inf_list(TALLOC_CTX *mem_ctx,
			 const char *core_driver_inf,
			 const char *filename,
			 const char *environment,
			 uint32_t *count,
			 struct spoolss_AddDriverInfo8 **r);
