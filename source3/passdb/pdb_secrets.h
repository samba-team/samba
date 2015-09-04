/*
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Andrew Bartlett      2002
   Copyright (C) Rafal Szczesniak     2002
   Copyright (C) Tim Potter           2001

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

#ifndef _PASSDB_PDB_SECRETS_H_
#define _PASSDB_PDB_SECRETS_H_

/* The following definitions come from passdb/pdb_secrets.c  */

NTSTATUS secrets_trusted_domains(TALLOC_CTX *mem_ctx, uint32_t *num_domains,
				 struct trustdom_info ***domains);

#endif /* _PASSDB_PDB_SECRETS_H_ */
