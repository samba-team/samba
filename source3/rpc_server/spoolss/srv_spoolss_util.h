/*
 *  Unix SMB/CIFS implementation.
 *
 *  SPOOLSS RPC Pipe server / winreg client routines
 *
 *  Copyright (c) 2010      Andreas Schneider <asn@samba.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SRV_SPOOLSS_UITL_H
#define _SRV_SPOOLSS_UITL_H

struct auth_serversupplied_info;
struct dcerpc_binding_handle;

WERROR winreg_printer_binding_handle(TALLOC_CTX *mem_ctx,
				     const struct auth_serversupplied_info *session_info,
				     struct messaging_context *msg_ctx,
				     struct dcerpc_binding_handle **winreg_binding_handle);

#endif /* _SRV_SPOOLSS_UITL_H */
