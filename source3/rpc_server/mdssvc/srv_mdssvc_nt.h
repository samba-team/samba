/*
 *  Unix SMB/CIFS implementation.
 *  MDSSVC RPC pipe initialisation routines
 *
 *  Copyright (C) Ralph Boehme                 2014
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

#ifndef _SRV_MDSSVC_NT_H
#define _SRV_MDSSVC_NT_H

bool init_service_mdssvc(struct messaging_context *msg_ctx);
bool shutdown_service_mdssvc(void);

#endif /* _SRV_MDSSVC_NT_H */
