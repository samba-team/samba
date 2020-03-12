/*
 * Copyright (c) 2020      Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _DCERPC_HELPER_H
#define _DCERPC_HELPER_H

#define DCERPC_SMB_ENCRYPTION_OFF      0x0000
#define DCERPC_SMB_ENCRYPTION_REQUIRED 0x0002

bool dcerpc_is_transport_encrypted(struct auth_session_info *session_info);

#endif /* _DCERPC_HELPER_H */
