/*
 * Unix SMB/CIFS implementation.
 * Support for OneFS
 *
 * Copyright (C) Steven Danneman, 2008
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ONEFS_H
#define _ONEFS_H

/* OneFS Module smb.conf parameters and defaults */

/**
* Specifies when ACLs presented to Windows should be canonicalized
* into the ordering which Explorer expects.
*/
enum onefs_acl_wire_format
{
	ACL_FORMAT_RAW, /**< Never canonicalize */
	ACL_FORMAT_WINDOWS_SD, /**< Only canonicalize synthetic ACLs */
	ACL_FORMAT_ALWAYS /**< Always canonicalize */
};

const struct enum_list enum_onefs_acl_wire_format[] = {
	{ACL_FORMAT_RAW,  "No Format"},
	{ACL_FORMAT_WINDOWS_SD, "Format Windows SD"},
	{ACL_FORMAT_ALWAYS, "Always Format SD"},
	{-1, NULL}
};

#define PARM_ONEFS_TYPE "onefs"
#define PARM_ACL_WIRE_FORMAT "acl wire format"
#define PARM_ACL_WIRE_FORMAT_DEFAULT ACL_FORMAT_WINDOWS_SD
#define PARM_SIMPLE_FILE_SHARING_COMPATIBILITY_MODE "simple file sharing compatibility mode"
#define PARM_SIMPLE_FILE_SHARING_COMPATIBILITY_MODE_DEFAULT false
#define PARM_CREATOR_OWNER_GETS_FULL_CONTROL "creator owner gets full control"
#define PARM_CREATOR_OWNER_GETS_FULL_CONTROL_DEFAULT true

#endif /* _ONEFS_H */
