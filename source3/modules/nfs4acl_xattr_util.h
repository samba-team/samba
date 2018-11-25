/*
 * Copyright (C) Ralph Boehme 2018
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
 *
 */

#ifndef _NFS4ACL_XATTR_UTIL_H_
#define _NFS4ACL_XATTR_UTIL_H_

unsigned smb4acl_to_nfs4acl_flags(uint16_t smb4acl_flags);
uint16_t nfs4acl_to_smb4acl_flags(unsigned nfsacl41_flags);

#endif /* _NFS4ACL_XATTR_UTIL_H_ */
