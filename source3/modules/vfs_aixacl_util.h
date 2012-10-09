/*
   Unix SMB/Netbios implementation.
   VFS module to get and set posix acls
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2006

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

SMB_ACL_T aixacl_to_smbacl( struct acl *file_acl, TALLOC_CTX *mem_ctx);
struct acl *aixacl_smb_to_aixacl(SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl);

