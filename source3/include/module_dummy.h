/* 
   Unix SMB/CIFS implementation.
   For faking up smb_register_*() functions
   e.g. smb_register_vfs() in nmbd
   Copyright (C) Stefan (metze) Metzmacher	2003
   
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

#ifndef _MODULE_DUMMY_H
#define _MODULE_DUMMY_H

#ifndef HAVE_SMB_REGISTER_AUTH
NTSTATUS smb_register_auth(int version, const char *name, auth_init_function init)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}
#endif /*HAVE_SMB_REGISTER_AUTH*/

#ifndef HAVE_SMB_REGISTER_PASSDB
NTSTATUS smb_register_passdb(int version, const char *name, pdb_init_function init) 
{
	return NT_STATUS_NOT_IMPLEMENTED;
}
#endif /*HAVE_SMB_REGISTER_PASSDB*/

#ifndef HAVE_RPC_PIPE_REGISTER_COMMANDS
NTSTATUS rpc_pipe_register_commands(int version, const char *clnt, const char *srv, const struct api_struct *cmds, int size)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}
#endif /*HAVE_RPC_PIPE_REGISTER_COMMANDS*/

#ifndef HAVE_SMB_REGISTER_VFS
NTSTATUS smb_register_vfs(int version, const char *name, vfs_op_tuple *(*init)(const struct vfs_ops *, struct smb_vfs_handle_struct *))
{
	return NT_STATUS_NOT_IMPLEMENTED;
}
#endif /*HAVE_SMB_REGISTER_VFS*/

#endif /* _MODULE_DUMMY_H */
