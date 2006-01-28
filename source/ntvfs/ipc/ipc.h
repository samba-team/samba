/* 
   Unix SMB/CIFS implementation.
   NTVFS IPC$ Named Pipes
   Copyright (C) Jelmer Vernooij 			2005
   
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

struct named_pipe_ops {
	NTSTATUS (*open)(void *context_data,
					 const char *path, 
					 struct auth_session_info *session, 
					 struct stream_connection *stream,
					 TALLOC_CTX *ctx, void **private_data);
	NTSTATUS (*trans)(void *private_data, DATA_BLOB *in, DATA_BLOB *out);
	NTSTATUS (*write)(void *private_data, DATA_BLOB *out);
	NTSTATUS (*read)(void *private_data, DATA_BLOB *in);
};
