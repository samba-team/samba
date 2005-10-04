/* 
   Unix SMB/CIFS implementation.

   SMB composite request interfaces

   Copyright (C) Volker Lendecke 2005
   
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

struct wb_finddcs {
	struct {
		struct messaging_context *msg_ctx;
		const char *domain;
	} in;

	struct {
		int num_dcs;
		struct nbt_dc_name {
			const char *address;
			const char *name;
		} *dcs;
	} out;
};

struct wb_get_schannel_creds {
	struct {
		struct cli_credentials *creds;
		struct smbcli_tree *tree;
	} in;
	struct {
		struct dcerpc_pipe *netlogon;
	} out;
};

struct wb_get_lsa_pipe {
	struct {
		struct event_context *event_ctx;
		struct messaging_context *msg_ctx;
		const char *domain;
	} in;
	struct {
		const struct dom_sid *domain_sid;
		struct dcerpc_pipe *pipe;
	} out;
};
