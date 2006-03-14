/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Stefan Metzmacher	2004
   
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

struct libnet_context {
	/* here we need:
	 * a client env context
	 * a user env context
	 */
	struct cli_credentials *cred;

	/* pipe */
	struct dcerpc_pipe *pipe;

	/* opened handles */
	struct policy_handle domain_handle;
	struct policy_handle user_handle;

	/* name resolution methods */
	const char **name_res_methods;

	struct event_context *event_ctx;
};


#include "ldb.h"
#include "libnet/libnet_passwd.h"
#include "libnet/libnet_time.h"
#include "libnet/libnet_rpc.h"
#include "libnet/libnet_join.h"
#include "libnet/libnet_site.h"
#include "libnet/libnet_vampire.h"
#include "libnet/libnet_user.h"
#include "libnet/libnet_share.h"
#include "libnet/libnet_lookup.h"
#include "libnet/composite.h"
#include "libnet/libnet_proto.h"
