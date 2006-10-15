/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Jelmer Vernooij 2006
   
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

#include "includes.h"
#include "torture/torture.h"
#include "torture/local/proto.h"
#include "torture/auth/proto.h"

/* ignore me */ static struct torture_suite *
	(*suite_generators[]) (TALLOC_CTX *mem_ctx) =
{ 
	torture_local_binding_string, 
	torture_ntlmssp, 
	torture_local_messaging, 
	torture_local_irpc, 
	torture_local_util_strlist, 
	torture_local_util_file, 
	torture_local_idtree, 
	torture_local_iconv,
	torture_local_socket, 
	torture_pac, 
	torture_registry, 
	torture_local_resolve,
	torture_local_sddl,
	torture_local_ndr, 
	torture_local_event, 
	torture_local_torture,
	torture_local_dbspeed, 
	NULL
};

NTSTATUS torture_local_init(void)
{
	int i;
	TALLOC_CTX *mem_ctx = talloc_autofree_context();

	register_torture_op("LOCAL-REPLACE", torture_local_replace);
	register_torture_op("LOCAL-TALLOC", torture_local_talloc);
	register_torture_op("LOCAL-CRYPTO-MD4", torture_local_crypto_md4);
	register_torture_op("LOCAL-CRYPTO-MD5", torture_local_crypto_md5);
	register_torture_op("LOCAL-CRYPTO-HMACMD5", torture_local_crypto_hmacmd5);
	register_torture_op("LOCAL-CRYPTO-SHA1", torture_local_crypto_sha1);
	register_torture_op("LOCAL-CRYPTO-HMACSHA1", torture_local_crypto_hmacsha1);
	for (i = 0; suite_generators[i]; i++)
		torture_register_suite(suite_generators[i](mem_ctx));

	return NT_STATUS_OK;
}
