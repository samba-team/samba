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
#include "torture/ndr/ndr.h"
#include "torture/ndr/proto.h"
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
	torture_local_genrand, 
	torture_local_iconv,
	torture_local_socket, 
	torture_local_socket_wrapper, 
	torture_pac, 
	torture_registry, 
	torture_local_resolve,
	torture_local_sddl,
	torture_local_ndr, 
	torture_local_tdr, 
	torture_local_event, 
	torture_local_torture,
	torture_local_dbspeed, 
	NULL
};

NTSTATUS torture_local_init(void)
{
	int i;
	struct torture_suite *suite = torture_suite_create(
										talloc_autofree_context(),
										"LOCAL");

	torture_suite_add_simple_test(suite, "TALLOC", torture_local_talloc);
	torture_suite_add_simple_test(suite, "REPLACE", torture_local_replace);

	torture_suite_add_simple_test(suite, "CRYPTO-SHA1", 
								  torture_local_crypto_sha1);
	torture_suite_add_simple_test(suite, 
								  "CRYPTO-MD4", torture_local_crypto_md4);
	torture_suite_add_simple_test(suite, "CRYPTO-MD5", 
								  torture_local_crypto_md5);
	torture_suite_add_simple_test(suite, "CRYPTO-HMACMD5", 
								  torture_local_crypto_hmacmd5);
	torture_suite_add_simple_test(suite, "CRYPTO-HMACSHA1", 
								  torture_local_crypto_hmacsha1);
	for (i = 0; suite_generators[i]; i++)
		torture_suite_add_suite(suite,
						suite_generators[i](talloc_autofree_context()));

	suite->description = talloc_strdup(suite, 
							"Local, Samba-specific tests");

	torture_register_suite(suite);

	return NT_STATUS_OK;
}
