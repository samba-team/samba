/*
   Unix SMB/CIFS implementation.

   Minimal ktutil for selftest

   Copyright (C) Ralph Boehme <slow@samba.org> 2016

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

#include "includes.h"
#include "krb5_wrap/krb5_samba.h"

static void smb_krb5_err(TALLOC_CTX *mem_ctx,
			 krb5_context context,
			 int exit_code,
			 krb5_error_code code,
			 const char *msg)
{
	char *krb5_err_str = smb_get_krb5_error_message(context,
							code,
							mem_ctx);
	printf("%s: %s\n", msg, krb5_err_str ? krb5_err_str : "UNKOWN");

	talloc_free(mem_ctx);
	exit(exit_code);
}

int main (int argc, char **argv)
{
	TALLOC_CTX *mem_ctx = talloc_init("ktutil");
	krb5_context context;
	krb5_keytab keytab;
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;
	krb5_error_code ret;
	char *keytab_name = NULL;

	if (mem_ctx == NULL) {
		printf("talloc_init() failed\n");
		exit(1);
	}

	if (argc != 2) {
		printf("Usage: %s KEYTAB\n", argv[0]);
		exit(1);
	}

	keytab_name = argv[1];

	ret = smb_krb5_init_context_common(&context);
	if (ret) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(ret));
		smb_krb5_err(mem_ctx, context, 1, ret, "krb5_context");
	}

	ret = smb_krb5_kt_open_relative(context, keytab_name, false, &keytab);
	if (ret) {
		smb_krb5_err(mem_ctx, context, 1, ret, "open keytab");
	}

	ret = krb5_kt_start_seq_get(context, keytab, &cursor);
	if (ret) {
		smb_krb5_err(mem_ctx, context, 1, ret, "krb5_kt_start_seq_get");
	}

	for (ret = krb5_kt_next_entry(context, keytab, &entry, &cursor);
	     ret == 0;
	     ret = krb5_kt_next_entry(context, keytab, &entry, &cursor))
	{
		char *principal = NULL;
		char *enctype_str = NULL;
		krb5_enctype enctype = smb_krb5_kt_get_enctype_from_entry(&entry);

		ret = smb_krb5_unparse_name(mem_ctx,
					    context,
					    entry.principal,
					    &principal);
		if (ret) {
			smb_krb5_err(mem_ctx, context, 1, ret, "krb5_enctype_to_string");
		}

		ret = smb_krb5_enctype_to_string(context,
						 enctype,
						 &enctype_str);
		if (ret) {
			smb_krb5_err(mem_ctx, context, 1, ret, "krb5_enctype_to_string");
		}

		printf("%s (%s)\n", principal, enctype_str);

		TALLOC_FREE(principal);
		SAFE_FREE(enctype_str);
		smb_krb5_kt_free_entry(context, &entry);
	}

	ret = krb5_kt_end_seq_get(context, keytab, &cursor);
	if (ret) {
		smb_krb5_err(mem_ctx, context, 1, ret, "krb5_kt_end_seq_get");
	}

	ret = krb5_kt_close(context, keytab);
	if (ret) {
		smb_krb5_err(mem_ctx, context, 1, ret, "krb5_kt_close");
	}

	krb5_free_context(context);
	talloc_free(mem_ctx);
	return 0;
}
