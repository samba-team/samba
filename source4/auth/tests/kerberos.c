#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "includes.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_proto.h"
#include "auth/credentials/credentials_krb5.h"
#include "auth/kerberos/kerberos_credentials.h"
#include "auth/kerberos/kerberos_util.h"

static void internal_obsolete_keytab_test(int num_principals, int num_kvnos,
					  krb5_kvno kvno, const char *kt_name)
{
	krb5_context krb5_ctx;
	krb5_keytab keytab;
	krb5_keytab_entry kt_entry;
	krb5_kt_cursor cursor;
	krb5_error_code code;

	int i,j;
	char princ_name[] = "user0";
	char expect_princ_name[] = "user0@samba.example.com";
	bool found_previous;
	const char *error_str;

	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	krb5_principal *principals = talloc_zero_array(tmp_ctx,
						       krb5_principal,
						       num_principals);
	krb5_init_context(&krb5_ctx);
	krb5_kt_resolve(krb5_ctx, kt_name, &keytab);
	ZERO_STRUCT(kt_entry);

	for(i=0; i<num_principals; i++) {
		princ_name[4] = (char)i+48;
		smb_krb5_make_principal(krb5_ctx, &(principals[i]),
				    "samba.example.com", princ_name, NULL);
		kt_entry.principal = principals[i];
		for (j=0; j<num_kvnos; j++) {
			kt_entry.vno = j+1;
			krb5_kt_add_entry(krb5_ctx, keytab, &kt_entry);
		}
	}

	code = krb5_kt_start_seq_get(krb5_ctx, keytab, &cursor);
	assert_int_equal(code, 0);
#ifdef SAMBA4_USES_HEIMDAL
	for (i=0; i<num_principals; i++) {
		expect_princ_name[4] = (char)i+48;
		for (j=0; j<num_kvnos; j++) {
			char *unparsed_name;
			code = krb5_kt_next_entry(krb5_ctx, keytab,
						  &kt_entry, &cursor);
			assert_int_equal(code, 0);
			assert_int_equal(kt_entry.vno, j+1);
#else
	/* MIT - For MEMORY type keytabs, krb5_kt_add_entry() adds an
	 * entry to the beginning of the keytab table, not the end */
	for (i=num_principals-1; i>=0; i--) {
		expect_princ_name[4] = (char)i+48;
		for (j=num_kvnos; j>0; j--) {
			char *unparsed_name;
			code = krb5_kt_next_entry(krb5_ctx, keytab,
						  &kt_entry, &cursor);
			assert_int_equal(code, 0);
			assert_int_equal(kt_entry.vno, j);
#endif
			krb5_unparse_name(krb5_ctx, kt_entry.principal,
					  &unparsed_name);
			assert_string_equal(expect_princ_name, unparsed_name);
		}
	}

	smb_krb5_remove_obsolete_keytab_entries(tmp_ctx, krb5_ctx, keytab,
						num_principals, principals,
						kvno, &found_previous,
						&error_str);

	code = krb5_kt_start_seq_get(krb5_ctx, keytab, &cursor);
	assert_int_equal(code, 0);
#ifdef SAMBA4_USES_HEIMDAL
	for (i=0; i<num_principals; i++) {
#else /* MIT - reverse iterate through entries */
	for (i=num_principals-1; i>=0; i--) {
#endif
		char *unparsed_name;
		expect_princ_name[4] = (char)i+48;
		code = krb5_kt_next_entry(krb5_ctx, keytab, &kt_entry, &cursor);
		assert_int_equal(code, 0);
		assert_int_equal(kt_entry.vno, kvno-1);
		krb5_unparse_name(krb5_ctx, kt_entry.principal, &unparsed_name);
		assert_string_equal(expect_princ_name, unparsed_name);
	}
	code = krb5_kt_next_entry(krb5_ctx, keytab, &kt_entry, &cursor);
	assert_int_not_equal(code, 0);
}

static void test_krb5_remove_obsolete_keytab_entries_many(void **state)
{
	internal_obsolete_keytab_test(5, 4, (krb5_kvno)5, "MEMORY:LOL2");
}

static void test_krb5_remove_obsolete_keytab_entries_one(void **state)
{
	internal_obsolete_keytab_test(1, 2, (krb5_kvno)3, "MEMORY:LOL");
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_krb5_remove_obsolete_keytab_entries_one),
		cmocka_unit_test(test_krb5_remove_obsolete_keytab_entries_many),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
