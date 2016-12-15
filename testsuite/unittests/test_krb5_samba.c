#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <krb5.h>

#include "includes.h"
#include "lib/krb5_wrap/krb5_samba.h"


static int setup_krb5_context(void **state)
{
	krb5_context context = NULL;
	krb5_error_code code;

	code = krb5_init_context(&context);
	assert_return_code(code, code);

	*state = context;

	return 0;
}

static int teardown_krb5_context(void **state)
{
	krb5_context context = *state;

	if (context != NULL) {
		krb5_free_context(context);
	}
	return 0;
}

static void test_smb_krb5_kt_open(void **state)
{
	krb5_context context = *state;
	krb5_keytab keytab = NULL;
	krb5_error_code code;
	char keytab_template[] = "/tmp/keytab.XXXXXX";
	int fd;

	fd = mkstemp(keytab_template);
	assert_return_code(fd, errno);
	unlink(keytab_template);

	code = smb_krb5_kt_open(context,
				keytab_template,
				false,
				&keytab);
	assert_int_equal(code, 0);

	krb5_kt_close(context, keytab);
	close(fd);
}

static void test_smb_krb5_kt_open_file(void **state)
{
	krb5_context context = *state;
	krb5_keytab keytab = NULL;
	krb5_error_code code;
	char keytab_template[] = "/tmp/keytab.XXXXXX";
	char keytab_file[6 + strlen(keytab_template)];
	int fd;

	fd = mkstemp(keytab_template);
	assert_return_code(fd, errno);
	unlink(keytab_template);

	snprintf(keytab_file, sizeof(keytab_file), "FILE:%s", keytab_template);

	code = smb_krb5_kt_open(context,
				keytab_file,
				false,
				&keytab);
	assert_int_equal(code, 0);

	krb5_kt_close(context, keytab);
	close(fd);
}

static void test_smb_krb5_kt_open_fail(void **state)
{
	krb5_context context = *state;
	krb5_keytab keytab = NULL;
	krb5_error_code code;

	code = smb_krb5_kt_open(context,
				NULL,
				false,
				&keytab);
	assert_int_equal(code, KRB5_KT_BADNAME);
	code = smb_krb5_kt_open(context,
				"wurst",
				false,
				&keytab);
	assert_int_equal(code, KRB5_KT_BADNAME);

	code = smb_krb5_kt_open(context,
				"FILE:wurst",
				false,
				&keytab);
	assert_int_equal(code, KRB5_KT_BADNAME);

	code = smb_krb5_kt_open(context,
				"WRFILE:wurst",
				false,
				&keytab);
	assert_int_equal(code, KRB5_KT_BADNAME);
}

static void test_smb_krb5_kt_open_relative_memory(void **state)
{
	krb5_context context = *state;
	krb5_keytab keytab = NULL;
	krb5_error_code code;

	code = smb_krb5_kt_open_relative(context,
					 NULL,
					 true,
					 &keytab);
	assert_int_equal(code, 0);

	krb5_kt_close(context, keytab);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_smb_krb5_kt_open,
						setup_krb5_context,
						teardown_krb5_context),
		cmocka_unit_test_setup_teardown(test_smb_krb5_kt_open_file,
						setup_krb5_context,
						teardown_krb5_context),
		cmocka_unit_test_setup_teardown(test_smb_krb5_kt_open_fail,
						setup_krb5_context,
						teardown_krb5_context),
		cmocka_unit_test_setup_teardown(test_smb_krb5_kt_open_relative_memory,
						setup_krb5_context,
						teardown_krb5_context),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
