#define TEST_USERNAME  "libnetusertest"

#define continue_if_field_set(field) \
	if (field != 0) { \
		i--; \
		continue; \
	}


#define FIELDS_NUM 15
enum test_fields { none = 0, account_name, full_name, description, home_directory, home_drive,
		   comment, logon_script, profile_path, acct_expiry, allow_password_change,
		   force_password_change, last_logon, last_logoff, last_password_change };


#define TEST_CHG_ACCOUNTNAME   "newlibnetusertest%02d"
#define TEST_CHG_DESCRIPTION   "Sample description %ld"
#define TEST_CHG_FULLNAME      "First%04x Last%04x"
#define TEST_CHG_COMMENT       "Comment[%04lu%04lu]"
#define TEST_CHG_PROFILEPATH   "\\\\srv%04ld\\profile%02u\\prof"
