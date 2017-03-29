/*
 * Copyright (c) 2015 Andreas Schneider <asn@samba.org>
 * Copyright (c) 2015 Jakub Hrozek <jakub.hrozek@posteo.se>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIBPAMTEST_H_
#define __LIBPAMTEST_H_

#include <stdint.h>
#include <security/pam_appl.h>

/**
 * @defgroup pamtest The pamtest API
 *
 * @{
 */

/**
 * @brief The enum which describes the operations performed by pamtest().
 */
enum pamtest_ops {
	/** run pam_authenticate to authenticate the account */
	PAMTEST_AUTHENTICATE,
	/** run pam_setcred() to establish/delete user credentials */
	PAMTEST_SETCRED,
	/** run pam_acct_mgmt() to validate the PAM account */
	PAMTEST_ACCOUNT,
	/** run pam_open_session() to start a PAM session */
	PAMTEST_OPEN_SESSION,
	/** run pam_close_session() to end a PAM session */
	PAMTEST_CLOSE_SESSION,
	/** run pam_chauthtok() to update the authentication token */
	PAMTEST_CHAUTHTOK,

	/**
	 * If this option is set the test will call pam_getenvlist() and copy
	 * the environment into case_out.envlist.
	 */
	PAMTEST_GETENVLIST = 20,
	/**
	 * This will prevent calling pam_end() and will just return the
	 * PAM handle in case_out.ph.
	 */
	PAMTEST_KEEPHANDLE,
};


/**
 * @brief The PAM testcase struction. Use the pam_test and pam_test_flags
 * macros to fill them.
 *
 * @see run_pamtest()
 */
struct pam_testcase {
	enum pamtest_ops pam_operation;	  /* The pam operation to run */
	int expected_rv;		  /* What we expect the op to return */
	int flags;			  /* Extra flags to pass to the op */

	int op_rv;			  /* What the op really returns */

	union {
		char **envlist;		/* output of PAMTEST_ENVLIST */
		pam_handle_t *ph;	/* output of PAMTEST_KEEPHANDLE */
	} case_out;		/* depends on pam_operation, mostly unused */
};

/** Initializes a pam_tescase structure. */
#define pam_test(op, expected) { op, expected, 0, 0, { .envlist = NULL } }
/** Initializes a CMUnitTest structure with additional PAM flags. */
#define pam_test_flags(op, expected, flags) { op, expected, flags, 0, { .envlist = NULL } }

/**
 * @brief The return code of the pamtest function
 */
enum pamtest_err {
	/** Testcases returns correspond with input */
	PAMTEST_ERR_OK,
	/** pam_start() failed */
	PAMTEST_ERR_START,
	/** A testcase failed. Use pamtest_failed_case */
	PAMTEST_ERR_CASE,
	/** Could not run a test case */
	PAMTEST_ERR_OP,
	/** pam_end failed */
	PAMTEST_ERR_END,
	/** Handled internally */
	PAMTEST_ERR_KEEPHANDLE,
	/** Internal error - bad input or similar */
	PAMTEST_ERR_INTERNAL,
};

/**
 * @brief PAM conversation function, defined in pam_conv(3)
 *
 * This is just a typedef to use in our declarations. See man pam_conv(3)
 * for more details.
 */
typedef int (*pam_conv_fn)(int num_msg,
			   const struct pam_message **msg,
			   struct pam_response **resp,
			   void *appdata_ptr);

/**
 * @brief This structure should be used when using run_pamtest,
 * which uses an internal conversation function.
 */
struct pamtest_conv_data {
	/** When the conversation function receives PAM_PROMPT_ECHO_OFF,
	 * it reads the auth token from the in_echo_off array and keeps
	 * an index internally.
	 */
	const char **in_echo_off;
	/** When the conversation function receives PAM_PROMPT_ECHO_ON,
	 * it reads the input from the in_echo_off array and keeps
	 * an index internally.
	 */
	const char **in_echo_on;

	/** Captures messages through PAM_TEXT_INFO. The test caller is
	 * responsible for allocating enough space in the array.
	 */
	char **out_err;
	/** Captures messages through PAM_ERROR_MSG. The test caller is
	 * responsible for allocating enough space in the array.
	 */
	char **out_info;
};

#ifdef DOXYGEN
/**
 * @brief      Run libpamtest test cases
 *
 * This is using the default libpamtest conversation function.
 *
 * @param[in]  service      The PAM service to use in the conversation
 *
 * @param[in]  user         The user to run conversation as
 *
 * @param[in]  conv_fn      Test-specific conversation function
 *
 * @param[in]  conv_userdata Test-specific conversation data
 *
 * @param[in]  test_cases   List of libpamtest test cases. Must end with
 *                          PAMTEST_CASE_SENTINEL
 *
 * @code
 * int main(void) {
 *     int rc;
 *     const struct pam_testcase tests[] = {
 *         pam_test(PAM_AUTHENTICATE, PAM_SUCCESS),
 *     };
 *
 *     rc = run_pamtest(tests, NULL, NULL);
 *
 *     return rc;
 * }
 * @endcode
 *
 * @return PAMTEST_ERR_OK on success, else the error code matching the failure.
 */
enum pamtest_err run_pamtest_conv(const char *service,
				  const char *user,
				  pam_conv_fn conv_fn,
				  void *conv_userdata,
				  struct pam_testcase test_cases[]);
#else
#define run_pamtest_conv(service, user, conv_fn, conv_data, test_cases) \
	_pamtest_conv(service, user, conv_fn, conv_data, test_cases, sizeof(test_cases)/sizeof(test_cases[0])
#endif

#ifdef DOXYGEN
/**
 * @brief      Run libpamtest test cases
 *
 * This is using the default libpamtest conversation function.
 *
 * @param[in]  service      The PAM service to use in the conversation
 *
 * @param[in]  user         The user to run conversation as
 *
 * @param[in]  conv_data    Test-specific conversation data
 *
 * @param[in]  test_cases   List of libpamtest test cases. Must end with
 *                          PAMTEST_CASE_SENTINEL
 *
 * @code
 * int main(void) {
 *     int rc;
 *     const struct pam_testcase tests[] = {
 *         pam_test(PAM_AUTHENTICATE, PAM_SUCCESS),
 *     };
 *
 *     rc = run_pamtest(tests, NULL, NULL);
 *
 *     return rc;
 * }
 * @endcode
 *
 * @return PAMTEST_ERR_OK on success, else the error code matching the failure.
 */
enum pamtest_err run_pamtest(const char *service,
			     const char *user,
			     struct pamtest_conv_data *conv_data,
			     struct pam_testcase test_cases[]);
#else
#define run_pamtest(service, user, conv_data, test_cases) \
	_pamtest(service, user, conv_data, test_cases, sizeof(test_cases)/sizeof(test_cases[0]))
#endif

#ifdef DOXYGEN
/**
 * @brief Helper you can call if run_pamtest() fails.
 *
 * If PAMTEST_ERR_CASE is returned by run_pamtest() you should call this
 * function get a pointer to the failed test case.
 *
 * @param[in]  test_cases The array of tests.
 *
 * @return a pointer to the array of test_cases[] that corresponds to the
 * first test case where the expected error code doesn't match the real error
 * code.
 */
const struct pam_testcase *pamtest_failed_case(struct pam_testcase *test_cases);
#else
#define pamtest_failed_case(test_cases) \
	_pamtest_failed_case(test_cases, sizeof(test_cases) / sizeof(test_cases[0]))
#endif

/**
 * @brief return a string representation of libpamtest error code.
 *
 * @param[in]  perr libpamtest error code
 *
 * @return String representation of the perr argument. Never returns NULL.
 */
const char *pamtest_strerror(enum pamtest_err perr);

/**
 * @brief This frees the string array returned by the PAMTEST_GETENVLIST test.
 *
 * @param[in]  envlist     The array to free.
 */
void pamtest_free_env(char **envlist);


/* Internal function protypes */
enum pamtest_err _pamtest_conv(const char *service,
			       const char *user,
			       pam_conv_fn conv_fn,
			       void *conv_userdata,
			       struct pam_testcase test_cases[],
			       size_t num_test_cases);

enum pamtest_err _pamtest(const char *service,
			  const char *user,
			  struct pamtest_conv_data *conv_data,
			  struct pam_testcase test_cases[],
			  size_t num_test_cases);

const struct pam_testcase *_pamtest_failed_case(struct pam_testcase test_cases[],
						size_t num_test_cases);

/** @} */

#endif /* __LIBPAMTEST_H_ */
