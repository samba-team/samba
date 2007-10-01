/*
   Unix SMB/CIFS implementation.
   SMB torture tester - winbind struct based protocol
   Copyright (C) Stefan Metzmacher 2007

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
#include "pstring.h"
#include "torture/torture.h"
#include "torture/winbind/proto.h"
#include "nsswitch/winbind_client.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/netlogon.h"
#include "param/param.h"
#include "auth/pam_errors.h"

#define DO_STRUCT_REQ_REP_EXT(op,req,rep,expected,strict,warnaction,cmt) do { \
	NSS_STATUS __got, __expected = (expected); \
	__got = winbindd_request_response(op, req, rep); \
	if (__got != __expected) { \
		const char *__cmt = (cmt); \
		if (strict) { \
			torture_result(torture, TORTURE_FAIL, \
				__location__ ": " __STRING(op) \
				" returned %d, expected %d%s%s", \
				__got, __expected, \
				(__cmt) ? ": " : "", \
				(__cmt) ? (__cmt) : ""); \
			return false; \
		} else { \
			torture_warning(torture, \
				__location__ ": " __STRING(op) \
				" returned %d, expected %d%s%s", \
				__got, __expected, \
				(__cmt) ? ": " : "", \
				(__cmt) ? (__cmt) : ""); \
			warnaction; \
		} \
	} \
} while(0)

#define DO_STRUCT_REQ_REP(op,req,rep) do { \
	bool __noop = false; \
	DO_STRUCT_REQ_REP_EXT(op,req,rep,NSS_STATUS_SUCCESS,true,__noop=true,NULL); \
} while (0)

static bool torture_winbind_struct_interface_version(struct torture_context *torture)
{
	struct winbindd_request req;
	struct winbindd_response rep;

	ZERO_STRUCT(req);
	ZERO_STRUCT(rep);

	torture_comment(torture, "Running WINBINDD_INTERFACE_VERSION (struct based)\n");

	DO_STRUCT_REQ_REP(WINBINDD_INTERFACE_VERSION, &req, &rep);

	torture_assert_int_equal(torture,
				 rep.data.interface_version,
				 WINBIND_INTERFACE_VERSION,
				 "winbind server and client doesn't match");

	return true;
}

static bool torture_winbind_struct_ping(struct torture_context *torture)
{
	struct timeval tv = timeval_current();
	int timelimit = torture_setting_int(torture, "timelimit", 5);
	uint32_t total = 0;

	torture_comment(torture,
			"Running WINBINDD_PING (struct based) for %d seconds\n",
			timelimit);

	while (timeval_elapsed(&tv) < timelimit) {
		DO_STRUCT_REQ_REP(WINBINDD_PING, NULL, NULL);
		total++;
	}

	torture_comment(torture,
			"%u (%.1f/s) WINBINDD_PING (struct based)\n",
			total, total / timeval_elapsed(&tv));

	return true;
}

static bool torture_winbind_struct_info(struct torture_context *torture)
{
	struct winbindd_response rep;
	const char *separator;

	ZERO_STRUCT(rep);

	torture_comment(torture, "Running WINBINDD_INFO (struct based)\n");

	DO_STRUCT_REQ_REP(WINBINDD_INFO, NULL, &rep);

	separator = torture_setting_string(torture,
					   "winbindd separator",
					   lp_winbind_separator(global_loadparm));
	torture_assert_int_equal(torture,
				 rep.data.info.winbind_separator,
				 *separator,
				 "winbind separator doesn't match");

	torture_comment(torture, "Samba Version '%s'\n",
			rep.data.info.samba_version);

	return true;
}

static bool torture_winbind_struct_priv_pipe_dir(struct torture_context *torture)
{
	struct winbindd_response rep;
	const char *default_dir;
	const char *expected_dir;
	const char *got_dir;

	ZERO_STRUCT(rep);

	torture_comment(torture, "Running WINBINDD_PRIV_PIPE_DIR (struct based)\n");

	DO_STRUCT_REQ_REP(WINBINDD_PRIV_PIPE_DIR, NULL, &rep);

	got_dir = (const char *)rep.extra_data.data;

	torture_assert(torture, got_dir, "NULL WINBINDD_PRIV_PIPE_DIR\n");

	default_dir = lock_path(torture, WINBINDD_PRIV_SOCKET_SUBDIR);
	expected_dir = torture_setting_string(torture,
					      "winbindd private pipe dir",
					      default_dir);

	torture_assert_str_equal(torture, got_dir, expected_dir,
				 "WINBINDD_PRIV_PIPE_DIR doesn't match");

	SAFE_FREE(rep.extra_data.data);
	return true;
}

static bool torture_winbind_struct_netbios_name(struct torture_context *torture)
{
	struct winbindd_response rep;
	const char *expected;

	ZERO_STRUCT(rep);

	torture_comment(torture, "Running WINBINDD_NETBIOS_NAME (struct based)\n");

	DO_STRUCT_REQ_REP(WINBINDD_NETBIOS_NAME, NULL, &rep);

	expected = torture_setting_string(torture,
					  "winbindd netbios name",
					  lp_netbios_name(global_loadparm));

	torture_assert_str_equal(torture,
				 rep.data.netbios_name, expected,
				 "winbindd's netbios name doesn't match");

	return true;
}

static bool torture_winbind_struct_domain_name(struct torture_context *torture)
{
	struct winbindd_response rep;
	const char *expected;

	ZERO_STRUCT(rep);

	torture_comment(torture, "Running WINBINDD_DOMAIN_NAME (struct based)\n");

	DO_STRUCT_REQ_REP(WINBINDD_DOMAIN_NAME, NULL, &rep);

	expected = torture_setting_string(torture,
					  "winbindd netbios domain",
					  lp_workgroup(global_loadparm));

	torture_assert_str_equal(torture,
				 rep.data.domain_name, expected,
				 "winbindd's netbios domain doesn't match");

	return true;
}

static bool torture_winbind_struct_check_machacc(struct torture_context *torture)
{
	bool ok;
	bool strict = torture_setting_bool(torture, "strict mode", false);
	struct winbindd_response rep;

	ZERO_STRUCT(rep);

	torture_comment(torture, "Running WINBINDD_CHECK_MACHACC (struct based)\n");

	ok = true;
	DO_STRUCT_REQ_REP_EXT(WINBINDD_CHECK_MACHACC, NULL, &rep,
			      NSS_STATUS_SUCCESS, strict, ok = false,
			      "WINBINDD_CHECK_MACHACC");

	if (!ok) {
		torture_assert(torture,
			       strlen(rep.data.auth.nt_status_string)>0,
			       "Failed with empty nt_status_string");

		torture_warning(torture,"%s:%s:%s:%d\n",
				nt_errstr(NT_STATUS(rep.data.auth.nt_status)),
				rep.data.auth.nt_status_string,
				rep.data.auth.error_string,
				rep.data.auth.pam_error);
		return true;
	}

	torture_assert_ntstatus_ok(torture,
				   NT_STATUS(rep.data.auth.nt_status),
				   "WINBINDD_CHECK_MACHACC ok: nt_status");

	torture_assert_str_equal(torture,
				 rep.data.auth.nt_status_string,
				 nt_errstr(NT_STATUS_OK),
				 "WINBINDD_CHECK_MACHACC ok:nt_status_string");

	torture_assert_str_equal(torture,
				 rep.data.auth.error_string,
				 nt_errstr(NT_STATUS_OK),
				 "WINBINDD_CHECK_MACHACC ok: error_string");

	torture_assert_int_equal(torture,
				 rep.data.auth.pam_error,
				 nt_status_to_pam(NT_STATUS_OK),
				 "WINBINDD_CHECK_MACHACC ok: pam_error");

	return true;
}

struct torture_trust_domain {
	const char *netbios_name;
	const char *dns_name;
	struct dom_sid *sid;
};

static bool get_trusted_domains(struct torture_context *torture,
				struct torture_trust_domain **_d)
{
	struct winbindd_request req;
	struct winbindd_response rep;
	struct torture_trust_domain *d = NULL;
	uint32_t dcount = 0;
	fstring line;
	const char *extra_data;

	ZERO_STRUCT(req);
	ZERO_STRUCT(rep);

	DO_STRUCT_REQ_REP(WINBINDD_LIST_TRUSTDOM, &req, &rep);

	extra_data = (char *)rep.extra_data.data;
	torture_assert(torture, extra_data, "NULL trust list");

	while (next_token(&extra_data, line, "\n", sizeof(fstring))) {
		char *p, *lp;

		d = talloc_realloc(torture, d,
				   struct torture_trust_domain,
				   dcount + 2);
		ZERO_STRUCT(d[dcount+1]);

		lp = line;
		p = strchr(lp, '\\');
		torture_assert(torture, p, "missing 1st '\\' in line");
		*p = 0;
		d[dcount].netbios_name = talloc_strdup(d, lp);
		torture_assert(torture, strlen(d[dcount].netbios_name) > 0,
			       "empty netbios_name");

		lp = p+1;
		p = strchr(lp, '\\');
		torture_assert(torture, p, "missing 2nd '\\' in line");
		*p = 0;
		d[dcount].dns_name = talloc_strdup(d, lp);
		/* it's ok to have an empty dns_name */

		lp = p+1;
		d[dcount].sid = dom_sid_parse_talloc(d, lp);
		torture_assert(torture, d[dcount].sid,
			       "failed to parse sid");

		dcount++;
	}
	SAFE_FREE(rep.extra_data.data);

	torture_assert(torture, dcount >= 2,
		       "The list of trusted domain should contain 2 entries");

	*_d = d;
	return true;
}

static bool torture_winbind_struct_list_trustdom(struct torture_context *torture)
{
	struct winbindd_request req;
	struct winbindd_response rep;
	char *list1;
	char *list2;
	bool ok;
	struct torture_trust_domain *listd = NULL;
	uint32_t i;

	torture_comment(torture, "Running WINBINDD_LIST_TRUSTDOM (struct based)\n");

	ZERO_STRUCT(req);
	ZERO_STRUCT(rep);

	req.data.list_all_domains = false;

	DO_STRUCT_REQ_REP(WINBINDD_LIST_TRUSTDOM, &req, &rep);

	list1 = (char *)rep.extra_data.data;
	torture_assert(torture, list1, "NULL trust list");

	torture_comment(torture, "%s\n", list1);

	ZERO_STRUCT(req);
	ZERO_STRUCT(rep);

	req.data.list_all_domains = true;

	DO_STRUCT_REQ_REP(WINBINDD_LIST_TRUSTDOM, &req, &rep);

	list2 = (char *)rep.extra_data.data;
	torture_assert(torture, list2, "NULL trust list");

	/*
	 * The list_all_domains parameter should be ignored
	 */
	torture_assert_str_equal(torture, list2, list1, "list_all_domains not ignored");

	SAFE_FREE(list1);
	SAFE_FREE(list2);

	ok = get_trusted_domains(torture, &listd);
	torture_assert(torture, ok, "failed to get trust list");

	for (i=0; listd[i].netbios_name; i++) {
		if (i == 0) {
			struct dom_sid *builtin_sid;

			builtin_sid = dom_sid_parse_talloc(torture, SID_BUILTIN);

			torture_assert_str_equal(torture,
						 listd[i].netbios_name,
						 NAME_BUILTIN,
						 "first domain should be 'BUILTIN'");

			torture_assert_str_equal(torture,
						 listd[i].dns_name,
						 "",
						 "BUILTIN domain should not have a dns name");

			ok = dom_sid_equal(builtin_sid,
					   listd[i].sid);
			torture_assert(torture, ok, "BUILTIN domain should have S-1-5-32");

			continue;
		}

		/*
		 * TODO: verify the content of the 2nd and 3rd (in member server mode)
		 *       domain entries
		 */
	}

	return true;
}

static bool torture_winbind_struct_domain_info(struct torture_context *torture)
{
	bool ok;
	struct torture_trust_domain *listd = NULL;
	uint32_t i;

	torture_comment(torture, "Running WINBINDD_DOMAIN_INFO (struct based)\n");

	ok = get_trusted_domains(torture, &listd);
	torture_assert(torture, ok, "failed to get trust list");

	for (i=0; listd[i].netbios_name; i++) {
		struct winbindd_request req;
		struct winbindd_response rep;
		struct dom_sid *sid;
		char *flagstr = talloc_strdup(torture," ");

		ZERO_STRUCT(req);
		ZERO_STRUCT(rep);

		fstrcpy(req.domain_name, listd[i].netbios_name);

		DO_STRUCT_REQ_REP(WINBINDD_DOMAIN_INFO, &req, &rep);

		torture_assert_str_equal(torture,
					 rep.data.domain_info.name,
					 listd[i].netbios_name,
					 "Netbios domain name doesn't match");

		torture_assert_str_equal(torture,
					 rep.data.domain_info.alt_name,
					 listd[i].dns_name,
					 "DNS domain name doesn't match");

		sid = dom_sid_parse_talloc(torture, rep.data.domain_info.sid);
		torture_assert(torture, sid, "Failed to parse SID");

		ok = dom_sid_equal(listd[i].sid, sid);
		torture_assert(torture, ok, "SID's doesn't match");

		if (rep.data.domain_info.primary) {
			flagstr = talloc_strdup_append(flagstr, "PR ");
		}

		if (rep.data.domain_info.active_directory) {
			torture_assert(torture,
				       strlen(rep.data.domain_info.alt_name)>0,
				       "Active Directory without DNS name");
			flagstr = talloc_strdup_append(flagstr, "AD ");
		}

		if (rep.data.domain_info.native_mode) {
			torture_assert(torture,
				       rep.data.domain_info.active_directory,
				       "Native-Mode, but no Active Directory");
			flagstr = talloc_strdup_append(flagstr, "NA ");
		}

		torture_comment(torture, "DOMAIN '%s' => '%s' [%s]\n",
				rep.data.domain_info.name,
				rep.data.domain_info.alt_name,
				flagstr);
	}

	return true;
}

static bool torture_winbind_struct_getdcname(struct torture_context *torture)
{
	bool ok;
	bool strict = torture_setting_bool(torture, "strict mode", false);
	struct torture_trust_domain *listd = NULL;
	uint32_t i;

	torture_comment(torture, "Running WINBINDD_GETDCNAME (struct based)\n");

	ok = get_trusted_domains(torture, &listd);
	torture_assert(torture, ok, "failed to get trust list");

	for (i=0; listd[i].netbios_name; i++) {
		struct winbindd_request req;
		struct winbindd_response rep;

		ZERO_STRUCT(req);
		ZERO_STRUCT(rep);

		fstrcpy(req.domain_name, listd[i].netbios_name);

		ok = true;
		DO_STRUCT_REQ_REP_EXT(WINBINDD_GETDCNAME, &req, &rep,
				      NSS_STATUS_SUCCESS,
				      (i <2 || strict), ok = false,
				      talloc_asprintf(torture, "DOMAIN '%s'",
				      		      req.domain_name));
		if (!ok) continue;

		/* TODO: check rep.data.dc_name; */
		torture_comment(torture, "DOMAIN '%s' => DCNAME '%s'\n",
				req.domain_name, rep.data.dc_name);
	}

	return true;
}

static bool torture_winbind_struct_dsgetdcname(struct torture_context *torture)
{
	bool ok;
	bool strict = torture_setting_bool(torture, "strict mode", false);
	struct torture_trust_domain *listd = NULL;
	uint32_t i;
	uint32_t count = 0;

	torture_comment(torture, "Running WINBINDD_DSGETDCNAME (struct based)\n");

	ok = get_trusted_domains(torture, &listd);
	torture_assert(torture, ok, "failed to get trust list");

	for (i=0; listd[i].netbios_name; i++) {
		struct winbindd_request req;
		struct winbindd_response rep;

		ZERO_STRUCT(req);
		ZERO_STRUCT(rep);

		if (strlen(listd[i].dns_name) == 0) continue;

		/*
		 * TODO: remove this and let winbindd give no dns name
		 *       for NT4 domains
		 */
		if (strcmp(listd[i].dns_name, listd[i].netbios_name) == 0) {
			continue;
		}

		fstrcpy(req.domain_name, listd[i].dns_name);

		/* TODO: test more flag combinations */
		req.flags = DS_DIRECTORY_SERVICE_REQUIRED;

		ok = true;
		DO_STRUCT_REQ_REP_EXT(WINBINDD_DSGETDCNAME, &req, &rep,
				      NSS_STATUS_SUCCESS,
				      strict, ok = false,
				      talloc_asprintf(torture, "DOMAIN '%s'",
						      req.domain_name));
		if (!ok) continue;

		/* TODO: check rep.data.dc_name; */
		torture_comment(torture, "DOMAIN '%s' => DCNAME '%s'\n",
				req.domain_name, rep.data.dc_name);

		count++;
	}

	if (count == 0) {
		torture_warning(torture, "WINBINDD_DSGETDCNAME"
				" was not tested with %d non-AD domains",
				i);
	}

	if (strict) {
		torture_assert(torture, count > 0,
			       "WiNBINDD_DSGETDCNAME was not tested");
	}

	return true;
}

static bool torture_winbind_struct_list_users(struct torture_context *torture)
{
	struct winbindd_request req;
	struct winbindd_response rep;

	torture_comment(torture, "Running WINBINDD_LIST_USERS (struct based)\n");

	ZERO_STRUCT(req);
	ZERO_STRUCT(rep);

	DO_STRUCT_REQ_REP(WINBINDD_LIST_USERS, &req, &rep);

	return true;
}

static bool torture_winbind_struct_list_groups(struct torture_context *torture)
{
	struct winbindd_request req;
	struct winbindd_response rep;

	torture_comment(torture, "Running WINBINDD_LIST_GROUPS (struct based)\n");

	ZERO_STRUCT(req);
	ZERO_STRUCT(rep);

	DO_STRUCT_REQ_REP(WINBINDD_LIST_GROUPS, &req, &rep);

	return true;
}

struct torture_domain_sequence {
	const char *netbios_name;
	uint32_t seq;
};

static bool torture_winbind_struct_show_sequence(struct torture_context *torture)
{
	struct winbindd_request req;
	struct winbindd_response rep;
	bool ok;
	const char *extra_data;
	fstring line;
	uint32_t i;
	uint32_t count = 0;
	struct torture_trust_domain *domlist = NULL;
	struct torture_domain_sequence *s = NULL;

	torture_comment(torture, "Running WINBINDD_SHOW_SEQUENCE (struct based)\n");

	torture_comment(torture, " - Running WINBINDD_SHOW_SEQUENCE without domain:\n");

	ZERO_STRUCT(req);
	ZERO_STRUCT(rep);

	DO_STRUCT_REQ_REP(WINBINDD_SHOW_SEQUENCE, &req, &rep);

	extra_data = (char *)rep.extra_data.data;
	torture_assert(torture, extra_data, "NULL sequence list");

	torture_comment(torture, "%s", extra_data);

	while (next_token(&extra_data, line, "\n", sizeof(fstring))) {
		char *p, *lp;
		uint32_t seq;

		s = talloc_realloc(torture, s, struct torture_domain_sequence,
				   count + 2);
		ZERO_STRUCT(s[count+1]);

		lp = line;
		p = strchr(lp, ' ');
		torture_assert(torture, p, "invalid line format");
		*p = 0;
		s[count].netbios_name = talloc_strdup(s, lp);

		lp = p+1;
		torture_assert(torture, strncmp(lp, ": ", 2) == 0, "invalid line format");
		lp += 2;
		if (strcmp(lp, "DISCONNECTED") == 0) {
			seq = (uint32_t)-1;
		} else {
			seq = (uint32_t)strtol(lp, &p, 10);
			torture_assert(torture, (*p == '\0'), "invalid line format");
			torture_assert(torture, (seq != (uint32_t)-1),
				       "sequence number -1 encountered");
		}
		s[count].seq = seq;

		count++;
	}

	torture_comment(torture, " - getting list of trusted domains\n");
	ok = get_trusted_domains(torture, &domlist);
	torture_assert(torture, ok, "failed to get trust list");

	for (i=0; domlist[i].netbios_name; i++) {
		uint32_t seq;

		ok = (s[i].netbios_name != NULL);
		torture_assert(torture, ok, "more domains recieved in second run");
		ok = (strcmp(domlist[i].netbios_name, s[i].netbios_name) == 0);
		torture_assert(torture, ok, "inconsistent order of domain lists");

		ZERO_STRUCT(req);
		ZERO_STRUCT(rep);

		fstrcpy(req.domain_name, domlist[i].netbios_name);

		torture_comment(torture, " - Running WINBINDD_SHOW_SEQUENCE "
				"for domain %s:\n", req.domain_name);

		DO_STRUCT_REQ_REP(WINBINDD_SHOW_SEQUENCE, &req, &rep);
		seq = rep.data.sequence_number;

		torture_comment(torture, "%s : ", req.domain_name);
		if (seq == (uint32_t)-1) {
			torture_comment(torture, "DISCONNECTED\n");
		} else {
			torture_comment(torture, "%d\n", seq);
		}
		torture_assert(torture, (seq >= s[i].seq),
			       "illegal sequence number encountered");
	}

	return true;
}

static bool torture_winbind_struct_setpwent(struct torture_context *torture)
{
	struct winbindd_request req;
	struct winbindd_response rep;

	torture_comment(torture, "Running WINBINDD_SETPWENT (struct based)\n");

	ZERO_STRUCT(req);
	ZERO_STRUCT(rep);

	DO_STRUCT_REQ_REP(WINBINDD_SETPWENT, &req, &rep);

	return true;
}

static bool torture_winbind_struct_endpwent(struct torture_context *torture)
{
	struct winbindd_request req;
	struct winbindd_response rep;

	torture_comment(torture, "Running WINBINDD_ENDPWENT (struct based)\n");

	ZERO_STRUCT(req);
	ZERO_STRUCT(rep);

	DO_STRUCT_REQ_REP(WINBINDD_ENDPWENT, &req, &rep);

	return true;
}

struct torture_suite *torture_winbind_struct_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "STRUCT");

	torture_suite_add_simple_test(suite, "INTERFACE_VERSION", torture_winbind_struct_interface_version);
	torture_suite_add_simple_test(suite, "PING", torture_winbind_struct_ping);
	torture_suite_add_simple_test(suite, "INFO", torture_winbind_struct_info);
	torture_suite_add_simple_test(suite, "PRIV_PIPE_DIR", torture_winbind_struct_priv_pipe_dir);
	torture_suite_add_simple_test(suite, "NETBIOS_NAME", torture_winbind_struct_netbios_name);
	torture_suite_add_simple_test(suite, "DOMAIN_NAME", torture_winbind_struct_domain_name);
	torture_suite_add_simple_test(suite, "CHECK_MACHACC", torture_winbind_struct_check_machacc);
	torture_suite_add_simple_test(suite, "LIST_TRUSTDOM", torture_winbind_struct_list_trustdom);
	torture_suite_add_simple_test(suite, "DOMAIN_INFO", torture_winbind_struct_domain_info);
	torture_suite_add_simple_test(suite, "GETDCNAME", torture_winbind_struct_getdcname);
	torture_suite_add_simple_test(suite, "DSGETDCNAME", torture_winbind_struct_dsgetdcname);
	torture_suite_add_simple_test(suite, "LIST_USERS", torture_winbind_struct_list_users);
	torture_suite_add_simple_test(suite, "LIST_GROUPS", torture_winbind_struct_list_groups);
	torture_suite_add_simple_test(suite, "SHOW_SEQUENCE", torture_winbind_struct_show_sequence);
	torture_suite_add_simple_test(suite, "SETPWENT", torture_winbind_struct_setpwent);
	torture_suite_add_simple_test(suite, "ENDPWENT", torture_winbind_struct_endpwent);

	suite->description = talloc_strdup(suite, "WINBIND - struct based protocol tests");

	return suite;
}
