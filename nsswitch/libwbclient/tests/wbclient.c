/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Guenther Deschner 2009-2010

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

#include "lib/replace/replace.h"
#include "libcli/util/ntstatus.h"
#include "libcli/util/werror.h"
#include "lib/util/data_blob.h"
#include "lib/util/time.h"
#include "libcli/resolve/resolve.h"
#include "nsswitch/libwbclient/wbclient.h"
#include "torture/smbtorture.h"
#include "torture/winbind/proto.h"
#include "lib/util/util_net.h"
#include "lib/util/charset/charset.h"
#include "libcli/auth/libcli_auth.h"
#include "lib/param/param.h"
#include "lib/util/samba_util.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#define WBC_ERROR_EQUAL(x,y) (x == y)

#define torture_assert_wbc_equal(torture_ctx, got, expected, cmt, cmt_arg)	\
	do { wbcErr __got = got, __expected = expected; \
	if (!WBC_ERROR_EQUAL(__got, __expected)) { \
		torture_result(torture_ctx, TORTURE_FAIL, __location__": "#got" was %s, expected %s: " cmt, wbcErrorString(__got), wbcErrorString(__expected), cmt_arg); \
		return false; \
	} \
	} while (0)

#define torture_assert_wbc_ok(torture_ctx,expr,cmt,cmt_arg)			\
	torture_assert_wbc_equal(torture_ctx,expr,WBC_ERR_SUCCESS,cmt,cmt_arg)

#define torture_assert_wbc_equal_goto_fail(torture_ctx, got, expected, cmt, cmt_arg)	\
	do { wbcErr __got = got, __expected = expected; \
	if (!WBC_ERROR_EQUAL(__got, __expected)) { \
		torture_result(torture_ctx, TORTURE_FAIL, __location__": "#got" was %s, expected %s: " cmt, wbcErrorString(__got), wbcErrorString(__expected), cmt_arg); \
		goto fail;						\
	} \
	} while (0)

#define torture_assert_wbc_ok_goto_fail(torture_ctx,expr,cmt,cmt_arg)			\
	torture_assert_wbc_equal_goto_fail(torture_ctx,expr,WBC_ERR_SUCCESS,cmt,cmt_arg)

#define torture_assert_str_equal_goto_fail(torture_ctx,got,expected,cmt)\
	do { const char *__got = (got), *__expected = (expected); \
	if (strcmp(__got, __expected) != 0) { \
		torture_result(torture_ctx, TORTURE_FAIL, \
			__location__": "#got" was %s, expected %s: %s", \
			__got, __expected, cmt); \
		goto fail;;			 \
	} \
	} while(0)

static bool test_wbc_ping(struct torture_context *tctx)
{
	torture_assert_wbc_ok(tctx, wbcPing(),
		"%s", "wbcPing failed");

	return true;
}

static bool test_wbc_pingdc(struct torture_context *tctx)
{
	struct wbcInterfaceDetails *details = NULL;
	wbcErr ret = false;

	torture_assert_wbc_equal_goto_fail(tctx,
					   wbcPingDc("random_string", NULL),
					   WBC_ERR_DOMAIN_NOT_FOUND,
					   "%s",
					   "wbcPingDc failed");
	torture_assert_wbc_ok_goto_fail(tctx, wbcPingDc(NULL, NULL),
		"%s", "wbcPingDc failed");

	torture_assert_wbc_ok_goto_fail(tctx, wbcInterfaceDetails(&details),
		"%s", "wbcInterfaceDetails failed");
	torture_assert_goto(tctx, details, ret, fail,
		       "wbcInterfaceDetails returned NULL pointer");
	torture_assert_goto(tctx, details->netbios_domain, ret, fail,
		       "wbcInterfaceDetails returned NULL netbios_domain");

	torture_assert_wbc_ok_goto_fail(tctx,
					wbcPingDc(details->netbios_domain, NULL),
					"wbcPingDc(%s) failed",
					details->netbios_domain);

	torture_assert_wbc_ok_goto_fail(tctx,
					wbcPingDc("BUILTIN", NULL),
					"%s",
					"wbcPingDc(BUILTIN) failed");

	ret = true;
fail:
	wbcFreeMemory(details);
	return ret;
}

static bool test_wbc_pingdc2(struct torture_context *tctx)
{
	struct wbcInterfaceDetails *details = NULL;
	char *name = NULL;
	wbcErr ret = false;

	torture_assert_wbc_equal_goto_fail(tctx,
					   wbcPingDc2("random_string", NULL, &name),
					   WBC_ERR_DOMAIN_NOT_FOUND,
					   "%s",
					   "wbcPingDc2 failed");
	torture_assert_wbc_ok_goto_fail(tctx,
					wbcPingDc2(NULL, NULL, &name),
					"%s",
					"wbcPingDc2 failed");
	wbcFreeMemory(name);
	name = NULL;

	torture_assert_wbc_ok_goto_fail(tctx,
					wbcInterfaceDetails(&details),
					"%s",
					"wbcInterfaceDetails failed");
	torture_assert_goto(tctx,
			    details,
			    ret,
			    fail,
			    "wbcInterfaceDetails returned NULL pointer");
	torture_assert_goto(tctx,
			    details->netbios_domain,
			    ret,
			    fail,
			    "wbcInterfaceDetails returned NULL netbios_domain");

	torture_assert_wbc_ok_goto_fail(tctx,
					wbcPingDc2(details->netbios_domain, NULL, &name),
					"wbcPingDc2(%s) failed",
					details->netbios_domain);
	wbcFreeMemory(name);
	name = NULL;

	torture_assert_wbc_ok_goto_fail(tctx,
					wbcPingDc2("BUILTIN", NULL, &name),
					"%s",
					"wbcPingDc2(BUILTIN) failed");

	ret = true;
fail:
	wbcFreeMemory(name);
	wbcFreeMemory(details);

	return ret;
}

static bool test_wbc_library_details(struct torture_context *tctx)
{
	struct wbcLibraryDetails *details;

	torture_assert_wbc_ok(tctx, wbcLibraryDetails(&details),
		"%s", "wbcLibraryDetails failed");
	torture_assert(tctx, details,
		"wbcLibraryDetails returned NULL pointer");

	wbcFreeMemory(details);

	return true;
}

static bool test_wbc_interface_details(struct torture_context *tctx)
{
	struct wbcInterfaceDetails *details;

	torture_assert_wbc_ok(tctx, wbcInterfaceDetails(&details),
		"%s", "wbcInterfaceDetails failed");
	torture_assert(tctx, details,
		       "wbcInterfaceDetails returned NULL pointer");

	wbcFreeMemory(details);

	return true;
}

static bool test_wbc_sidtypestring(struct torture_context *tctx)
{
	torture_assert_str_equal(tctx, wbcSidTypeString(WBC_SID_NAME_USE_NONE),
				 "SID_NONE", "SID_NONE failed");
	torture_assert_str_equal(tctx, wbcSidTypeString(WBC_SID_NAME_USER),
				 "SID_USER", "SID_USER failed");
	torture_assert_str_equal(tctx, wbcSidTypeString(WBC_SID_NAME_DOM_GRP),
				 "SID_DOM_GROUP", "SID_DOM_GROUP failed");
	torture_assert_str_equal(tctx, wbcSidTypeString(WBC_SID_NAME_DOMAIN),
				 "SID_DOMAIN", "SID_DOMAIN failed");
	torture_assert_str_equal(tctx, wbcSidTypeString(WBC_SID_NAME_ALIAS),
				 "SID_ALIAS", "SID_ALIAS failed");
	torture_assert_str_equal(tctx, wbcSidTypeString(WBC_SID_NAME_WKN_GRP),
				 "SID_WKN_GROUP", "SID_WKN_GROUP failed");
	torture_assert_str_equal(tctx, wbcSidTypeString(WBC_SID_NAME_DELETED),
				 "SID_DELETED", "SID_DELETED failed");
	torture_assert_str_equal(tctx, wbcSidTypeString(WBC_SID_NAME_INVALID),
				 "SID_INVALID", "SID_INVALID failed");
	torture_assert_str_equal(tctx, wbcSidTypeString(WBC_SID_NAME_UNKNOWN),
				 "SID_UNKNOWN", "SID_UNKNOWN failed");
	torture_assert_str_equal(tctx, wbcSidTypeString(WBC_SID_NAME_COMPUTER),
				 "SID_COMPUTER",  "SID_COMPUTER failed");
	torture_assert_str_equal(tctx, wbcSidTypeString(WBC_SID_NAME_LABEL),
				 "SID_LABEL",  "SID_LABEL failed");
	return true;
}

static bool test_wbc_sidtostring(struct torture_context *tctx)
{
	struct wbcDomainSid sid;
	const char *sid_string = "S-1-5-32";
	char *sid_string2;

	torture_assert_wbc_ok(tctx, wbcStringToSid(sid_string, &sid),
			      "wbcStringToSid of %s failed", sid_string);
	torture_assert_wbc_ok(tctx, wbcSidToString(&sid, &sid_string2),
			      "wbcSidToString of %s failed", sid_string);
	torture_assert_str_equal(tctx, sid_string, sid_string2,
		"sid strings differ");
	wbcFreeMemory(sid_string2);

	return true;
}

static bool test_wbc_guidtostring(struct torture_context *tctx)
{
	struct wbcGuid guid;
	const char *guid_string = "f7cf07b4-1487-45c7-824d-8b18cc580811";
	char *guid_string2;

	torture_assert_wbc_ok(tctx, wbcStringToGuid(guid_string, &guid),
			      "wbcStringToGuid of %s failed", guid_string);
	torture_assert_wbc_ok(tctx, wbcGuidToString(&guid, &guid_string2),
			      "wbcGuidToString of %s failed", guid_string);
	torture_assert_str_equal(tctx, guid_string, guid_string2,
				 "guid strings differ");
	wbcFreeMemory(guid_string2);

	return true;
}

static bool test_wbc_domain_info(struct torture_context *tctx)
{
	struct wbcDomainInfo *info = NULL;
	struct wbcInterfaceDetails *details = NULL;
	wbcErr ret = false;

	torture_assert_wbc_ok_goto_fail(tctx,
					wbcInterfaceDetails(&details),
					"%s",
					"wbcInterfaceDetails failed");
	torture_assert_wbc_ok_goto_fail(tctx,
					wbcDomainInfo(details->netbios_domain, &info),
					"%s",
					"wbcDomainInfo failed");

	torture_assert_goto(tctx,
			    info,
			    ret,
			    fail,
			    "wbcDomainInfo returned NULL pointer");

	ret = true;
fail:
	wbcFreeMemory(details);
	wbcFreeMemory(info);

	return ret;
}

static bool test_wbc_users(struct torture_context *tctx)
{
	const char *domain_name = NULL;
	uint32_t num_users;
	const char **users = NULL;
	uint32_t i;
	struct wbcInterfaceDetails *details = NULL;
	struct wbcDomainSid *sids = NULL;
	char *domain = NULL;
	char *name = NULL;
	char *sid_string = NULL;
	wbcErr ret = false;
	char separator;

	torture_assert_wbc_ok(tctx, wbcInterfaceDetails(&details),
		"%s", "wbcInterfaceDetails failed");

	domain_name = talloc_strdup(tctx, details->netbios_domain);
	torture_assert_goto(tctx,
			    domain_name != NULL,
			    ret,
			    fail,
			    "Failed to allocate domain_name");
	separator = details->winbind_separator;
	wbcFreeMemory(details);
	details = NULL;

	torture_assert_wbc_ok_goto_fail(tctx,
					wbcListUsers(domain_name, &num_users, &users),
					"%s",
					"wbcListUsers failed");
	torture_assert_goto(tctx,
			    !(num_users > 0 && !users),
			    ret,
			    fail,
			    "wbcListUsers returned invalid results");

	for (i = 0; i < MIN(num_users, 100); i++) {
		struct wbcDomainSid sid;
		enum wbcSidType name_type;
		uint32_t num_sids;
		const char *user;
		char *c;

		c = strchr(users[i], separator);

		if (c == NULL) {
			/*
			 * NT4 DC
			 * user name does not contain DOMAIN SEPARATOR prefix.
			 */

			user = users[i];
		} else {
			/*
			 * AD DC
			 * user name starts with DOMAIN SEPARATOR prefix.
			 */
			const char *dom;

			*c = '\0';
			dom = users[i];
			user = c + 1;

			torture_assert_str_equal_goto(tctx, dom, domain_name,
						      ret, fail, "Domain part "
						      "of user name does not "
						      "match domain name.\n");
		}

		torture_assert_wbc_ok_goto_fail(tctx,
						wbcLookupName(domain_name, user,
							      &sid, &name_type),
						"wbcLookupName of %s failed",
						users[i]);
		torture_assert_int_equal_goto(tctx,
					      name_type, WBC_SID_NAME_USER,
					      ret,
					      fail,
					      "wbcLookupName expected WBC_SID_NAME_USER");
		wbcSidToString(&sid, &sid_string);
		torture_assert_wbc_ok_goto_fail(tctx,
						wbcLookupSid(&sid,
							     &domain,
							     &name,
							     &name_type),
						"wbcLookupSid of %s failed",
						sid_string);
		torture_assert_int_equal_goto(tctx,
					      name_type, WBC_SID_NAME_USER,
					      ret,
					      fail,
					      "wbcLookupSid of expected WBC_SID_NAME_USER");
		torture_assert_goto(tctx,
				    name,
				    ret,
				    fail,
				    "wbcLookupSid returned no name");
		wbcFreeMemory(domain);
		domain = NULL;
		wbcFreeMemory(name);
		name = NULL;

		torture_assert_wbc_ok_goto_fail(tctx,
						wbcLookupUserSids(&sid, true, &num_sids, &sids),
						"wbcLookupUserSids of %s failed", sid_string);
		torture_assert_wbc_ok_goto_fail(tctx,
						wbcGetDisplayName(&sid,
								  &domain,
								  &name,
								  &name_type),
						"wbcGetDisplayName of %s failed",
						sid_string);
		wbcFreeMemory(domain);
		domain = NULL;
		wbcFreeMemory(name);
		name = NULL;
		wbcFreeMemory(sids);
		sids = NULL;
		wbcFreeMemory(sid_string);
		sid_string = NULL;
	}

	ret = true;
fail:
	wbcFreeMemory(details);
	wbcFreeMemory(users);
	wbcFreeMemory(domain);
	wbcFreeMemory(name);
	wbcFreeMemory(sids);
	wbcFreeMemory(sid_string);

	return ret;
}

static bool test_wbc_groups(struct torture_context *tctx)
{
	wbcErr ret = false;
	const char *domain_name = NULL;
	uint32_t num_groups;
	const char **groups = NULL;
	uint32_t i;
	struct wbcInterfaceDetails *details = NULL;
	char *domain = NULL;
	char *name = NULL;
	char *sid_string = NULL;
	char separator;

	torture_assert_wbc_ok(tctx, wbcInterfaceDetails(&details),
			      "%s", "wbcInterfaceDetails failed");

	domain_name = talloc_strdup(tctx, details->netbios_domain);
	torture_assert_goto(tctx,
			    domain_name != NULL,
			    ret,
			    fail,
			    "Failed to allocate domain_name");
	separator = details->winbind_separator;
	wbcFreeMemory(details);
	details = NULL;

	torture_assert_wbc_ok_goto_fail(tctx,
					wbcListGroups(domain_name, &num_groups, &groups),
					"wbcListGroups in %s failed",
					domain_name);
	torture_assert_goto(tctx,
			    !(num_groups > 0 && !groups),
			    ret,
			    fail,
			    "wbcListGroups returned invalid results");

	for (i=0; i < MIN(num_groups,100); i++) {
		struct wbcDomainSid sid;
		enum wbcSidType name_type;
		const char *group;
		char *c;

		c = strchr(groups[i], separator);

		if (c == NULL) {
			/*
			 * NT4 DC
			 * group name does not contain DOMAIN SEPARATOR prefix.
			 */

			group = groups[i];
		} else {
			/*
			 * AD DC
			 * group name starts with DOMAIN SEPARATOR prefix.
			 */
			const char *dom;


			*c = '\0';
			dom = groups[i];
			group = c + 1;

			torture_assert_str_equal_goto(tctx, dom, domain_name,
						      ret, fail, "Domain part "
						      "of group name does not "
						      "match domain name.\n");
		}

		torture_assert_wbc_ok_goto_fail(tctx,
						wbcLookupName(domain_name,
							      group,
							      &sid,
							      &name_type),
						"wbcLookupName for %s failed",
						domain_name);
		wbcSidToString(&sid, &sid_string);
		torture_assert_wbc_ok_goto_fail(tctx,
						wbcLookupSid(&sid,
							     &domain,
							     &name,
							     &name_type),
						"wbcLookupSid of %s failed",
						sid_string);
		torture_assert_goto(tctx,
				    name,
				    ret,
				    fail,
				    "wbcLookupSid returned no name");

		wbcFreeMemory(domain);
		domain = NULL;
		wbcFreeMemory(name);
		name = NULL;
		wbcFreeMemory(sid_string);
		sid_string = NULL;
	}

	ret = true;
fail:
	wbcFreeMemory(details);
	wbcFreeMemory(groups);
	wbcFreeMemory(domain);
	wbcFreeMemory(name);
	wbcFreeMemory(sid_string);

	return ret;
}

static bool test_wbc_trusts(struct torture_context *tctx)
{
	struct wbcDomainInfo *domains = NULL;
	struct wbcAuthErrorInfo *error = NULL;
	size_t num_domains;
	uint32_t i;
	wbcErr ret = false;

	torture_assert_wbc_ok_goto_fail(tctx,
					wbcListTrusts(&domains, &num_domains),
					"%s",
					"wbcListTrusts failed");
	torture_assert_goto(tctx,
			    !(num_domains > 0 && !domains),
			    ret,
			    fail,
			    "wbcListTrusts returned invalid results");

	for (i=0; i < MIN(num_domains,100); i++) {

		/*
		struct wbcDomainSid sid;
		enum wbcSidType name_type;
		char *domain;
		char *name;
		*/
		torture_assert_wbc_ok_goto_fail(tctx,
						wbcCheckTrustCredentials(domains[i].short_name,
									 &error),
						"%s",
						"wbcCheckTrustCredentials failed");
		/*
		torture_assert_wbc_ok(tctx, wbcLookupName(domains[i].short_name, NULL, &sid, &name_type),
			"wbcLookupName failed");
		torture_assert_int_equal(tctx, name_type, WBC_SID_NAME_DOMAIN,
			"wbcLookupName expected WBC_SID_NAME_DOMAIN");
		torture_assert_wbc_ok(tctx, wbcLookupSid(&sid, &domain, &name, &name_type),
			"wbcLookupSid failed");
		torture_assert_int_equal(tctx, name_type, WBC_SID_NAME_DOMAIN,
			"wbcLookupSid expected WBC_SID_NAME_DOMAIN");
		torture_assert(tctx, name,
			"wbcLookupSid returned no name");
		*/
		wbcFreeMemory(error);
		error = NULL;
	}

	ret = true;
fail:
	wbcFreeMemory(domains);
	wbcFreeMemory(error);

	return ret;
}

static bool test_wbc_lookupdc(struct torture_context *tctx)
{
	const char *domain_name = NULL;
	struct wbcInterfaceDetails *details;
	struct wbcDomainControllerInfo *dc_info;

	torture_assert_wbc_ok(tctx, wbcInterfaceDetails(&details),
		"%s", "wbcInterfaceDetails failed");

	domain_name = talloc_strdup(tctx, details->netbios_domain);
	wbcFreeMemory(details);

	torture_assert_wbc_ok(tctx, wbcLookupDomainController(domain_name, 0, &dc_info),
			      "wbcLookupDomainController for %s failed", domain_name);
	wbcFreeMemory(dc_info);

	return true;
}

static bool test_wbc_lookupdcex(struct torture_context *tctx)
{
	const char *domain_name = NULL;
	struct wbcInterfaceDetails *details;
	struct wbcDomainControllerInfoEx *dc_info;

	torture_assert_wbc_ok(tctx, wbcInterfaceDetails(&details),
		"%s", "wbcInterfaceDetails failed");

	domain_name = talloc_strdup(tctx, details->netbios_domain);
	wbcFreeMemory(details);

	torture_assert_wbc_ok(tctx, wbcLookupDomainControllerEx(domain_name, NULL, NULL, 0, &dc_info),
		"wbcLookupDomainControllerEx for %s failed", domain_name);
	wbcFreeMemory(dc_info);

	return true;
}

static bool test_wbc_resolve_winsbyname(struct torture_context *tctx)
{
	const char *name;
	char *ip;
	wbcErr ret;

	name = torture_setting_string(tctx, "host", NULL);

	torture_comment(tctx, "test-WinsByName: host='%s'\n", name);

	ret = wbcResolveWinsByName(name, &ip);

	if (is_ipaddress(name)) {
		torture_assert_wbc_equal(tctx, ret, WBC_ERR_DOMAIN_NOT_FOUND, "wbcResolveWinsByName of %s failed", name);
	} else {
		torture_assert_wbc_ok(tctx, ret, "wbcResolveWinsByName for %s failed", name);
	}

	return true;
}

static bool test_wbc_resolve_winsbyip(struct torture_context *tctx)
{
	const char *ip;
	const char *host;
	struct nbt_name nbt_name;
	char *name;
	wbcErr ret;
	NTSTATUS status;

	host = torture_setting_string(tctx, "host", NULL);

	torture_comment(tctx, "test-WinsByIp: host='%s'\n", host);

	make_nbt_name_server(&nbt_name, host);

	status = resolve_name_ex(lpcfg_resolve_context(tctx->lp_ctx),
				 0, 0, &nbt_name, tctx, &ip, tctx->ev);
	torture_assert_ntstatus_ok(tctx, status,
			talloc_asprintf(tctx,"Failed to resolve %s: %s",
					nbt_name.name, nt_errstr(status)));

	torture_comment(tctx, "test-WinsByIp: ip='%s'\n", ip);

	ret = wbcResolveWinsByIP(ip, &name);

	torture_assert_wbc_ok(tctx, ret, "wbcResolveWinsByIP for %s failed", ip);

	wbcFreeMemory(name);

	return true;
}

static bool test_wbc_lookup_rids(struct torture_context *tctx)
{
	struct wbcDomainSid builtin;
	uint32_t rids[2] = { 544, 545 };
	const char *domain_name = NULL;
	const char **names = NULL;
	enum wbcSidType *types;
	wbcErr ret = false;

	wbcStringToSid("S-1-5-32", &builtin);

	ret = wbcLookupRids(&builtin, 2, rids, &domain_name, &names,
			    &types);
	torture_assert_wbc_ok_goto_fail(
		tctx, ret, "%s", "wbcLookupRids for 544 and 545 failed");

	torture_assert_str_equal(
		tctx, names[0], "Administrators",
		"S-1-5-32-544 not mapped to 'Administrators'");
	torture_assert_str_equal_goto_fail(
		tctx, names[1], "Users", "S-1-5-32-545 not mapped to 'Users'");

	ret = true;
fail:
	wbcFreeMemory(discard_const_p(char ,domain_name));
	wbcFreeMemory(names);
	wbcFreeMemory(types);
	return ret;
}

static bool test_wbc_get_sidaliases(struct torture_context *tctx)
{
	struct wbcDomainSid builtin;
	struct wbcDomainInfo *info = NULL;
	struct wbcInterfaceDetails *details = NULL;
	struct wbcDomainSid sids[2];
	uint32_t *rids = NULL;
	uint32_t num_rids;
	wbcErr ret = false;

	torture_assert_wbc_ok_goto_fail(tctx,
					wbcInterfaceDetails(&details),
					"%s",
					"wbcInterfaceDetails failed");
	torture_assert_wbc_ok_goto_fail(tctx,
					wbcDomainInfo(details->netbios_domain, &info),
					"wbcDomainInfo of %s failed",
					details->netbios_domain);

	sids[0] = info->sid;
	sids[0].sub_auths[sids[0].num_auths++] = 500;
	sids[1] = info->sid;
	sids[1].sub_auths[sids[1].num_auths++] = 512;

	torture_assert_wbc_ok_goto_fail(tctx,
					wbcStringToSid("S-1-5-32", &builtin),
					"wbcStringToSid of %s failed",
					"S-1-5-32");

	ret = wbcGetSidAliases(&builtin, sids, 2, &rids, &num_rids);
	torture_assert_wbc_ok_goto_fail(tctx,
					ret,
					"%s",
					"wbcGetSidAliases failed");

	ret = true;
fail:
	wbcFreeMemory(details);
	wbcFreeMemory(info);
	wbcFreeMemory(rids);
	return ret;
}

static bool test_wbc_authenticate_user_int(struct torture_context *tctx,
					   const char *correct_password)
{
	struct wbcAuthUserParams params;
	struct wbcAuthUserInfo *info = NULL;
	struct wbcAuthErrorInfo *error = NULL;
	wbcErr ret;

	ret = wbcAuthenticateUser(cli_credentials_get_username(
			popt_get_cmdline_credentials()), correct_password);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
		 "wbcAuthenticateUser of %s failed",
		 cli_credentials_get_username(popt_get_cmdline_credentials()));

	ZERO_STRUCT(params);
	params.account_name		=
		cli_credentials_get_username(popt_get_cmdline_credentials());
	params.level			= WBC_AUTH_USER_LEVEL_PLAIN;
	params.password.plaintext	= correct_password;

	ret = wbcAuthenticateUserEx(&params, &info, &error);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
				 "wbcAuthenticateUserEx of %s failed", params.account_name);
	wbcFreeMemory(info);
	info = NULL;

	wbcFreeMemory(error);
	error = NULL;

	params.password.plaintext       = "wrong";
	ret = wbcAuthenticateUserEx(&params, &info, &error);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_AUTH_ERROR,
				 "wbcAuthenticateUserEx for %s succeeded where it "
				 "should have failed", params.account_name);
	wbcFreeMemory(info);
	info = NULL;

	wbcFreeMemory(error);
	error = NULL;

	return true;
}

static bool test_wbc_authenticate_user(struct torture_context *tctx)
{
	return test_wbc_authenticate_user_int(tctx,
		cli_credentials_get_password(popt_get_cmdline_credentials()));
}

static bool test_wbc_change_password(struct torture_context *tctx)
{
	wbcErr ret;
	const char *oldpass =
		cli_credentials_get_password(popt_get_cmdline_credentials());
	const char *newpass = "Koo8irei%$";

	struct samr_CryptPassword new_nt_password;
	struct samr_CryptPassword new_lm_password;
	struct samr_Password old_nt_hash_enc;
	struct samr_Password old_lanman_hash_enc;

	gnutls_cipher_hd_t cipher_hnd = NULL;

	uint8_t old_nt_hash[16];
	uint8_t old_lanman_hash[16];
	uint8_t new_nt_hash[16];
	uint8_t new_lanman_hash[16];
	gnutls_datum_t old_nt_key = {
		.data = old_nt_hash,
		.size = sizeof(old_nt_hash),
	};

	struct wbcChangePasswordParams params;

	if (oldpass == NULL) {
		torture_skip(tctx,
			"skipping wbcChangeUserPassword test as old password cannot be retrieved\n");
	}

	ZERO_STRUCT(params);

	E_md4hash(oldpass, old_nt_hash);
	E_md4hash(newpass, new_nt_hash);

	if (lpcfg_client_lanman_auth(tctx->lp_ctx) &&
	    E_deshash(newpass, new_lanman_hash) &&
	    E_deshash(oldpass, old_lanman_hash)) {

		/* E_deshash returns false for 'long' passwords (> 14
		   DOS chars).  This allows us to match Win2k, which
		   does not store a LM hash for these passwords (which
		   would reduce the effective password length to 14) */

		encode_pw_buffer(new_lm_password.data, newpass, STR_UNICODE);

		gnutls_cipher_init(&cipher_hnd,
				   GNUTLS_CIPHER_ARCFOUR_128,
				   &old_nt_key,
				   NULL);
		gnutls_cipher_encrypt(cipher_hnd,
				      new_lm_password.data,
				      516);
		gnutls_cipher_deinit(cipher_hnd);

		E_old_pw_hash(new_nt_hash, old_lanman_hash,
			      old_lanman_hash_enc.hash);

		params.old_password.response.old_lm_hash_enc_length =
			sizeof(old_lanman_hash_enc.hash);
		params.old_password.response.old_lm_hash_enc_data =
			old_lanman_hash_enc.hash;
		params.new_password.response.lm_length =
			sizeof(new_lm_password.data);
		params.new_password.response.lm_data =
			new_lm_password.data;
	} else {
		ZERO_STRUCT(new_lm_password);
		ZERO_STRUCT(old_lanman_hash_enc);
	}

	encode_pw_buffer(new_nt_password.data, newpass, STR_UNICODE);

	gnutls_cipher_init(&cipher_hnd,
			   GNUTLS_CIPHER_ARCFOUR_128,
			   &old_nt_key,
			   NULL);
	gnutls_cipher_encrypt(cipher_hnd,
			      new_nt_password.data,
			      516);
	gnutls_cipher_deinit(cipher_hnd);

	E_old_pw_hash(new_nt_hash, old_nt_hash, old_nt_hash_enc.hash);

	params.old_password.response.old_nt_hash_enc_length =
		sizeof(old_nt_hash_enc.hash);
	params.old_password.response.old_nt_hash_enc_data =
		old_nt_hash_enc.hash;
	params.new_password.response.nt_length = sizeof(new_nt_password.data);
	params.new_password.response.nt_data = new_nt_password.data;

	params.level = WBC_CHANGE_PASSWORD_LEVEL_RESPONSE;
	params.account_name =
		cli_credentials_get_username(popt_get_cmdline_credentials());
	params.domain_name =
		cli_credentials_get_domain(popt_get_cmdline_credentials());

	ret = wbcChangeUserPasswordEx(&params, NULL, NULL, NULL);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
				 "wbcChangeUserPassword for %s failed", params.account_name);

	if (!test_wbc_authenticate_user_int(tctx, newpass)) {
		return false;
	}

	ret = wbcChangeUserPassword(
		cli_credentials_get_username(popt_get_cmdline_credentials()),
		newpass,
		cli_credentials_get_password(popt_get_cmdline_credentials()));
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
				 "wbcChangeUserPassword for %s failed", params.account_name);

	return test_wbc_authenticate_user_int(tctx,
		cli_credentials_get_password(popt_get_cmdline_credentials()));
}

static bool test_wbc_logon_user(struct torture_context *tctx)
{
	struct wbcLogonUserParams params;
	struct wbcLogonUserInfo *info = NULL;
	struct wbcAuthErrorInfo *error = NULL;
	struct wbcUserPasswordPolicyInfo *policy = NULL;
	struct wbcInterfaceDetails *iface;
	struct wbcDomainSid sid;
	enum wbcSidType sidtype;
	char *sidstr;
	wbcErr ret;

	ZERO_STRUCT(params);

	ret = wbcLogonUser(&params, &info, &error, &policy);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_INVALID_PARAM,
				 "%s", "wbcLogonUser succeeded for NULL where it should "
				 "have failed");

	params.username =
		cli_credentials_get_username(popt_get_cmdline_credentials());
	params.password =
		cli_credentials_get_password(popt_get_cmdline_credentials());

	ret = wbcAddNamedBlob(&params.num_blobs, &params.blobs,
			      "foo", 0, discard_const_p(uint8_t, "bar"), 4);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
				 "%s", "wbcAddNamedBlob failed");

	ret = wbcLogonUser(&params, &info, &error, &policy);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
				 "wbcLogonUser for %s failed", params.username);
	wbcFreeMemory(info); info = NULL;
	wbcFreeMemory(error); error = NULL;
	wbcFreeMemory(policy); policy = NULL;

	params.password = "wrong";

	ret = wbcLogonUser(&params, &info, &error, &policy);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_AUTH_ERROR,
				 "wbcLogonUser for %s should have failed with "
				 "WBC_ERR_AUTH_ERROR", params.username);
	wbcFreeMemory(info); info = NULL;
	wbcFreeMemory(error); error = NULL;
	wbcFreeMemory(policy); policy = NULL;

	ret = wbcAddNamedBlob(&params.num_blobs, &params.blobs,
			      "membership_of", 0,
			      discard_const_p(uint8_t, "S-1-2-3-4"),
			      strlen("S-1-2-3-4")+1);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
				 "%s", "wbcAddNamedBlob failed");
	params.password =
		cli_credentials_get_password(popt_get_cmdline_credentials());
	ret = wbcLogonUser(&params, &info, &error, &policy);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_AUTH_ERROR,
				 "wbcLogonUser for %s should have failed with "
				 "WBC_ERR_AUTH_ERROR", params.username);
	wbcFreeMemory(info); info = NULL;
	wbcFreeMemory(error); error = NULL;
	wbcFreeMemory(policy); policy = NULL;
	wbcFreeMemory(params.blobs);
	params.blobs = NULL; params.num_blobs = 0;

	ret = wbcInterfaceDetails(&iface);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
				 "%s", "wbcInterfaceDetails failed");

	ret = wbcLookupName(iface->netbios_domain,
		cli_credentials_get_username(popt_get_cmdline_credentials()),
		&sid,
		&sidtype);
	wbcFreeMemory(iface);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
		"wbcLookupName for %s failed",
		cli_credentials_get_username(popt_get_cmdline_credentials()));

	ret = wbcSidToString(&sid, &sidstr);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
				 "%s", "wbcSidToString failed");

	ret = wbcAddNamedBlob(&params.num_blobs, &params.blobs,
			      "membership_of", 0,
			      (uint8_t *)sidstr, strlen(sidstr)+1);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
				 "%s", "wbcAddNamedBlob failed");
	wbcFreeMemory(sidstr);
	params.password =
		cli_credentials_get_password(popt_get_cmdline_credentials());
	ret = wbcLogonUser(&params, &info, &error, &policy);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
				 "wbcLogonUser for %s failed", params.username);
	wbcFreeMemory(info); info = NULL;
	wbcFreeMemory(error); error = NULL;
	wbcFreeMemory(policy); policy = NULL;
	wbcFreeMemory(params.blobs);
	params.blobs = NULL; params.num_blobs = 0;

	return true;
}

static bool test_wbc_getgroups(struct torture_context *tctx)
{
	wbcErr ret;
	uint32_t num_groups;
	gid_t *groups;

	ret = wbcGetGroups(
		cli_credentials_get_username(popt_get_cmdline_credentials()),
		&num_groups,
		&groups);
	torture_assert_wbc_equal(tctx, ret, WBC_ERR_SUCCESS,
		"wbcGetGroups for %s failed",
		cli_credentials_get_username(popt_get_cmdline_credentials()));
	wbcFreeMemory(groups);
	return true;
}

struct torture_suite *torture_wbclient(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "wbclient");

	torture_suite_add_simple_test(suite, "wbcPing", test_wbc_ping);
	torture_suite_add_simple_test(suite, "wbcPingDc", test_wbc_pingdc);
	torture_suite_add_simple_test(suite, "wbcPingDc2", test_wbc_pingdc2);
	torture_suite_add_simple_test(suite, "wbcLibraryDetails", test_wbc_library_details);
	torture_suite_add_simple_test(suite, "wbcInterfaceDetails", test_wbc_interface_details);
	torture_suite_add_simple_test(suite, "wbcSidTypeString", test_wbc_sidtypestring);
	torture_suite_add_simple_test(suite, "wbcSidToString", test_wbc_sidtostring);
	torture_suite_add_simple_test(suite, "wbcGuidToString", test_wbc_guidtostring);
	torture_suite_add_simple_test(suite, "wbcDomainInfo", test_wbc_domain_info);
	torture_suite_add_simple_test(suite, "wbcListUsers", test_wbc_users);
	torture_suite_add_simple_test(suite, "wbcListGroups", test_wbc_groups);
	torture_suite_add_simple_test(suite, "wbcListTrusts", test_wbc_trusts);
	torture_suite_add_simple_test(suite, "wbcLookupDomainController", test_wbc_lookupdc);
	torture_suite_add_simple_test(suite, "wbcLookupDomainControllerEx", test_wbc_lookupdcex);
	torture_suite_add_simple_test(suite, "wbcResolveWinsByName", test_wbc_resolve_winsbyname);
	torture_suite_add_simple_test(suite, "wbcResolveWinsByIP", test_wbc_resolve_winsbyip);
	torture_suite_add_simple_test(suite, "wbcLookupRids",
				      test_wbc_lookup_rids);
	torture_suite_add_simple_test(suite, "wbcGetSidAliases",
				      test_wbc_get_sidaliases);
	torture_suite_add_simple_test(suite, "wbcAuthenticateUser",
				      test_wbc_authenticate_user);
	torture_suite_add_simple_test(suite, "wbcLogonUser",
				      test_wbc_logon_user);
	torture_suite_add_simple_test(suite, "wbcChangeUserPassword",
				      test_wbc_change_password);
	torture_suite_add_simple_test(suite, "wbcGetGroups",
				      test_wbc_getgroups);

	return suite;
}
