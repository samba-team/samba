/* 
   Unix SMB/CIFS implementation.
   passdb testing utility

   Copyright (C) Wilco Baan Hofman 2006
   Copyright (C) Jelmer Vernooij 2006

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
#include "popt_common.h"
#include "passdb.h"

#include "../librpc/gen_ndr/drsblobs.h"
#include "../librpc/gen_ndr/ndr_drsblobs.h"
#include "../libcli/security/dom_sid.h"

#define TRUST_DOM "trustdom"
#define TRUST_PWD "trustpwd1232"
#define TRUST_SID "S-1-5-21-1111111111-2222222222-3333333333"

static bool samu_correct(struct samu *s1, struct samu *s2)
{
	bool ret = True;
	uint32 s1_len, s2_len;
	const char *s1_buf, *s2_buf;
	const uint8 *d1_buf, *d2_buf;

	/* Check Unix username */
	s1_buf = pdb_get_username(s1);
	s2_buf = pdb_get_username(s2);
	if (s2_buf == NULL && s1_buf != NULL) {
		DEBUG(0, ("Username is not set\n"));
		ret = False;
	} else if (s1_buf == NULL) {
		/* Do nothing */
	} else if (strcmp(s1_buf,s2_buf)) {
		DEBUG(0, ("Username not written correctly, want %s, got \"%s\"\n",
					pdb_get_username(s1),
					pdb_get_username(s2)));
		ret = False;
	}

	/* Check NT username */
	s1_buf = pdb_get_nt_username(s1);
	s2_buf = pdb_get_nt_username(s2);
	if (s2_buf == NULL && s1_buf != NULL) {
		DEBUG(0, ("NT Username is not set\n"));
		ret = False;
	} else if (s1_buf == NULL) {
		/* Do nothing */
	} else if (strcmp(s1_buf, s2_buf)) {
		DEBUG(0, ("NT Username not written correctly, want \"%s\", got \"%s\"\n",
					pdb_get_nt_username(s1),
					pdb_get_nt_username(s2)));
		ret = False;
	}

	/* Check acct ctrl */
	if (pdb_get_acct_ctrl(s1) != pdb_get_acct_ctrl(s2)) {
		DEBUG(0, ("Acct ctrl field not written correctly, want %d (0x%X), got %d (0x%X)\n",
					pdb_get_acct_ctrl(s1),
					pdb_get_acct_ctrl(s1),
					pdb_get_acct_ctrl(s2),
					pdb_get_acct_ctrl(s2)));
		ret = False;
	}

	/* Check NT password */
	d1_buf = pdb_get_nt_passwd(s1);
	d2_buf = pdb_get_nt_passwd(s2);
	if (d2_buf == NULL && d1_buf != NULL) {
		DEBUG(0, ("NT password is not set\n"));
		ret = False;
	} else if (d1_buf == NULL) {
		/* Do nothing */
	} else if (memcmp(d1_buf, d2_buf, NT_HASH_LEN)) {
		DEBUG(0, ("NT password not written correctly\n"));
		ret = False;
	}

	/* Check lanman password */
	d1_buf = pdb_get_lanman_passwd(s1);
	d2_buf = pdb_get_lanman_passwd(s2);
	if (d2_buf == NULL && d1_buf != NULL) {
		DEBUG(0, ("Lanman password is not set\n"));
	} else if (d1_buf == NULL) {
		/* Do nothing */
	} else if (memcmp(d1_buf, d2_buf, NT_HASH_LEN)) {
		DEBUG(0, ("Lanman password not written correctly\n"));
		ret = False;
	}

	/* Check password history */
	d1_buf = pdb_get_pw_history(s1, &s1_len);
	d2_buf = pdb_get_pw_history(s2, &s2_len);
	if (d2_buf == NULL && d1_buf != NULL) {
		DEBUG(0, ("Password history is not set\n"));
	} else if (d1_buf == NULL) {
		/* Do nothing */
	} else if (s1_len != s1_len) {
		DEBUG(0, ("Password history not written correctly, lengths differ, want %d, got %d\n",
					s1_len, s2_len));
		ret = False;
	} else if (strncmp(s1_buf, s2_buf, s1_len)) {
		DEBUG(0, ("Password history not written correctly\n"));
		ret = False;
	}

	/* Check logon time */
	if (pdb_get_logon_time(s1) != pdb_get_logon_time(s2)) {
		DEBUG(0, ("Logon time is not written correctly\n"));
		ret = False;
	}

	/* Check logoff time */
	if (pdb_get_logoff_time(s1) != pdb_get_logoff_time(s2)) {
		DEBUG(0, ("Logoff time is not written correctly\n"));
		ret = False;
	}

	/* Check kickoff time */
	if (pdb_get_kickoff_time(s1) != pdb_get_logoff_time(s2)) {
		DEBUG(0, ("Kickoff time is not written correctly\n"));
		ret = False;
	}

	/* Check bad password time */
	if (pdb_get_bad_password_time(s1) != pdb_get_bad_password_time(s2)) {
		DEBUG(0, ("Bad password time is not written correctly\n"));
		ret = False;
	}

	/* Check password last set time */
	if (pdb_get_pass_last_set_time(s1) != pdb_get_pass_last_set_time(s2)) {
		DEBUG(0, ("Password last set time is not written correctly\n"));
		ret = False;
	}

	/* Check password can change time */
	if (pdb_get_pass_can_change_time(s1) != pdb_get_pass_can_change_time(s2)) {
		DEBUG(0, ("Password can change time is not written correctly\n"));
		ret = False;
	}

	/* Check password must change time */
	if (pdb_get_pass_must_change_time(s1) != pdb_get_pass_must_change_time(s2)) {
		DEBUG(0, ("Password must change time is not written correctly\n"));
		ret = False;
	}

	/* Check logon divs */
	if (pdb_get_logon_divs(s1) != pdb_get_logon_divs(s2)) {
		DEBUG(0, ("Logon divs not written correctly\n"));
		ret = False;
	}

	/* Check logon hours */
	if (pdb_get_hours_len(s1) != pdb_get_hours_len(s2)) {
		DEBUG(0, ("Logon hours length not written correctly\n"));
		ret = False;
	} else if (pdb_get_hours_len(s1) != 0) {
		d1_buf = pdb_get_hours(s1);
		d2_buf = pdb_get_hours(s2);
		if (d2_buf == NULL && d2_buf != NULL) {
			DEBUG(0, ("Logon hours is not set\n"));
			ret = False;
		} else if (d1_buf == NULL) {
			/* Do nothing */
		} else if (memcmp(d1_buf, d2_buf, MAX_HOURS_LEN)) {
			DEBUG(0, ("Logon hours is not written correctly\n"));
			ret = False;
		}
	}

	/* Check profile path */
	s1_buf = pdb_get_profile_path(s1);
	s2_buf = pdb_get_profile_path(s2);
	if (s2_buf == NULL && s1_buf != NULL) {
		DEBUG(0, ("Profile path is not set\n"));
		ret = False;
	} else if (s1_buf == NULL) {
		/* Do nothing */
	} else if (strcmp(s1_buf, s2_buf)) {
		DEBUG(0, ("Profile path is not written correctly\n"));
		ret = False;
	}

	/* Check home dir */
	s1_buf = pdb_get_homedir(s1);
	s2_buf = pdb_get_homedir(s2);
	if (s2_buf == NULL && s1_buf != NULL) {
		DEBUG(0, ("Home dir is not set\n"));
		ret = False;
	} else if (s1_buf == NULL) {
		/* Do nothing */
	} else if (strcmp(s1_buf, s2_buf)) {
		DEBUG(0, ("Home dir is not written correctly\n"));
		ret = False;
	}

	/* Check logon script */
	s1_buf = pdb_get_logon_script(s1);
	s2_buf = pdb_get_logon_script(s2);
	if (s2_buf == NULL && s1_buf != NULL) {
		DEBUG(0, ("Logon script not set\n"));
		ret = False;
	} else if (s1_buf == NULL) {
		/* Do nothing */
	} else if (strcmp(s1_buf, s2_buf)) {
		DEBUG(0, ("Logon script is not written correctly\n"));
		ret = False;
	}

	/* TODO Check user and group sids */

	return ret;	
}

static bool test_trusted_domains(TALLOC_CTX *ctx,
				 struct pdb_methods *pdb,
				 bool *error)
{
	NTSTATUS rv;
	/* test trustdom calls */
	struct pdb_trusted_domain *td;
	struct pdb_trusted_domain *new_td;
	struct trustAuthInOutBlob taiob;
	struct AuthenticationInformation aia;
	enum ndr_err_code ndr_err;

	td = talloc_zero(ctx ,struct pdb_trusted_domain);
	if (!td) {
		fprintf(stderr, "talloc failed\n");
		return false;
	}

	td->domain_name = talloc_strdup(td, TRUST_DOM);
	td->netbios_name = talloc_strdup(td, TRUST_DOM);
	if (!td->domain_name || !td->netbios_name) {
		fprintf(stderr, "talloc failed\n");
		return false;
	}

	td->trust_auth_incoming = data_blob_null;

	ZERO_STRUCT(taiob);
	ZERO_STRUCT(aia);
	taiob.count = 1;
	taiob.current.count = 1;
	taiob.current.array = &aia;
	unix_to_nt_time(&aia.LastUpdateTime, time(NULL));
	aia.AuthType = TRUST_AUTH_TYPE_CLEAR;
	aia.AuthInfo.clear.password = (uint8_t *) talloc_strdup(ctx, TRUST_PWD);
	aia.AuthInfo.clear.size = strlen(TRUST_PWD);

	taiob.previous.count = 0;
	taiob.previous.array = NULL;

	ndr_err = ndr_push_struct_blob(&td->trust_auth_outgoing,
					td, &taiob,
			(ndr_push_flags_fn_t) ndr_push_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		fprintf(stderr, "ndr_push_struct_blob failed.\n");
		return false;
	}

	td->trust_direction = LSA_TRUST_DIRECTION_OUTBOUND;
	td->trust_type = LSA_TRUST_TYPE_DOWNLEVEL;
	td->trust_attributes = 0;
	td->trust_forest_trust_info = data_blob_null;

	rv = pdb->set_trusted_domain(pdb, TRUST_DOM, td);
	if (!NT_STATUS_IS_OK(rv)) {
		fprintf(stderr, "Error in set_trusted_domain %s\n",
				get_friendly_nt_error_msg(rv));
		*error = true;
	}

	rv = pdb->get_trusted_domain(pdb, ctx, TRUST_DOM, &new_td);
	if (!NT_STATUS_IS_OK(rv)) {
		fprintf(stderr, "Error in set_trusted_domain %s\n",
				get_friendly_nt_error_msg(rv));
		*error = true;
	}

	if (!strequal(td->domain_name, new_td->domain_name) ||
	    !strequal(td->netbios_name, new_td->netbios_name) ||
	    !dom_sid_equal(&td->security_identifier,
			   &new_td->security_identifier) ||
	    td->trust_direction != new_td->trust_direction ||
	    td->trust_type != new_td->trust_type ||
	    td->trust_attributes != new_td->trust_attributes ||
	    td->trust_auth_incoming.length != new_td->trust_auth_incoming.length ||
	    td->trust_forest_trust_info.length != new_td->trust_forest_trust_info.length ||
	    data_blob_cmp(&td->trust_auth_outgoing, &new_td->trust_auth_outgoing) != 0) {
		fprintf(stderr, "Old and new trusdet domain data do not match\n");
		*error = true;
	}

	return true;
}


int main(int argc, char **argv)
{
	TALLOC_CTX *ctx;
	struct samu *out = NULL;
	struct samu *in = NULL;
	NTSTATUS rv;
	int i;
	struct timeval tv;
	bool error = False;
	struct passwd *pwd;
	uint8 *buf;
	uint32 expire, min_age, history;
	struct pdb_methods *pdb;
	poptContext pc;
	static const char *backend = NULL;
	static const char *unix_user = "nobody";
	struct poptOption long_options[] = {
		{"username", 'u', POPT_ARG_STRING, &unix_user, 0, "Unix user to use for testing", "USERNAME" },
		{"backend", 'b', POPT_ARG_STRING, &backend, 0, "Backend to use if not default", "BACKEND[:SETTINGS]" },
		POPT_AUTOHELP
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};

	load_case_tables();

	pc = poptGetContext("pdbtest", argc, (const char **) argv,
			    long_options, 0);

	poptSetOtherOptionHelp(pc, "backend[:settings] username");

	while(poptGetNextOpt(pc) != -1);

	poptFreeContext(pc);

	/* Load configuration */
	lp_load_global(get_dyn_CONFIGFILE());
	setup_logging("pdbtest", DEBUG_STDOUT);

	if (backend == NULL) {
		backend = lp_passdb_backend();
	}

	rv = make_pdb_method_name(&pdb, backend);
	if (NT_STATUS_IS_ERR(rv)) {
		fprintf(stderr, "Error initializing '%s': %s\n", backend, get_friendly_nt_error_msg(rv));
		exit(1);
	}

	ctx = talloc_init("PDBTEST");

	if (!(out = samu_new(ctx))) {
		fprintf(stderr, "Can't create samu structure.\n");
		exit(1);
	}

	if ((pwd = Get_Pwnam_alloc(ctx, unix_user)) == NULL) {
		fprintf(stderr, "Error getting user information for %s\n", unix_user);
		exit(1);
	}

	samu_set_unix(out, pwd);

	pdb_set_profile_path(out, "\\\\torture\\profile", PDB_SET);
	pdb_set_homedir(out, "\\\\torture\\home", PDB_SET);
	pdb_set_logon_script(out, "torture_script.cmd", PDB_SET);

	pdb_get_account_policy(PDB_POLICY_PASSWORD_HISTORY, &history);
	if (history * PW_HISTORY_ENTRY_LEN < NT_HASH_LEN) {
		buf = (uint8 *)TALLOC(ctx, NT_HASH_LEN);
	} else {
		buf = (uint8 *)TALLOC(ctx, history * PW_HISTORY_ENTRY_LEN);
	}

	/* Generate some random hashes */
	GetTimeOfDay(&tv);
	srand(tv.tv_usec);
	for (i = 0; i < NT_HASH_LEN; i++) {
		buf[i] = (uint8) rand();
	}
	pdb_set_nt_passwd(out, buf, PDB_SET);
	for (i = 0; i < LM_HASH_LEN; i++) {
		buf[i] = (uint8) rand();
	}
	pdb_set_lanman_passwd(out, buf, PDB_SET);
	for (i = 0; i < history * PW_HISTORY_ENTRY_LEN; i++) {
		buf[i] = (uint8) rand();
	}
	pdb_set_pw_history(out, buf, history, PDB_SET);

	pdb_get_account_policy(PDB_POLICY_MAX_PASSWORD_AGE, &expire);
	pdb_get_account_policy(PDB_POLICY_MIN_PASSWORD_AGE, &min_age);
	pdb_set_pass_last_set_time(out, time(NULL), PDB_SET);

	if (min_age == (uint32)-1) {
		pdb_set_pass_can_change_time(out, 0, PDB_SET);
	} else {
		pdb_set_pass_can_change_time(out, time(NULL)+min_age, PDB_SET);
	}

	/* Create account */
	if (!NT_STATUS_IS_OK(rv = pdb->add_sam_account(pdb, out))) {
		fprintf(stderr, "Error in add_sam_account: %s\n", 
				get_friendly_nt_error_msg(rv));
		exit(1);
	}

	if (!(in = samu_new(ctx))) {
		fprintf(stderr, "Can't create samu structure.\n");
		exit(1);
	}

	/* Get account information through getsampwnam() */
	if (NT_STATUS_IS_ERR(pdb->getsampwnam(pdb, in, out->username))) {
		fprintf(stderr, "Error getting sampw of added user %s.\n",
				out->username);
		if (!NT_STATUS_IS_OK(rv = pdb->delete_sam_account(pdb, out))) {
			fprintf(stderr, "Error in delete_sam_account %s\n", 
					get_friendly_nt_error_msg(rv));
		}
		TALLOC_FREE(ctx);
	}

	/* Verify integrity */
	if (samu_correct(out, in)) {
		printf("User info written correctly\n");
	} else {
		printf("User info NOT written correctly\n");
		error = True;
	}

	/* Delete account */
	if (!NT_STATUS_IS_OK(rv = pdb->delete_sam_account(pdb, out))) {
		fprintf(stderr, "Error in delete_sam_account %s\n", 
					get_friendly_nt_error_msg(rv));
	}

	if (pdb_capabilities() & PDB_CAP_TRUSTED_DOMAINS_EX) {
		if (!test_trusted_domains(ctx, pdb, &error)) {
			fprintf(stderr, "failed testing trusted domains.\n");
			exit(1);
		}
	}

	TALLOC_FREE(ctx);

	if (error) {
		return 1;
	}
	return 0;
}
