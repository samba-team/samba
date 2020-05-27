/*
   Unix SMB/CIFS implementation.
   kerberos keytab utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Luke Howard 2003
   Copyright (C) Jim McDonough (jmcd@us.ibm.com) 2003
   Copyright (C) Guenther Deschner 2003
   Copyright (C) Rakesh Patel 2004
   Copyright (C) Dan Perry 2004
   Copyright (C) Jeremy Allison 2004
   Copyright (C) Gerald Carter 2006

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
#include "smb_krb5.h"
#include "ads.h"
#include "secrets.h"

#ifdef HAVE_KRB5

#ifdef HAVE_ADS

/* This MAX_NAME_LEN is a constant defined in krb5.h */
#ifndef MAX_KEYTAB_NAME_LEN
#define MAX_KEYTAB_NAME_LEN 1100
#endif

static krb5_error_code ads_keytab_open(krb5_context context,
				       krb5_keytab *keytab)
{
	char keytab_str[MAX_KEYTAB_NAME_LEN] = {0};
	const char *keytab_name = NULL;
	krb5_error_code ret = 0;

	switch (lp_kerberos_method()) {
	case KERBEROS_VERIFY_SYSTEM_KEYTAB:
	case KERBEROS_VERIFY_SECRETS_AND_KEYTAB:
		ret = krb5_kt_default_name(context,
					   keytab_str,
					   sizeof(keytab_str) - 2);
		if (ret != 0) {
			DBG_WARNING("Failed to get default keytab name");
			goto out;
		}
		keytab_name = keytab_str;
		break;
	case KERBEROS_VERIFY_DEDICATED_KEYTAB:
		keytab_name = lp_dedicated_keytab_file();
		break;
	default:
		DBG_ERR("Invalid kerberos method set (%d)\n",
			lp_kerberos_method());
		ret = KRB5_KT_BADNAME;
		goto out;
	}

	if (keytab_name == NULL || keytab_name[0] == '\0') {
		DBG_ERR("Invalid keytab name\n");
		ret = KRB5_KT_BADNAME;
		goto out;
	}

	ret = smb_krb5_kt_open(context, keytab_name, true, keytab);
	if (ret != 0) {
		DBG_WARNING("smb_krb5_kt_open failed (%s)\n",
			    error_message(ret));
		goto out;
	}

out:
	return ret;
}

static bool fill_default_spns(TALLOC_CTX *ctx, const char *machine_name,
                                          const char *my_fqdn, const char *spn,
					  const char ***spns)
{
	char *psp1, *psp2;

	if (*spns == NULL) {
		*spns = talloc_zero_array(ctx, const char*, 3);
		if (*spns == NULL) {
			return false;
		}
	}

	psp1 = talloc_asprintf(ctx,
			       "%s/%s",
			       spn,
			       machine_name);
	if (psp1 == NULL) {
		return false;
	}

	if (!strlower_m(&psp1[strlen(spn) + 1])) {
		return false;
	}
	(*spns)[0] = psp1;

	psp2 = talloc_asprintf(ctx,
			       "%s/%s",
			       spn,
			       my_fqdn);
	if (psp2 == NULL) {
		return false;
	}

	if (!strlower_m(&psp2[strlen(spn) + 1])) {
		return false;
	}

	(*spns)[1] = psp2;

	return true;
}

static bool ads_set_machine_account_spns(TALLOC_CTX *ctx,
					 ADS_STRUCT *ads,
					 const char *service_or_spn,
					 const char *my_fqdn)
{
	const char **spn_names = NULL;
	ADS_STATUS aderr;
	struct spn_struct* spn_struct = NULL;
	char *tmp = NULL;

	/* SPN should have '/' */
	tmp = strchr_m(service_or_spn, '/');
	if (tmp != NULL) {
		spn_struct = parse_spn(ctx, service_or_spn);
		if (spn_struct == NULL) {
			return false;
		}
	}

	DBG_INFO("Attempting to add/update '%s'\n", service_or_spn);

	if (spn_struct != NULL) {
		spn_names = talloc_zero_array(ctx, const char*, 2);
		spn_names[0] = service_or_spn;
	} else {
		bool ok;

		ok = fill_default_spns(ctx,
				       lp_netbios_name(),
				       my_fqdn,
				       service_or_spn,
				       &spn_names);
		if (!ok) {
			return false;
		}
	}
	aderr = ads_add_service_principal_names(ads,
						lp_netbios_name(),
						spn_names);
	if (!ADS_ERR_OK(aderr)) {
		DBG_WARNING("Failed to add service principal name.\n");
		return false;
	}

	return true;
}

/*
 * Create kerberos principal(s) from SPN or service name.
 */
static bool service_or_spn_to_kerberos_princ(TALLOC_CTX *ctx,
					     const char *service_or_spn,
					     const char *my_fqdn,
					     char **p_princ_s,
					     char **p_short_princ_s)
{
	char *princ_s = NULL;
	char *short_princ_s = NULL;
	const char *service = service_or_spn;
	const char *host = my_fqdn;
	struct spn_struct* spn_struct = NULL;
	char *tmp = NULL;
	bool ok = true;

	/* SPN should have '/' */
	tmp = strchr_m(service_or_spn, '/');
	if (tmp != NULL) {
		spn_struct = parse_spn(ctx, service_or_spn);
		if (spn_struct == NULL) {
			ok = false;
			goto out;
		}
	}
	if (spn_struct != NULL) {
		service = spn_struct->serviceclass;
		host = spn_struct->host;
	}
	princ_s = talloc_asprintf(ctx, "%s/%s@%s",
				  service,
				  host, lp_realm());
	if (princ_s == NULL) {
		ok = false;
		goto out;
	}

	if (spn_struct == NULL) {
		short_princ_s = talloc_asprintf(ctx, "%s/%s@%s",
					service, lp_netbios_name(),
					lp_realm());
		if (short_princ_s == NULL) {
			ok = false;
			goto out;
		}
	}
	*p_princ_s = princ_s;
	*p_short_princ_s = short_princ_s;
out:
	return ok;
}

static int add_kt_entry_etypes(krb5_context context, TALLOC_CTX *tmpctx,
			       ADS_STRUCT *ads, const char *salt_princ_s,
			       krb5_keytab keytab, krb5_kvno kvno,
			       const char *srvPrinc, const char *my_fqdn,
			       krb5_data *password, bool update_ads)
{
	krb5_error_code ret = 0;
	char *princ_s = NULL;
	char *short_princ_s = NULL;
	krb5_enctype enctypes[4] = {
#ifdef HAVE_ENCTYPE_AES256_CTS_HMAC_SHA1_96
		ENCTYPE_AES256_CTS_HMAC_SHA1_96,
#endif
#ifdef HAVE_ENCTYPE_AES128_CTS_HMAC_SHA1_96
		ENCTYPE_AES128_CTS_HMAC_SHA1_96,
#endif
		ENCTYPE_ARCFOUR_HMAC,
		0
	};
	size_t i;

	/* Construct our principal */
	if (strchr_m(srvPrinc, '@')) {
		/* It's a fully-named principal. */
		princ_s = talloc_asprintf(tmpctx, "%s", srvPrinc);
		if (!princ_s) {
			ret = -1;
			goto out;
		}
	} else if (srvPrinc[strlen(srvPrinc)-1] == '$') {
		/* It's the machine account, as used by smbclient clients. */
		princ_s = talloc_asprintf(tmpctx, "%s@%s",
					  srvPrinc, lp_realm());
		if (!princ_s) {
			ret = -1;
			goto out;
		}
	} else {
		/* It's a normal service principal.  Add the SPN now so that we
		 * can obtain credentials for it and double-check the salt value
		 * used to generate the service's keys. */

		if (!service_or_spn_to_kerberos_princ(tmpctx,
						      srvPrinc,
						      my_fqdn,
						      &princ_s,
						      &short_princ_s)) {
			ret = -1;
			goto out;
		}

		/* According to http://support.microsoft.com/kb/326985/en-us,
		   certain principal names are automatically mapped to the
		   host/... principal in the AD account.
		   So only create these in the keytab, not in AD.  --jerry */

		if (update_ads && !strequal(srvPrinc, "cifs") &&
		    !strequal(srvPrinc, "host")) {
			if (!ads_set_machine_account_spns(tmpctx,
							  ads,
							  srvPrinc,
							  my_fqdn)) {
				ret = -1;
				goto out;
			}
		}
	}

	for (i = 0; enctypes[i]; i++) {

		/* add the fqdn principal to the keytab */
		ret = smb_krb5_kt_add_entry(context,
					    keytab,
					    kvno,
					    princ_s,
					    salt_princ_s,
					    enctypes[i],
					    password,
					    false,
					    false);
		if (ret) {
			DBG_WARNING("Failed to add entry to keytab\n");
			goto out;
		}

		/* add the short principal name if we have one */
		if (short_princ_s) {
			ret = smb_krb5_kt_add_entry(context,
						    keytab,
						    kvno,
						    short_princ_s,
						    salt_princ_s,
						    enctypes[i],
						    password,
						    false,
						    false);
			if (ret) {
				DBG_WARNING("Failed to add short entry to keytab\n");
				goto out;
			}
		}
	}
out:
	return ret;
}

/**********************************************************************
 Adds a single service principal, i.e. 'host' to the system keytab
***********************************************************************/

int ads_keytab_add_entry(ADS_STRUCT *ads, const char *srvPrinc, bool update_ads)
{
	krb5_error_code ret = 0;
	krb5_context context = NULL;
	krb5_keytab keytab = NULL;
	krb5_data password;
	krb5_kvno kvno;
	char *salt_princ_s = NULL;
	char *password_s = NULL;
	char *my_fqdn;
	TALLOC_CTX *tmpctx = NULL;
	char **hostnames_array = NULL;
	size_t num_hostnames = 0;

	ret = smb_krb5_init_context_common(&context);
	if (ret) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(ret));
		return -1;
	}

	ret = ads_keytab_open(context, &keytab);
	if (ret != 0) {
		goto out;
	}

	/* retrieve the password */
	if (!secrets_init()) {
		DBG_WARNING("secrets_init failed\n");
		ret = -1;
		goto out;
	}
	password_s = secrets_fetch_machine_password(lp_workgroup(), NULL, NULL);
	if (!password_s) {
		DBG_WARNING("failed to fetch machine password\n");
		ret = -1;
		goto out;
	}
	ZERO_STRUCT(password);
	password.data = password_s;
	password.length = strlen(password_s);

	/* we need the dNSHostName value here */
	tmpctx = talloc_init(__location__);
	if (!tmpctx) {
		DBG_ERR("talloc_init() failed!\n");
		ret = -1;
		goto out;
	}

	my_fqdn = ads_get_dnshostname(ads, tmpctx, lp_netbios_name());
	if (!my_fqdn) {
		DBG_ERR("unable to determine machine account's dns name in "
			"AD!\n");
		ret = -1;
		goto out;
	}

	/* make sure we have a single instance of a the computer account */
	if (!ads_has_samaccountname(ads, tmpctx, lp_netbios_name())) {
		DBG_ERR("unable to determine machine account's short name in "
			"AD!\n");
		ret = -1;
		goto out;
	}

	kvno = (krb5_kvno)ads_get_machine_kvno(ads, lp_netbios_name());
	if (kvno == -1) {
		/* -1 indicates failure, everything else is OK */
		DBG_WARNING("ads_get_machine_kvno failed to determine the "
			    "system's kvno.\n");
		ret = -1;
		goto out;
	}

	salt_princ_s = kerberos_secrets_fetch_salt_princ();
	if (salt_princ_s == NULL) {
		DBG_WARNING("kerberos_secrets_fetch_salt_princ() failed\n");
		ret = -1;
		goto out;
	}

	ret = add_kt_entry_etypes(context, tmpctx, ads, salt_princ_s, keytab,
				  kvno, srvPrinc, my_fqdn, &password,
				  update_ads);
	if (ret != 0) {
		goto out;
	}

	if (ADS_ERR_OK(ads_get_additional_dns_hostnames(tmpctx, ads,
							lp_netbios_name(),
							&hostnames_array,
							&num_hostnames))) {
		size_t i;

		for (i = 0; i < num_hostnames; i++) {

			ret = add_kt_entry_etypes(context, tmpctx, ads,
						  salt_princ_s, keytab,
						  kvno, srvPrinc,
						  hostnames_array[i],
						  &password, update_ads);
			if (ret != 0) {
				goto out;
			}
		}
	}

out:
	SAFE_FREE(salt_princ_s);
	TALLOC_FREE(tmpctx);

	if (keytab) {
		krb5_kt_close(context, keytab);
	}
	if (context) {
		krb5_free_context(context);
	}
	return (int)ret;
}

/**********************************************************************
 Flushes all entries from the system keytab.
***********************************************************************/

int ads_keytab_flush(ADS_STRUCT *ads)
{
	krb5_error_code ret = 0;
	krb5_context context = NULL;
	krb5_keytab keytab = NULL;
	krb5_kvno kvno;
	ADS_STATUS aderr;

	ret = smb_krb5_init_context_common(&context);
	if (ret) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(ret));
		return ret;
	}

	ret = ads_keytab_open(context, &keytab);
	if (ret != 0) {
		goto out;
	}

	kvno = (krb5_kvno)ads_get_machine_kvno(ads, lp_netbios_name());
	if (kvno == -1) {
		/* -1 indicates a failure */
		DEBUG(1, (__location__ ": Error determining the kvno.\n"));
		ret = -1;
		goto out;
	}

	/* Seek and delete old keytab entries */
	ret = smb_krb5_kt_seek_and_delete_old_entries(context,
						      keytab,
						      kvno,
						      ENCTYPE_NULL,
						      NULL,
						      NULL,
						      true,
						      false);
	if (ret) {
		goto out;
	}

	aderr = ads_clear_service_principal_names(ads, lp_netbios_name());
	if (!ADS_ERR_OK(aderr)) {
		DEBUG(1, (__location__ ": Error while clearing service "
			  "principal listings in LDAP.\n"));
		ret = -1;
		goto out;
	}

out:
	if (keytab) {
		krb5_kt_close(context, keytab);
	}
	if (context) {
		krb5_free_context(context);
	}
	return ret;
}

/**********************************************************************
 Adds all the required service principals to the system keytab.
***********************************************************************/

int ads_keytab_create_default(ADS_STRUCT *ads)
{
	krb5_error_code ret = 0;
	krb5_context context = NULL;
	krb5_keytab keytab = NULL;
	krb5_kt_cursor cursor = {0};
	krb5_keytab_entry kt_entry = {0};
	krb5_kvno kvno;
	size_t found = 0;
	char *sam_account_name, *upn;
	char **oldEntries = NULL, *princ_s[26];
	TALLOC_CTX *frame;
	char *machine_name;
	char **spn_array;
	size_t num_spns;
	size_t i;
	bool ok = false;
	ADS_STATUS status;

	ZERO_STRUCT(kt_entry);
	ZERO_STRUCT(cursor);

	frame = talloc_stackframe();
	if (frame == NULL) {
		ret = -1;
		goto done;
	}

	status = ads_get_service_principal_names(frame,
						 ads,
						 lp_netbios_name(),
						 &spn_array,
						 &num_spns);
	if (!ADS_ERR_OK(status)) {
		ret = -1;
		goto done;
	}

	for (i = 0; i < num_spns; i++) {
		char *srv_princ;
		char *p;

		srv_princ = strlower_talloc(frame, spn_array[i]);
		if (srv_princ == NULL) {
			ret = -1;
			goto done;
		}

		p = strchr_m(srv_princ, '/');
		if (p == NULL) {
			continue;
		}
		p[0] = '\0';

		/* Add the SPNs found on the DC */
		ret = ads_keytab_add_entry(ads, srv_princ, false);
		if (ret != 0) {
			DEBUG(1, ("ads_keytab_add_entry failed while "
				  "adding '%s' principal.\n",
				  spn_array[i]));
			goto done;
		}
	}

#if 0	/* don't create the CIFS/... keytab entries since no one except smbd
	   really needs them and we will fall back to verifying against
	   secrets.tdb */

	ret = ads_keytab_add_entry(ads, "cifs", false));
	if (ret != 0 ) {
		DEBUG(1, (__location__ ": ads_keytab_add_entry failed while "
			  "adding 'cifs'.\n"));
		return ret;
	}
#endif

	memset(princ_s, '\0', sizeof(princ_s));

	ret = smb_krb5_init_context_common(&context);
	if (ret) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(ret));
		goto done;
	}

	machine_name = talloc_strdup(frame, lp_netbios_name());
	if (!machine_name) {
		ret = -1;
		goto done;
	}

	/* now add the userPrincipalName and sAMAccountName entries */
	ok = ads_has_samaccountname(ads, frame, machine_name);
	if (!ok) {
		DEBUG(0, (__location__ ": unable to determine machine "
			  "account's name in AD!\n"));
		ret = -1;
		goto done;
	}

	/*
	 * append '$' to netbios name so 'ads_keytab_add_entry' recognises
	 * it as a machine account rather than a service or Windows SPN.
	 */
	sam_account_name = talloc_asprintf(frame, "%s$",machine_name);
	if (sam_account_name == NULL) {
		ret = -1;
		goto done;
	}
	/* upper case the sAMAccountName to make it easier for apps to
	   know what case to use in the keytab file */
	if (!strupper_m(sam_account_name)) {
		ret = -1;
		goto done;
	}

	ret = ads_keytab_add_entry(ads, sam_account_name, false);
	if (ret != 0) {
		DEBUG(1, (__location__ ": ads_keytab_add_entry() failed "
			  "while adding sAMAccountName (%s)\n",
			  sam_account_name));
		goto done;
	}

	/* remember that not every machine account will have a upn */
	upn = ads_get_upn(ads, frame, machine_name);
	if (upn) {
		ret = ads_keytab_add_entry(ads, upn, false);
		if (ret != 0) {
			DEBUG(1, (__location__ ": ads_keytab_add_entry() "
				  "failed while adding UPN (%s)\n", upn));
			goto done;
		}
	}

	/* Now loop through the keytab and update any other existing entries */
	kvno = (krb5_kvno)ads_get_machine_kvno(ads, machine_name);
	if (kvno == (krb5_kvno)-1) {
		DEBUG(1, (__location__ ": ads_get_machine_kvno() failed to "
			  "determine the system's kvno.\n"));
		goto done;
	}

	DEBUG(3, (__location__ ": Searching for keytab entries to preserve "
		  "and update.\n"));

	ret = ads_keytab_open(context, &keytab);
	if (ret != 0) {
		goto done;
	}

	ret = krb5_kt_start_seq_get(context, keytab, &cursor);
	if (ret != KRB5_KT_END && ret != ENOENT ) {
		while ((ret = krb5_kt_next_entry(context, keytab,
						 &kt_entry, &cursor)) == 0) {
			smb_krb5_kt_free_entry(context, &kt_entry);
			ZERO_STRUCT(kt_entry);
			found++;
		}
	}
	krb5_kt_end_seq_get(context, keytab, &cursor);
	ZERO_STRUCT(cursor);

	/*
	 * Hmmm. There is no "rewind" function for the keytab. This means we
	 * have a race condition where someone else could add entries after
	 * we've counted them. Re-open asap to minimise the race. JRA.
	 */
	DEBUG(3, (__location__ ": Found %zd entries in the keytab.\n", found));
	if (!found) {
		goto done;
	}

	oldEntries = talloc_zero_array(frame, char *, found + 1);
	if (!oldEntries) {
		DEBUG(1, (__location__ ": Failed to allocate space to store "
			  "the old keytab entries (talloc failed?).\n"));
		ret = -1;
		goto done;
	}

	ret = krb5_kt_start_seq_get(context, keytab, &cursor);
	if (ret == KRB5_KT_END || ret == ENOENT) {
		krb5_kt_end_seq_get(context, keytab, &cursor);
		ZERO_STRUCT(cursor);
		goto done;
	}

	while (krb5_kt_next_entry(context, keytab, &kt_entry, &cursor) == 0) {
		if (kt_entry.vno != kvno) {
			char *ktprinc = NULL;
			char *p;

			/* This returns a malloc'ed string in ktprinc. */
			ret = smb_krb5_unparse_name(oldEntries, context,
						    kt_entry.principal,
						    &ktprinc);
			if (ret) {
				DEBUG(1, (__location__
					 ": smb_krb5_unparse_name failed "
					 "(%s)\n", error_message(ret)));
				goto done;
			}
			/*
			 * From looking at the krb5 source they don't seem to
			 * take locale or mb strings into account.
			 * Maybe this is because they assume utf8 ?
			 * In this case we may need to convert from utf8 to
			 * mb charset here ? JRA.
			 */
			p = strchr_m(ktprinc, '@');
			if (p) {
				*p = '\0';
			}

			p = strchr_m(ktprinc, '/');
			if (p) {
				*p = '\0';
			}
			for (i = 0; i < found; i++) {
				if (!oldEntries[i]) {
					oldEntries[i] = ktprinc;
					break;
				}
				if (!strcmp(oldEntries[i], ktprinc)) {
					TALLOC_FREE(ktprinc);
					break;
				}
			}
			if (i == found) {
				TALLOC_FREE(ktprinc);
			}
		}
		smb_krb5_kt_free_entry(context, &kt_entry);
		ZERO_STRUCT(kt_entry);
	}
	krb5_kt_end_seq_get(context, keytab, &cursor);
	ZERO_STRUCT(cursor);

	ret = 0;
	for (i = 0; oldEntries[i]; i++) {
		ret |= ads_keytab_add_entry(ads, oldEntries[i], false);
		TALLOC_FREE(oldEntries[i]);
	}

done:
	TALLOC_FREE(oldEntries);
	TALLOC_FREE(frame);

	if (context) {
		if (!all_zero((uint8_t *)&kt_entry, sizeof(kt_entry))) {
			smb_krb5_kt_free_entry(context, &kt_entry);
		}
		if (!all_zero((uint8_t *)&cursor, sizeof(cursor)) && keytab) {
			krb5_kt_end_seq_get(context, keytab, &cursor);
		}
		if (keytab) {
			krb5_kt_close(context, keytab);
		}
		krb5_free_context(context);
	}
	return ret;
}

#endif /* HAVE_ADS */

/**********************************************************************
 List system keytab.
***********************************************************************/

int ads_keytab_list(const char *keytab_name)
{
	krb5_error_code ret = 0;
	krb5_context context = NULL;
	krb5_keytab keytab = NULL;
	krb5_kt_cursor cursor;
	krb5_keytab_entry kt_entry;

	ZERO_STRUCT(kt_entry);
	ZERO_STRUCT(cursor);

	ret = smb_krb5_init_context_common(&context);
	if (ret) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(ret));
		return ret;
	}

	if (keytab_name == NULL) {
#ifdef HAVE_ADS
		ret = ads_keytab_open(context, &keytab);
#else
		ret = ENOENT;
#endif
	} else {
		ret = smb_krb5_kt_open(context, keytab_name, False, &keytab);
	}
	if (ret) {
		DEBUG(1, ("smb_krb5_kt_open failed (%s)\n",
			  error_message(ret)));
		goto out;
	}

	ret = krb5_kt_start_seq_get(context, keytab, &cursor);
	if (ret) {
		ZERO_STRUCT(cursor);
		goto out;
	}

	printf("Vno  Type                                        Principal\n");

	while (krb5_kt_next_entry(context, keytab, &kt_entry, &cursor) == 0) {

		char *princ_s = NULL;
		char *etype_s = NULL;
		krb5_enctype enctype = 0;

		ret = smb_krb5_unparse_name(talloc_tos(), context,
					    kt_entry.principal, &princ_s);
		if (ret) {
			goto out;
		}

		enctype = smb_krb5_kt_get_enctype_from_entry(&kt_entry);

		ret = smb_krb5_enctype_to_string(context, enctype, &etype_s);
		if (ret &&
		    (asprintf(&etype_s, "UNKNOWN: %d\n", enctype) == -1)) {
			TALLOC_FREE(princ_s);
			goto out;
		}

		printf("%3d  %-43s %s\n", kt_entry.vno, etype_s, princ_s);

		TALLOC_FREE(princ_s);
		SAFE_FREE(etype_s);

		ret = smb_krb5_kt_free_entry(context, &kt_entry);
		if (ret) {
			goto out;
		}
	}

	ret = krb5_kt_end_seq_get(context, keytab, &cursor);
	if (ret) {
		goto out;
	}

	/* Ensure we don't double free. */
	ZERO_STRUCT(kt_entry);
	ZERO_STRUCT(cursor);
out:

	if (!all_zero((uint8_t *)&kt_entry, sizeof(kt_entry))) {
		smb_krb5_kt_free_entry(context, &kt_entry);
	}
	if (!all_zero((uint8_t *)&cursor, sizeof(cursor)) && keytab) {
		krb5_kt_end_seq_get(context, keytab, &cursor);
	}

	if (keytab) {
		krb5_kt_close(context, keytab);
	}
	if (context) {
		krb5_free_context(context);
	}
	return ret;
}

#endif /* HAVE_KRB5 */
