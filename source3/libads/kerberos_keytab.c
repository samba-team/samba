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
#include "librpc/gen_ndr/ndr_secrets.h"

#ifdef HAVE_KRB5

#ifdef HAVE_ADS

/* This MAX_NAME_LEN is a constant defined in krb5.h */
#ifndef MAX_KEYTAB_NAME_LEN
#define MAX_KEYTAB_NAME_LEN 1100
#endif

enum spn_spec_type {
	SPN_SPEC_DEFAULT,
	SPN_SPEC_SYNC,
	SPN_SPEC_FULL,
	SPN_SPEC_PREFIX
};

/* pw2kt_conf contains 1 parsed line from "sync machine password to keytab" */
struct pw2kt_conf {
	enum spn_spec_type spn_spec;
	char *keytab;
	bool sync_etypes;
	bool sync_kvno;
	bool additional_dns_hostnames;
	bool netbios_aliases;
	bool machine_password;
	char **spn_spec_array;
	size_t num_spn_spec;
};

/* State used by pw2kt */
struct pw2kt_state {
	/* Array of parsed lines from "sync machine password to keytab" */
	struct pw2kt_conf *keytabs;
	size_t num_keytabs;
	bool sync_etypes;
	bool sync_kvno;
	bool sync_spns;
	/* These are from DC */
	krb5_kvno ad_kvno;
	uint32_t ad_etypes;
	char **ad_spn_array;
	size_t ad_num_spns;
	/* This is from secrets.db */
	struct secrets_domain_info1 *info;
};

/* State used by pw2kt_process_keytab */
struct pw2kt_process_state {
	krb5_keytab keytab;
	krb5_context context;
	krb5_keytab_entry *array1;
	krb5_keytab_entry *array2;
	krb5_principal *princ_array;
	krb5_enctype *enctypes;
	krb5_enctype preferred_etype;
};

static ADS_STATUS pw2kt_scan_add_spn(TALLOC_CTX *ctx,
				     const char *spn,
				     struct pw2kt_conf *conf)
{
	conf->spn_spec_array = talloc_realloc(ctx,
					      conf->spn_spec_array,
					      char *,
					      conf->num_spn_spec + 1);
	if (conf->spn_spec_array == NULL) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}
	conf->spn_spec_array[conf->num_spn_spec] = talloc_strdup(
		conf->spn_spec_array, spn);
	if (conf->spn_spec_array[conf->num_spn_spec] == NULL) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}
	conf->num_spn_spec++;

	return ADS_SUCCESS;
}

/*
 * Parse the smb.conf and find out if it is needed to read from DC:
 *  - servicePrincipalNames
 *  - msDs-KeyVersionNumber
 */
static ADS_STATUS pw2kt_scan_line(const char *line, struct pw2kt_state *state)
{
	char *keytabname = NULL;
	char *spn_spec = NULL;
	char *spn_val = NULL;
	char *option = NULL;
	struct pw2kt_conf *conf = NULL;
	ADS_STATUS status;

	state->keytabs = talloc_realloc(state,
					state->keytabs,
					struct pw2kt_conf,
					state->num_keytabs + 1);
	if (state->keytabs == NULL) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}
	conf = &state->keytabs[state->num_keytabs];
	state->num_keytabs++;

	keytabname = talloc_strdup(state->keytabs, line);
	if (keytabname == NULL) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	ZERO_STRUCT(*conf);
	conf->keytab = keytabname;
	spn_spec = strchr_m(keytabname, ':');
	if (spn_spec == NULL) {
		DBG_ERR("Invalid format! ':' expected in '%s'\n", keytabname);
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}
	*spn_spec++ = 0;

	/* reverse match with strrchr_m() */
	while ((option = strrchr_m(spn_spec, ':')) != NULL) {
		*option++ = 0;
		if (strequal(option, "sync_kvno")) {
			conf->sync_kvno = state->sync_kvno = true;
		} else if (strequal(option, "sync_etypes")) {
			conf->sync_etypes = state->sync_etypes = true;
		} else if (strequal(option, "additional_dns_hostnames")) {
			conf->additional_dns_hostnames = true;
		} else if (strequal(option, "netbios_aliases")) {
			conf->netbios_aliases = true;
		} else if (strequal(option, "machine_password")) {
			conf->machine_password = true;
		} else {
			DBG_WARNING("Unknown option '%s'!\n", option);
			return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}
	}

	spn_val = strchr_m(spn_spec, '=');
	if (spn_val != NULL) {
		*spn_val++ = 0;
	}

	if (strcmp(spn_spec, "account_name") == 0) {
		conf->spn_spec = SPN_SPEC_DEFAULT;
	} else if (strcmp(spn_spec, "sync_spns") == 0) {
		conf->spn_spec = SPN_SPEC_SYNC;
		state->sync_spns = true;
	} else if (strcmp(spn_spec, "spns") == 0 ||
		   strcmp(spn_spec, "spn_prefixes") == 0)
	{
		char *spn = NULL, *tmp = NULL;

		conf->spn_spec = strcmp(spn_spec, "spns") == 0
					 ? SPN_SPEC_FULL
					 : SPN_SPEC_PREFIX;
		conf->num_spn_spec = 0;
		spn = spn_val;
		while ((tmp = strchr_m(spn, ',')) != NULL) {
			*tmp++ = 0;
			status = pw2kt_scan_add_spn(state->keytabs, spn, conf);
			if (!ADS_ERR_OK(status)) {
				return status;
			}
			spn = tmp;
		}
		/* Do not forget the last entry */
		return pw2kt_scan_add_spn(state->keytabs, spn, conf);
	} else {
		DBG_WARNING("Invalid SPN specifier: %s\n", spn_spec);
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	return ADS_SUCCESS;
}

/*
 * Fill struct pw2kt_state with defaults if "sync machine password to keytab"
 * is missing in smb.conf
 */
static ADS_STATUS pw2kt_default_cfg(const char *name, struct pw2kt_state *state)
{
	char *keytabname = NULL;
	struct pw2kt_conf *conf = NULL;

	state->keytabs = talloc_zero_array(state->keytabs,
					   struct pw2kt_conf,
					   1);
	if (state->keytabs == NULL) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}
	conf = &state->keytabs[0];
	state->num_keytabs = 1;

	keytabname = talloc_strdup(state->keytabs, name);
	if (keytabname == NULL) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}

	conf->spn_spec = SPN_SPEC_SYNC;
	conf->keytab = keytabname;
	conf->machine_password = true;
	conf->sync_kvno = state->sync_kvno = true;
	state->sync_spns = true;

	return ADS_SUCCESS;
}

/*
 * For the given principal add to the array entries created from all pw->keys[]
 */
static krb5_error_code pw2kt_process_add_pw(
	struct pw2kt_process_state *state2,
	krb5_principal princ,
	krb5_kvno vno,
	struct secrets_domain_info1_password *pw)
{
	uint16_t i;
	size_t len = talloc_array_length(state2->array1);

	for (i = 0; i < pw->num_keys; i++) {
		krb5_keytab_entry *kt_entry = NULL;
		krb5_keyblock *key = NULL;
		krb5_keytab_entry *tmp_a = NULL;

		if (state2->preferred_etype != -1 &&
		    state2->preferred_etype != pw->keys[i].keytype)
		{
			DBG_DEBUG("Skip enc type '%d'.\n", pw->keys[i].keytype);
			continue;
		}

		len++;
		tmp_a = talloc_realloc(state2,
				       state2->array1,
				       krb5_keytab_entry,
				       len);
		if (tmp_a == NULL) {
			return ENOMEM;
		}
		state2->array1 = tmp_a;
		kt_entry = &state2->array1[len - 1];
		ZERO_STRUCT(*kt_entry);
		kt_entry->principal = princ;
		kt_entry->vno = vno;

		key = KRB5_KT_KEY(kt_entry);
		KRB5_KEY_TYPE(key) = pw->keys[i].keytype;
		KRB5_KEY_DATA(key) = pw->keys[i].value.data;
		KRB5_KEY_LENGTH(key) = pw->keys[i].value.length;
	}

	return 0;
}

/*
 * For the given principal add to the array entries based on password,
 * old_password, older_password and next_change->password.
 */
static krb5_error_code pw2kt_process_add_info(
	struct pw2kt_process_state *state2,
	krb5_kvno kvno,
	const char *princs,
	struct secrets_domain_info1 *info)
{
	krb5_error_code ret;
	krb5_principal princ = NULL;
	krb5_principal *a = NULL;
	size_t len;

	ret = smb_krb5_parse_name(state2->context, princs, &princ);
	if (ret != 0) {
		DBG_ERR("Failed to parse principal: %s\n", princs);
		return ret;
	}
	len = talloc_array_length(state2->princ_array);
	a = talloc_realloc(state2,
			   state2->princ_array,
			   krb5_principal,
			   len + 1);
	if (a == NULL) {
		(void)krb5_free_principal(state2->context, princ);
		return ENOMEM;
	}
	a[len] = princ;
	state2->princ_array = a;

#define ADD_PW(K, P)                                                     \
	if (info->P != NULL) {                                           \
		ret = pw2kt_process_add_pw(state2, princ, (K), info->P); \
		if (ret != 0) {                                          \
			DBG_ERR("Failed adding %s keys for %s.\n",       \
				#P,                                      \
				princs);                                 \
			return ret;                                      \
		}                                                        \
	}

	ADD_PW(kvno, password);
	ADD_PW(kvno - 1, old_password);
	ADD_PW(kvno - 2, older_password);
	if (info->next_change) {
		ADD_PW(kvno == -1 ? -4 : kvno + 1, next_change->password);
	}

	return ret;
}

static int pw2kt_process_state_destructor(struct pw2kt_process_state *state2)
{
	int i;
	size_t len2 = talloc_array_length(state2->array2);
	size_t len_p = talloc_array_length(state2->princ_array);

	for (i = 0; i < len2; i++) {
		(void)smb_krb5_kt_free_entry(state2->context,
					     &state2->array2[i]);
	}
	for (i = 0; i < len_p; i++) {
		(void)krb5_free_principal(state2->context,
					  state2->princ_array[i]);
	}
	(void)krb5_free_enctypes(state2->context, state2->enctypes);

	return 0;
}

/* Read the whole keytab to krb5_keytab_entry array */
static krb5_error_code pw2kt_process_kt2ar(struct pw2kt_process_state *state2)
{
	krb5_error_code ret = 0, ret2 = 0;
	krb5_kt_cursor cursor;
	krb5_keytab_entry *a = NULL;
	krb5_keytab_entry e;
	size_t num = 0;

	ZERO_STRUCT(cursor);

	ret = krb5_kt_start_seq_get(state2->context, state2->keytab, &cursor);
	if (ret != 0) {
		if (ret == KRB5_KT_END || ret == ENOENT) {
			ret = 0;
		}
		return ret;
	}

	for (;;) {
		ret = samba_krb5_kt_next_entry(state2->context,
					       state2->keytab,
					       &e,
					       &cursor);
		if (ret != 0) {
			break;
		}
		a = talloc_realloc(state2,
				   state2->array2,
				   krb5_keytab_entry,
				   num + 1);
		if (a == NULL) {
			smb_krb5_kt_free_entry(state2->context, &e);
			return ENOMEM;
		}
		a[num++] = e;
		state2->array2 = a;
	}

	if (ret == KRB5_KT_END || ret == ENOENT) {
		ret = 0;
	}
	ret2 = krb5_kt_end_seq_get(state2->context, state2->keytab, &cursor);

	return ret != 0 ? ret : ret2;
}

static ADS_STATUS pw2kt_process_keytab(struct pw2kt_state *state,
				       struct pw2kt_conf *keytabptr)
{
	krb5_error_code ret = 0;
	krb5_kvno kvno = -1;
	size_t i, j, len1 = 0, len2 = 0;
	char *princ_s = NULL;
	const char **netbios_alias = NULL;
	const char **addl_hostnames = NULL;
	size_t *index_array1 = NULL;
	size_t *index_array2 = NULL;
	struct pw2kt_process_state *state2 = NULL;

	if (!keytabptr->machine_password) {
		DBG_ERR("No 'machine_password' option for '%s'. Skip it.\n",
			keytabptr->keytab);
		return ADS_SUCCESS;
	}

	state2 = talloc_zero(state, struct pw2kt_process_state);
	if (state2 == NULL) {
		return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);
	}
	talloc_set_destructor(state2, pw2kt_process_state_destructor);

	ret = smb_krb5_init_context_common(&state2->context);
	if (ret != 0) {
		DBG_ERR("Krb init context failed (%s)\n", error_message(ret));
		return ADS_ERROR_KRB5(ret);
	}

#define MATCH_ENCTYPE(TYPES, TYPE)                               \
	({                                                       \
		int ei, result = 0;                              \
		for (ei = 0; (TYPES)[ei] != 0; ei++) {           \
			if ((uint32_t)(TYPES)[ei] != (TYPE)) {   \
				continue;                        \
			}                                        \
			result = 1;                              \
			break;                                   \
		}                                                \
		result;                                          \
	})

#define COMMON_ENCTYPE(ETYPE)                         \
	MATCH_ENCTYPE((state2->enctypes), (ETYPE)) && \
		((state->ad_etypes) & (ETYPE))

	/*
	 * -1 means there is no information about supported encryption types
	 * from DC and all encoding types will be added to the keytab.
	 */
	state2->preferred_etype = -1;

	/* Find the highest common enc type for AD and KRB5 lib */
	if (keytabptr->sync_etypes) {
		ret = smb_krb5_get_allowed_etypes(state2->context,
						  &state2->enctypes);
		if (ret != 0) {
			DBG_ERR("Failed to get allowed enc types.\n");
			return ADS_ERROR_KRB5(ret);
		}

		if (COMMON_ENCTYPE(ENCTYPE_AES256_CTS_HMAC_SHA1_96)) {
			state2->preferred_etype =
				ENCTYPE_AES256_CTS_HMAC_SHA1_96;
		} else if (COMMON_ENCTYPE(ENCTYPE_AES128_CTS_HMAC_SHA1_96)) {
			state2->preferred_etype =
				ENCTYPE_AES128_CTS_HMAC_SHA1_96;
		} else if (COMMON_ENCTYPE(ENCTYPE_ARCFOUR_HMAC)) {
			state2->preferred_etype = ENCTYPE_ARCFOUR_HMAC;
		} else {
			DBG_ERR("No common enctype for AD and KRB5 lib.\n");
			return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
		}
	}

	if (keytabptr->sync_kvno) {
		kvno = state->ad_kvno;
	}

#define ADD_INFO(P)                                                   \
	ret = pw2kt_process_add_info(state2, kvno, (P), state->info); \
	if (ret != 0) {                                               \
		return ADS_ERROR_KRB5(ret);                           \
	}

	/* Add ACCOUNTNAME$ entries */
	switch (keytabptr->spn_spec) {
	case SPN_SPEC_DEFAULT:
		ADD_INFO(state->info->account_name);
		break;
	case SPN_SPEC_SYNC:
		for (i = 0; i < state->ad_num_spns; i++) {
			ADD_INFO(state->ad_spn_array[i]);
		}
		break;
	case SPN_SPEC_FULL:
		for (i = 0; i < keytabptr->num_spn_spec; i++) {
			ADD_INFO(keytabptr->spn_spec_array[i]);
		}
		break;
	case SPN_SPEC_PREFIX:
		for (i = 0; i < keytabptr->num_spn_spec; i++) {
			princ_s = talloc_asprintf(talloc_tos(),
						  "%s/%s@%s",
						  keytabptr->spn_spec_array[i],
						  lp_netbios_name(),
						  lp_realm());
			if (princ_s == NULL) {
				return ADS_ERROR_KRB5(ENOMEM);
			}
			ADD_INFO(princ_s);

			if (!keytabptr->netbios_aliases) {
				goto additional_dns_hostnames;
			}
			for (netbios_alias = lp_netbios_aliases();
			     netbios_alias != NULL && *netbios_alias != NULL;
			     netbios_alias++)
			{
				/* Add PREFIX/netbiosname@REALM */
				princ_s = talloc_asprintf(
					talloc_tos(),
					"%s/%s@%s",
					keytabptr->spn_spec_array[i],
					*netbios_alias,
					lp_realm());
				if (princ_s == NULL) {
					return ADS_ERROR_KRB5(ENOMEM);
				}
				ADD_INFO(princ_s);

				/* Add PREFIX/netbiosname.domainname@REALM */
				princ_s = talloc_asprintf(
					talloc_tos(),
					"%s/%s.%s@%s",
					keytabptr->spn_spec_array[i],
					*netbios_alias,
					lp_dnsdomain(),
					lp_realm());
				if (princ_s == NULL) {
					return ADS_ERROR_KRB5(ENOMEM);
				}
				ADD_INFO(princ_s);
			}

additional_dns_hostnames:
			if (!keytabptr->additional_dns_hostnames) {
				continue;
			}
			for (addl_hostnames = lp_additional_dns_hostnames();
			     addl_hostnames != NULL && *addl_hostnames != NULL;
			     addl_hostnames++)
			{
				/* Add PREFIX/netbiosname@REALM */
				princ_s = talloc_asprintf(
					talloc_tos(),
					"%s/%s@%s",
					keytabptr->spn_spec_array[i],
					*addl_hostnames,
					lp_realm());
				if (princ_s == NULL) {
					return ADS_ERROR_KRB5(ENOMEM);
				}
				ADD_INFO(princ_s);
			}
		}
		break;
	default:
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	ret = smb_krb5_kt_open(state2->context,
			       keytabptr->keytab,
			       true,
			       &state2->keytab);
	if (ret != 0) {
		return ADS_ERROR_KRB5(ret);
	}

	/* The new entries are in array1. Read existing entries to array2. */
	ret = pw2kt_process_kt2ar(state2);
	if (ret != 0) {
		return ADS_ERROR_KRB5(ret);
	}

	len1 = talloc_array_length(state2->array1);
	len2 = talloc_array_length(state2->array2);

	if (keytabptr->sync_kvno) {
		goto sync_kvno;
	}

	/* copy existing entries VNO -1, -2, -3, -4 to VNO -11, -12, -13, -14 */
	for (j = 0; j < len2; j++) {
		krb5_keytab_entry e = state2->array2[j];
		/* vno type is 'krb5_kvno' which is 'unsigned int' */
		if (e.vno != -1 && e.vno != -2 && e.vno != -3 && e.vno != -4) {
			DBG_WARNING("Unexpected keytab entry with VNO = %d (it "
				    "should be -1, -2, -3, -4) in %s\n",
				    e.vno,
				    keytabptr->keytab);
			continue;
		}
		e.vno = state2->array2[j].vno - 10;
		ret = samba_krb5_kt_add_entry(state2->context,
					      state2->keytab,
					      &e);
		if (ret != 0) {
			return ADS_ERROR_KRB5(ret);
		}
	}
	/* remove all old entries (they should have VNO -1, -2, -3, -4) */
	for (j = 0; j < len2; j++) {
		krb5_keytab_entry e = state2->array2[j];
		if (e.vno != -1 && e.vno != -2 && e.vno != -3 && e.vno != -4) {
			DBG_WARNING("Unexpected keytab entry with VNO = %d (it "
				    "should be -1, -2, -3, -4) in %s\n",
				    e.vno,
				    keytabptr->keytab);
		}
		ret = samba_krb5_kt_remove_entry(state2->context,
						 state2->keytab,
						 &state2->array2[j]);
		if (ret != 0) {
			D_WARNING("Failed to remove keytab entry from %s\n",
				  keytabptr->keytab);
			ret = 0; /* Be fault tolerant */
		}
	}
	/* add new entries with VNO -1, -2, -3, -4 */
	for (i = 0; i < len1; i++) {
		ret = samba_krb5_kt_add_entry(state2->context,
					      state2->keytab,
					      &state2->array1[i]);
		if (ret != 0) {
			return ADS_ERROR_KRB5(ret);
		}
	}
	/* remove entries with VNO -11, -12, -13, -14 */
	for (j = 0; j < len2; j++) {
		krb5_keytab_entry e = state2->array2[j];
		e.vno = state2->array2[j].vno - 10;
		ret = samba_krb5_kt_remove_entry(state2->context,
						 state2->keytab,
						 &e);
		if (ret != 0) {
			D_WARNING("Failed to remove keytab entry from %s\n",
				  keytabptr->keytab);
			ret = 0; /* Be fault tolerant */
		}
	}

	ret = krb5_kt_close(state2->context, state2->keytab);
	return ADS_ERROR_KRB5(ret);

sync_kvno:

	index_array1 = talloc_zero_array(state2, size_t, len1);
	index_array2 = talloc_zero_array(state2, size_t, len2);
	if (index_array1 == NULL || index_array2 == NULL) {
		return ADS_ERROR_KRB5(ENOMEM);
	}
	/*
	 * Mark entries that are present in both arrays.
	 * These will not be added or removed.
	 */
	for (i = 0; i < len1; i++) {
		for (j = 0; j < len2; j++) {
			krb5_keytab_entry e2 = state2->array2[j];
			if (smb_krb5_kt_compare(
				state2->context,
				&state2->array1[i],
				e2.principal,
				e2.vno,
				KRB5_KEY_TYPE(KRB5_KT_KEY(&e2))
			))
			{
				index_array1[i] = 1;
				index_array2[j] = 1;
			}
		}
	}

	/* First add the new entries to the keytab.*/
	for (i = 0; i < len1; i++) {
		if (index_array1[i] == 0) {
			ret = samba_krb5_kt_add_entry(state2->context,
						      state2->keytab,
						      &state2->array1[i]);
			if (ret != 0) {
				return ADS_ERROR_KRB5(ret);
			}
		}
	}

	/* Now, remove the old entries from the keytab. */
	for (j = 0; j < len2; j++) {
		if (index_array2[j] == 0) {
			ret = samba_krb5_kt_remove_entry(state2->context,
							 state2->keytab,
							 &state2->array2[j]);
			if (ret != 0) {
				D_WARNING("Failed to remove keytab entry from "
					  "%s\n",
					  keytabptr->keytab);
				ret = 0; /* Be fault tolerant */
			}
		}
	}

	ret = krb5_kt_close(state2->context, state2->keytab);
	return ADS_ERROR_KRB5(ret);
}

static ADS_STATUS pw2kt_get_dc_info(struct pw2kt_state *state)
{
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	int count;
	bool ok;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	ADS_STRUCT *ads = ads_init(
		tmp_ctx, lp_realm(), lp_workgroup(), NULL, ADS_SASL_SIGN);

	if (ads == NULL) {
		DBG_ERR("ads_init() failed\n");
		TALLOC_FREE(tmp_ctx);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	status = ads_connect_machine(ads);
	if (!ADS_ERR_OK(status)) {
		DBG_ERR("Failed to refresh keytab, ads_connect() returned %s\n",
			ads_errstr(status));
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	status = ads_find_machine_acct(ads, &res, lp_netbios_name());
	if (!ADS_ERR_OK(status)) {
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	count = ads_count_replies(ads, res);
	if (count != 1) {
		status = ADS_ERROR(LDAP_NO_SUCH_OBJECT);
		ads_msgfree(ads, res);
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	if (state->sync_etypes) {
		ok = ads_pull_uint32(ads,
				     res,
				     "msDS-SupportedEncryptionTypes",
				     &state->ad_etypes);
		if (!ok) {
			DBG_WARNING("Failed to determine encryption types.\n");
			ads_msgfree(ads, res);
			TALLOC_FREE(tmp_ctx);
			return ADS_ERROR_NT(NT_STATUS_INTERNAL_ERROR);
		}
	}

	if (state->sync_kvno) {
		uint32_t kvno = -1;
		ok = ads_pull_uint32(ads, res, "msDS-KeyVersionNumber", &kvno);
		if (!ok) {
			DBG_WARNING("Failed to determine the system's kvno.\n");
			ads_msgfree(ads, res);
			TALLOC_FREE(tmp_ctx);
			return ADS_ERROR_NT(NT_STATUS_INTERNAL_ERROR);
		}
		state->ad_kvno = (krb5_kvno) kvno;
	}

	if (state->sync_spns) {
		state->ad_spn_array = ads_pull_strings(ads,
						       state,
						       res,
						       "servicePrincipalName",
						       &state->ad_num_spns);
		if (state->ad_spn_array == NULL) {
			DBG_WARNING("Failed to determine SPNs.\n");
			ads_msgfree(ads, res);
			TALLOC_FREE(tmp_ctx);
			return ADS_ERROR_NT(NT_STATUS_INTERNAL_ERROR);
		}
	}

	ads_msgfree(ads, res);
	TALLOC_FREE(tmp_ctx);
	return status;
}

static bool pw2kt_default_keytab_name(char *name_str, size_t name_size)
{
	char keytab_str[MAX_KEYTAB_NAME_LEN] = {0};
	const char *keytab_name = NULL;
	krb5_context context = 0;
	krb5_error_code ret;

	switch (lp_kerberos_method()) {
	case KERBEROS_VERIFY_SYSTEM_KEYTAB:
	case KERBEROS_VERIFY_SECRETS_AND_KEYTAB:
		ret = smb_krb5_init_context_common(&context);
		if (ret) {
			DBG_ERR("kerberos init context failed (%s)\n",
				error_message(ret));
			return false;
		}
		ret = krb5_kt_default_name(context,
					   keytab_str,
					   sizeof(keytab_str) - 2);
		krb5_free_context(context);
		if (ret != 0) {
			DBG_WARNING("Failed to get default keytab name\n");
			return false;
		}
		if (strncmp(keytab_str, "WRFILE:", 7) == 0) {
			keytab_name = keytab_str + 7;
		} else if (strncmp(keytab_str, "FILE:", 5) == 0) {
			keytab_name = keytab_str + 5;
		} else {
			keytab_name = keytab_str;
		}
		break;

	case KERBEROS_VERIFY_DEDICATED_KEYTAB:
		keytab_name = lp_dedicated_keytab_file();
		break;

	default:
		DBG_NOTICE("'kerberos method' is 'secrets only' but "
			   "'sync machine password to keytab' is not set "
			   "==> no keytab will be generated.\n");
		return false;
	}

	if (keytab_name == NULL || keytab_name[0] == '\0') {
		DBG_ERR("Invalid keytab name\n");
		return false;
	}

	if (strlen(keytab_name) + 1 > name_size) {
		DBG_ERR("Too long keytab name\n");
		return false;
	}

	(void)strncpy(name_str, keytab_name, name_size);

	return true;
}

NTSTATUS sync_pw2keytabs(void)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct pw2kt_state *state = NULL;
	const char **line = NULL;
	const char **lp_ptr = NULL;
	const char *pwsync_script = NULL;
	NTSTATUS status_nt;
	ADS_STATUS status_ads;
	int i;

	DBG_DEBUG("Syncing machine password from secrets to keytabs.\n");

	if (lp_server_role() != ROLE_DOMAIN_MEMBER) {
		TALLOC_FREE(frame);
		return NT_STATUS_OK; /* nothing todo */
	}

	state = talloc_zero(frame, struct pw2kt_state);
	if (state == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	lp_ptr = lp_sync_machine_password_to_keytab();
	if (lp_ptr == NULL) {
		char name[MAX_KEYTAB_NAME_LEN] = {0};
		bool ok = pw2kt_default_keytab_name(name, sizeof(name));

		if (!ok) {
			TALLOC_FREE(frame);
			DBG_WARNING("No default keytab name.\n");
			return NT_STATUS_OK; /* nothing todo */
		}
		status_ads = pw2kt_default_cfg(name, state);
		if (!ADS_ERR_OK(status_ads)) {
			DBG_WARNING("Cannot create default configuration.\n");
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_ERROR;
		}
		goto params_ready;
	}

	if ((*lp_ptr != NULL) && strequal_m(*lp_ptr, "disabled")) {
		DBG_DEBUG("'sync machine password to keytab' is explicitly disabled.\n");
		return NT_STATUS_OK;
	}

	line = lp_ptr;
	while (*line) {
		DBG_DEBUG("Scanning line: %s\n", *line);
		status_ads = pw2kt_scan_line(*line, state);
		if (!ADS_ERR_OK(status_ads)) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_ERROR;
		}
		line++;
	}

params_ready:
	if (state->sync_etypes || state->sync_kvno || state->sync_spns) {
		status_ads = pw2kt_get_dc_info(state);
		if (!ADS_ERR_OK(status_ads)) {
			DBG_WARNING("cannot read from DC\n");
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_ERROR;
		}
	} else {
		DBG_DEBUG("No 'sync_etypes', 'sync_kvno' and 'sync_spns' in "
			  "parameter 'sync machine password to keytab' => "
			  "no need to talk to DC.\n");
	}

	if (!secrets_init()) {
		DBG_WARNING("secrets_init failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	status_nt = secrets_fetch_or_upgrade_domain_info(lp_workgroup(),
							 frame,
							 &state->info);
	if (!NT_STATUS_IS_OK(status_nt)) {
		DBG_WARNING("secrets_fetch_or_upgrade_domain_info(%s) - %s\n",
			    lp_workgroup(),
			    nt_errstr(status_nt));
		TALLOC_FREE(frame);
		return status_nt;
	}

	for (i = 0; i < state->num_keytabs; i++) {
		status_ads = pw2kt_process_keytab(state, &state->keytabs[i]);
		if (!ADS_ERR_OK(status_ads)) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	pwsync_script = lp_sync_machine_password_script(frame, lp_sub);
	if (pwsync_script != NULL && pwsync_script[0] != '\0') {
		int ret;

		DBG_DEBUG("Running script: '%s'\n.", pwsync_script);
		ret = smbrun(pwsync_script, NULL, NULL);
		if (ret != 0) {
			DBG_ERR("Script '%s' failed with: %d.\n",
				pwsync_script,
				ret);
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

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
			DBG_WARNING("Failed to get default keytab name\n");
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

/**********************************************************************
 Flushes all entries from the system keytab.
***********************************************************************/

int ads_keytab_flush(ADS_STRUCT *ads)
{
	krb5_error_code ret = 0;
	krb5_context context = NULL;
	krb5_keytab keytab = NULL;
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

	/* Seek and delete all old keytab entries */
	ret = smb_krb5_kt_seek_and_delete_old_entries(context,
						      keytab,
						      false, /* keep_old_kvno */
						      -1,
						      false, /* enctype_only */
						      ENCTYPE_NULL,
						      NULL,
						      NULL,
						      true); /* flush */
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

	while (samba_krb5_kt_next_entry(context, keytab, &kt_entry, &cursor) ==
	       0)
	{

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
		    (asprintf(&etype_s, "UNKNOWN: %d", enctype) == -1)) {
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
