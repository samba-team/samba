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

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

#ifdef HAVE_KRB5


/*
  Adds a single service principal, i.e. 'host' to the system keytab
*/
int ads_keytab_add_entry(const char *srvPrinc, ADS_STRUCT *ads)
{
	krb5_error_code ret;
	krb5_context context;
	krb5_keytab keytab;
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;
	krb5_principal princ;
	krb5_data password;
	krb5_enctype *enctypes = NULL;
	krb5_kvno kvno;
	krb5_keyblock *key;

	char *principal = NULL;
	char *princ_s = NULL;
	char *password_s = NULL;
	char keytab_name[MAX_KEYTAB_NAME_LEN];          /* This MAX_NAME_LEN is a constant defined in krb5.h */
	fstring myname;
	int i;
	int retval = 0;
	char *ktprinc = NULL;
	struct hostent *hp;

	initialize_krb5_error_table();
	ret = krb5_init_context(&context);
	if (ret) {
		DEBUG(1,("could not krb5_init_context: %s\n",error_message(ret)));
		return -1;
	}
#ifdef HAVE_WRFILE_KEYTAB       /* MIT */
	keytab_name[0] = 'W';
	keytab_name[1] = 'R';
	ret = krb5_kt_default_name(context, (char *) &keytab_name[2], MAX_KEYTAB_NAME_LEN - 4);
#else                           /* Heimdal */
	ret = krb5_kt_default_name(context, (char *) &keytab_name[0], MAX_KEYTAB_NAME_LEN - 2);
#endif
	if (ret) {
		DEBUG(1,("krb5_kt_default_name failed (%s)\n", error_message(ret)));
	}
	DEBUG(1,("Using default system keytab: %s\n", (char *) &keytab_name));
	ret = krb5_kt_resolve(context, (char *) &keytab_name, &keytab);
	if (ret) {
		DEBUG(1,("krb5_kt_resolve failed (%s)\n", error_message(ret)));
		return ret;
	}

	ret = get_kerberos_allowed_etypes(context,&enctypes);
	if (ret) {
		DEBUG(1,("get_kerberos_allowed_etypes failed (%s)\n",error_message(ret)));
		goto out;
	}

	/* retrieve the password */
	if (!secrets_init()) {
		DEBUG(1,("secrets_init failed\n"));
		ret = -1;
		goto out;
	}
	password_s = secrets_fetch_machine_password(lp_workgroup(), NULL, NULL);
	if (!password_s) {
		DEBUG(1,("failed to fetch machine password\n"));
		ret = -1;
		goto out;
	}
	password.data = password_s;
	password.length = strlen(password_s);

	/* Construct our principal */
	fstrcpy(myname, global_myname());
	hp = gethostbyname(myname);
	if ( hp->h_name && strlen(hp->h_name) > 0 ) {
		fstrcpy(myname,hp->h_name);
	}
	strlower_m(myname);
	asprintf(&princ_s, "%s/%s@%s", srvPrinc, myname, lp_realm());

	ret = krb5_parse_name(context, princ_s, &princ);
	if (ret) {
		DEBUG(1,("krb5_parse_name(%s) failed (%s)\n", princ_s, error_message(ret)));
		goto out;
	}

	kvno = (krb5_kvno) ads_get_kvno(ads, global_myname());
	if (kvno == -1) {       /* -1 indicates failure, everything else is OK */
		DEBUG(1,("ads_get_kvno failed to determine the system's kvno.\n"));
		ret = -1;
		goto out;
	}

	/* Seek and delete old keytab entries */
	ret = krb5_kt_start_seq_get(context, keytab, &cursor);
	if (ret != KRB5_KT_END && ret != ENOENT ) {
		DEBUG(1,("Will try to delete old keytab entries\n"));
		while(!krb5_kt_next_entry(context, keytab, &entry, &cursor)) {

			krb5_unparse_name(context, entry.principal, &ktprinc);

			/*---------------------------------------------------------------------------
			 * Save the entries with kvno - 1.   This is what microsoft does
			 * to allow people with existing sessions that have kvno - 1 to still
			 * work.   Otherwise, when the password for the machine changes, all
			 * kerberizied sessions will 'break' until either the client reboots or
			 * the client's session key expires and they get a new session ticket
			 * with the new kvno.
			 */

#ifdef HAVE_KRB5_KT_COMPARE
			if (krb5_kt_compare(context, &entry, princ, 0, 0) == True && entry.vno != kvno - 1) {
#else
			if (strcmp(ktprinc, princ_s) == 0 && entry.vno != kvno - 1) {
#endif
				free(ktprinc);
				DEBUG(1,("Found old entry for principal: %s (kvno %d) - trying to remove it.\n",
					princ_s, entry.vno));
				ret = krb5_kt_end_seq_get(context, keytab, &cursor);
				if (ret) {
					DEBUG(1,("krb5_kt_end_seq_get() failed (%s)\n", error_message(ret)));
					goto out;
				}
				ret = krb5_kt_remove_entry(context, keytab, &entry);
				if (ret) {
					DEBUG(1,("krb5_kt_remove_entry failed (%s)\n", error_message(ret)));
					goto out;
				}
				ret = krb5_kt_start_seq_get(context, keytab, &cursor);
				if (ret) {
					DEBUG(1,("krb5_kt_start_seq failed (%s)\n", error_message(ret)));
					goto out;
				}
				ret = krb5_kt_free_entry(context, &entry);
				if (ret) {
					DEBUG(1,("krb5_kt_remove_entry failed (%s)\n", error_message(ret)));
					goto out;
				}
				continue;
			} else {
				free(ktprinc);
			}

			ret = krb5_kt_free_entry(context, &entry);
			if (ret) {
				DEBUG(1,("krb5_kt_free_entry failed (%s)\n", error_message(ret)));
				goto out;
			}
		}

		ret = krb5_kt_end_seq_get(context, keytab, &cursor);
		if (ret) {
			DEBUG(1,("krb5_kt_end_seq_get failed (%s)\n",error_message(ret)));
			goto out;
		}
	}

	/* Add keytab entries for all encryption types */
	for (i = 0; enctypes[i]; i++) {

		key = (krb5_keyblock *) malloc(sizeof(*key));
		if (!key) {
			DEBUG(1,("Failed to allocate memory to store the keyblock.\n"));
			ret = ENOMEM;
			goto out;
		}

		if (create_kerberos_key_from_string(context, princ, &password, key, enctypes[i])) {
			continue;
		}

		entry.principal = princ;
		entry.vno       = kvno;

#if !defined(HAVE_KRB5_KEYTAB_ENTRY_KEY) && !defined(HAVE_KRB5_KEYTAB_ENTRY_KEYBLOCK)
#error krb5_keytab_entry has no key or keyblock member
#endif
#ifdef HAVE_KRB5_KEYTAB_ENTRY_KEY               /* MIT */
		entry.key = *key;
#endif
#ifdef HAVE_KRB5_KEYTAB_ENTRY_KEYBLOCK          /* Heimdal */
		entry.keyblock = *key;
#endif
		DEBUG(3,("adding keytab entry for (%s) with encryption type (%d) and version (%d)\n",
		princ_s, enctypes[i], entry.vno));
		ret = krb5_kt_add_entry(context, keytab, &entry);
		krb5_free_keyblock(context, key);
		if (ret) {
			DEBUG(1,("adding entry to keytab failed (%s)\n", error_message(ret)));
			krb5_kt_close(context, keytab);
			goto out;
		}
	}

	/* Update the LDAP with the SPN */
	DEBUG(1,("Attempting to add/update '%s'\n", princ_s));
	if (!ADS_ERR_OK(ads_add_spn(ads, global_myname(), srvPrinc))) {
		DEBUG(1,("ads_add_spn failed.\n"));
		goto out;
	}

out:

	krb5_kt_close(context, keytab);
	krb5_free_principal(context, princ);
	if (enctypes) {
		free(enctypes);
	}
	if (principal) {
		free(principal);
	}
	if (password_s) {
		free(password_s);
	}
	if (princ_s) {
		free(princ_s);
	}

	return ret;
}


/*
  Flushes all entries from the system keytab.
*/
int ads_keytab_flush(ADS_STRUCT *ads)
{
	krb5_error_code ret;
	krb5_context context;
	krb5_keytab keytab;
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;
	krb5_kvno kvno;
	char keytab_name[MAX_KEYTAB_NAME_LEN];

	initialize_krb5_error_table();
	ret = krb5_init_context(&context);
	if (ret) {
		DEBUG(1,("could not krb5_init_context: %s\n",error_message(ret)));
		return ret;
	}
#ifdef HAVE_WRFILE_KEYTAB
	keytab_name[0] = 'W';
	keytab_name[1] = 'R';
	ret = krb5_kt_default_name(context, (char *) &keytab_name[2], MAX_KEYTAB_NAME_LEN - 4);
#else
	ret = krb5_kt_default_name(context, (char *) &keytab_name[0], MAX_KEYTAB_NAME_LEN - 2);
#endif
	if (ret) {
		DEBUG(1,("krb5_kt_default failed (%s)\n", error_message(ret)));
		goto out;
	}
	DEBUG(1,("Using default keytab: %s\n", (char *) &keytab_name));
	ret = krb5_kt_resolve(context, (char *) &keytab_name, &keytab);
	if (ret) {
		DEBUG(1,("krb5_kt_default failed (%s)\n", error_message(ret)));
		goto out;
	}
	DEBUG(1,("Using default keytab: %s\n", (char *) &keytab_name));
	ret = krb5_kt_resolve(context, (char *) &keytab_name, &keytab);
	if (ret) {
		DEBUG(1,("krb5_kt_default failed (%s)\n", error_message(ret)));
		goto out;
	}

	kvno = (krb5_kvno) ads_get_kvno(ads, global_myname());
	if (kvno == -1) {       /* -1 indicates a failure */
		DEBUG(1,("Error determining the system's kvno.\n"));
		goto out;
	}

	ret = krb5_kt_start_seq_get(context, keytab, &cursor);
	if (ret != KRB5_KT_END && ret != ENOENT) {
		while (!krb5_kt_next_entry(context, keytab, &entry, &cursor)) {
			ret = krb5_kt_end_seq_get(context, keytab, &cursor);
			if (ret) {
				DEBUG(1,("krb5_kt_end_seq_get() failed (%s)\n",error_message(ret)));
				goto out;
			}
			ret = krb5_kt_remove_entry(context, keytab, &entry);
			if (ret) {
				DEBUG(1,("krb5_kt_remove_entry failed (%s)\n",error_message(ret)));
				goto out;
			}
			ret = krb5_kt_start_seq_get(context, keytab, &cursor);
			if (ret) {
				DEBUG(1,("krb5_kt_start_seq failed (%s)\n",error_message(ret)));
				goto out;
			}
			ret = krb5_kt_free_entry(context, &entry);
			if (ret) {
				DEBUG(1,("krb5_kt_remove_entry failed (%s)\n",error_message(ret)));
				goto out;
			}
		}
	}
	if (!ADS_ERR_OK(ads_clear_spns(ads, global_myname()))) {
		DEBUG(1,("Error while clearing service principal listings in LDAP.\n"));
		goto out;
	}

out:

	krb5_kt_close(context, keytab);
	return ret;
}


int ads_keytab_create_default(ADS_STRUCT *ads)
{
	krb5_error_code ret;
	krb5_context context;
	krb5_keytab keytab;
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;
	krb5_kvno kvno;
	char *ktprinc;
	int i, found = 0;
	char **oldEntries;

	ret = ads_keytab_add_entry("host", ads);
	if (ret) {
		DEBUG(1,("ads_keytab_add_entry failed while adding 'host'.\n"));
		return ret;
	}
	ret = ads_keytab_add_entry("cifs", ads);
	if (ret) {
		DEBUG(1,("ads_keytab_add_entry failed while adding 'cifs'.\n"));
		return ret;
	}

	kvno = (krb5_kvno) ads_get_kvno(ads, global_myname());
	if (kvno == -1) {
		DEBUG(1,("ads_get_kvno failed to determine the system's kvno.\n"));
		return -1;
	}

	DEBUG(1,("Searching for keytab entries to preserve and update.\n"));
	/* Now loop through the keytab and update any other existing entries... */
	initialize_krb5_error_table();
	ret = krb5_init_context(&context);
	if (ret) {
		DEBUG(1,("could not krb5_init_context: %s\n",error_message(ret)));
		return ret;
	}
	ret = krb5_kt_default(context, &keytab);
	if (ret) {
		DEBUG(1,("krb5_kt_default failed (%s)\n",error_message(ret)));
		return ret;
	}

	ret = krb5_kt_start_seq_get(context, keytab, &cursor);
	if (ret != KRB5_KT_END && ret != ENOENT ) {
		while ((ret = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0) {
			found++;
		}
	}

	DEBUG(1, ("Found %d entries in the keytab.\n", found));
	if (!found) {
		goto done;
	}
	oldEntries = (char **) malloc(found * sizeof(char *));
	if (!oldEntries) {
		DEBUG(1,("Failed to allocate space to store the old keytab entries (malloc failed?).\n"));
		return ENOMEM;
	}
	memset(oldEntries, 0, found * sizeof(char *));

	ret = krb5_kt_start_seq_get(context, keytab, &cursor);
	if (ret != KRB5_KT_END && ret != ENOENT ) {
		while ((ret = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0) {
			if (entry.vno != kvno) {
				krb5_unparse_name(context, entry.principal, &ktprinc);
				for (i = 0; *(ktprinc + i); i++) {
					if (*(ktprinc + i) == '/') {
						*(ktprinc + i) = (char) NULL;
						break;
					}
				}
				for (i = 0; i < found; i++) {
					if (!oldEntries[i]) {
						oldEntries[i] = ktprinc;
						break;
					}
					if (!strcmp(oldEntries[i], ktprinc)) {
						break;
					}
				}
			}
		}
		for (i = 0; oldEntries[i]; i++) {
			ret |= ads_keytab_add_entry(oldEntries[i], ads);
			free(oldEntries[i]);
		}
	}
	free(oldEntries);

done:

	krb5_kt_close(context, keytab);
	return ret;
}
#endif /* HAVE_KRB5 */
