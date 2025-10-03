/*
   Unix SMB/CIFS implementation.

   Database Glue between Samba and the KDC

   Copyright (C) Guenther Deschner <gd@samba.org> 2014
   Copyright (C) Andreas Schneider <asn@samba.org> 2014

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

#ifndef _KDC_SDB_H_
#define _KDC_SDB_H_

struct sdb_salt {
	unsigned int type;
	krb5_data salt;
};

struct sdb_key {
	krb5_keyblock key;
	struct sdb_salt *salt;
};

struct sdb_keys {
	unsigned int len;
	struct sdb_key *val;
};

struct sdb_event {
	krb5_principal principal;
	time_t time;
};

struct sdb_etypes {
	unsigned len;
	krb5_enctype *val;
};

struct SDBFlags {
	unsigned int initial:1;
	unsigned int forwardable:1;
	unsigned int proxiable:1;
	unsigned int renewable:1;
	unsigned int postdate:1;
	unsigned int server:1;
	unsigned int client:1;
	unsigned int invalid:1;
	unsigned int require_preauth:1;
	unsigned int change_pw:1;
	unsigned int require_hwauth:1;
	unsigned int ok_as_delegate:1;
	unsigned int user_to_user:1;
	unsigned int immutable:1;
	unsigned int trusted_for_delegation:1;
	unsigned int allow_kerberos4:1;
	unsigned int allow_digest:1;
	unsigned int locked_out:1;
	unsigned int require_pwchange:1;
	unsigned int materialize:1;
	unsigned int virtual_keys:1;
	unsigned int virtual:1;
	unsigned int synthetic:1;
	unsigned int no_auth_data_reqd:1;
	unsigned int auth_data_reqd:1;
	unsigned int _unused25:1;
	unsigned int _unused26:1;
	unsigned int _unused27:1;
	unsigned int _unused28:1;
	unsigned int _unused29:1;
	unsigned int force_canonicalize:1;
	unsigned int do_not_store:1;
};

struct sdb_pub_key {
	unsigned int bit_size;
	krb5_data modulus;
	krb5_data exponent;
};

struct sdb_pub_keys {
	unsigned int len;
	struct sdb_pub_key *keys;
};

struct sdb_certificate_mappings {
	int enforcement_mode;
	time_t valid_certificate_start;
	unsigned int len;
	struct sdb_certificate_mapping *mappings;
};


struct sdb_certificate_mapping {
	krb5_boolean strong_mapping;
	krb5_data issuer_name;
	krb5_data subject_name;
	krb5_data serial_number;
	krb5_data ski;
	krb5_data public_key;
	krb5_data rfc822;
};


struct sdb_entry {
	struct samba_kdc_entry *skdc_entry;
	krb5_principal principal;
	unsigned int kvno;
	struct sdb_keys keys;
	struct sdb_etypes *etypes;
	struct sdb_keys old_keys;
	struct sdb_keys older_keys;
	struct sdb_etypes *session_etypes;
	struct sdb_event created_by;
	struct sdb_event *modified_by;
	time_t *valid_start;
	time_t *valid_end;
	time_t *pw_end;
	int *max_life;
	int *max_renew;
	struct SDBFlags flags;
	struct sdb_pub_keys pub_keys;
	struct sdb_certificate_mappings mappings;
};

#define SDB_ERR_NOENTRY 36150275
#define SDB_ERR_NOT_FOUND_HERE 36150287
#define SDB_ERR_WRONG_REALM 36150289

/* These must match the values in hdb.h */

#define SDB_F_DECRYPT			0x00001	/* decrypt keys */
#define SDB_F_REPLACE			0x00002	/* replace entry */
#define SDB_F_GET_CLIENT		0x00004	/* fetch client */
#define SDB_F_GET_SERVER		0x00008	/* fetch server */
#define SDB_F_GET_KRBTGT		0x00010	/* fetch krbtgt */
#define SDB_F_GET_ANY			( SDB_F_GET_CLIENT | \
					  SDB_F_GET_SERVER | \
					  SDB_F_GET_KRBTGT ) /* fetch any of client,server,krbtgt */
#define SDB_F_CANON			0x00020	/* want canonicalization */
#define SDB_F_ADMIN_DATA		0x00040	/* want data that kdc don't use  */
#define SDB_F_KVNO_SPECIFIED		0x00080	/* we want a particular KVNO */
#define SDB_F_FOR_AS_REQ		0x01000	/* fetch is for a AS REQ */
#define SDB_F_FOR_TGS_REQ		0x02000	/* fetch is for a TGS REQ */
#define SDB_F_ARMOR_PRINCIPAL		0x40000	/* fetch is for the client of an armor ticket */
#define SDB_F_USER2USER_PRINCIPAL	0x80000	/* fetch is for the server of a user2user tgs-req */
#define SDB_F_CROSS_REALM_PRINCIPAL	0x100000 /* fetch is cross-realm ticket */
#define SDB_F_S4U2SELF_PRINCIPAL	0x200000 /* fetch is for S4U2Self */
#define SDB_F_S4U2PROXY_PRINCIPAL	0x400000 /* fetch is for S4U2Proxy */

#define SDB_F_HDB_MASK		(SDB_F_DECRYPT | \
				 SDB_F_GET_CLIENT| \
				 SDB_F_GET_SERVER | \
				 SDB_F_GET_KRBTGT | \
				 SDB_F_CANON | \
				 SDB_F_ADMIN_DATA | \
				 SDB_F_KVNO_SPECIFIED | \
				 SDB_F_FOR_AS_REQ | \
				 SDB_F_FOR_TGS_REQ | \
				 SDB_F_ARMOR_PRINCIPAL| \
				 SDB_F_USER2USER_PRINCIPAL| \
				 SDB_F_CROSS_REALM_PRINCIPAL| \
				 SDB_F_S4U2SELF_PRINCIPAL| \
				 SDB_F_S4U2PROXY_PRINCIPAL)

/* These are not supported by HDB */
#define SDB_F_FORCE_CANON		0x4000	/* force canonicalization */
#define SDB_F_RODC_NUMBER_SPECIFIED	0x8000	/* we want a particular RODC number */

void sdb_certificate_mapping_free(struct sdb_certificate_mapping *m);
void sdb_certificate_mappings_free(struct sdb_certificate_mappings *m);
void sdb_pub_key_free(struct sdb_pub_key *key);
void sdb_pub_keys_free(struct sdb_pub_keys *keys);
void sdb_key_free(struct sdb_key *key);
void sdb_keys_free(struct sdb_keys *keys);
void sdb_entry_free(struct sdb_entry *e);
krb5_error_code sdb_entry_set_etypes(struct sdb_entry *s);
krb5_error_code sdb_entry_set_session_etypes(struct sdb_entry *s,
					     bool add_aes256,
					     bool add_aes128,
					     bool add_rc4);

#endif /* _KDC_SDB_H_ */
