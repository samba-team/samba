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
	unsigned int *mkvno;
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
	unsigned int _unused18:1;
	unsigned int _unused19:1;
	unsigned int _unused20:1;
	unsigned int _unused21:1;
	unsigned int _unused22:1;
	unsigned int _unused23:1;
	unsigned int _unused24:1;
	unsigned int _unused25:1;
	unsigned int _unused26:1;
	unsigned int _unused27:1;
	unsigned int _unused28:1;
	unsigned int _unused29:1;
	unsigned int _unused30:1;
	unsigned int do_not_store:1;
};

struct sdb_entry {
	krb5_principal principal;
	unsigned int kvno;
	struct sdb_keys keys;
	struct sdb_event created_by;
	struct sdb_event *modified_by;
	time_t *valid_start;
	time_t *valid_end;
	time_t *pw_end;
	unsigned int *max_life;
	unsigned int *max_renew;
	struct SDBFlags flags;
};

struct sdb_entry_ex {
	void *ctx;
	struct sdb_entry entry;
	void (*free_entry)(struct sdb_entry_ex *);
};

#define SDB_ERR_NOENTRY 36150275
#define SDB_ERR_NOT_FOUND_HERE 36150287
#define SDB_ERR_WRONG_REALM 36150289

#define SDB_F_DECRYPT		1	/* decrypt keys */
#define SDB_F_GET_CLIENT	4	/* fetch client */
#define SDB_F_GET_SERVER	8	/* fetch server */
#define SDB_F_GET_KRBTGT	16	/* fetch krbtgt */
#define SDB_F_GET_ANY		28	/* fetch any of client,server,krbtgt */
#define SDB_F_CANON		32	/* want canonicalition */
#define SDB_F_ADMIN_DATA	64	/* want data that kdc don't use  */
#define SDB_F_KVNO_SPECIFIED	128	/* we want a particular KVNO */
#define SDB_F_FOR_AS_REQ	4096	/* fetch is for a AS REQ */
#define SDB_F_FOR_TGS_REQ	8192	/* fetch is for a TGS REQ */

void sdb_free_entry(struct sdb_entry_ex *e);
void free_sdb_entry(struct sdb_entry *s);
struct SDBFlags int2SDBFlags(unsigned n);

#endif /* _KDC_SDB_H_ */
