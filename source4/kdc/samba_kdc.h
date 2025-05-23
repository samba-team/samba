/*
   Unix SMB/CIFS implementation.

   KDC structures

   Copyright (C) Andrew Tridgell	2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Simo Sorce <idra@samba.org> 2010

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

#ifndef _SAMBA_KDC_H_
#define _SAMBA_KDC_H_

#include "lib/replace/replace.h"
#include "system/time.h"
#include "libcli/util/ntstatus.h"

struct samba_kdc_policy {
	time_t svc_tkt_lifetime;
	time_t usr_tkt_lifetime;
	time_t renewal_lifetime;
};

struct samba_kdc_base_context {
	struct tevent_context *ev_ctx;
	struct loadparm_context *lp_ctx;
	struct imessaging_context *msg_ctx;
	struct ldb_context *samdb;

	/*
	 * If we are under Heimdal, this will be updated at each
	 * packet to be the same time as the KDC process uses and will
	 * be set into dsdb_gmsa_set_current_time() (otherwise NULL)
	 */
	unsigned long long *current_nttime_ull;
};

struct samba_kdc_seq;

struct samba_kdc_db_context {
	struct tevent_context *ev_ctx;
	struct loadparm_context *lp_ctx;
	struct imessaging_context *msg_ctx;
	struct ldb_context *samdb;
	struct samba_kdc_seq *seq_ctx;
	bool rodc;
	unsigned int my_krbtgt_number;
	struct ldb_dn *krbtgt_dn;
	struct samba_kdc_policy policy;
	/*
	 * Copied from the base_context when this is created
	 */
	unsigned long long *current_nttime_ull;
};

struct samba_kdc_entry {
	struct samba_kdc_db_context *kdc_db_ctx;
	const struct sdb_entry *db_entry; /* this is only temporarily valid */
	const void *kdc_entry; /* this is a reference to hdb_entry/krb5_db_entry */
	struct ldb_message *msg;
	struct ldb_dn *realm_dn;
	struct claims_data *claims_from_pac;
	struct claims_data *claims_from_db;
	const struct auth_user_info_dc *info_from_pac;
	const struct PAC_DOMAIN_GROUP_MEMBERSHIP *resource_groups_from_pac;
	const struct auth_user_info_dc *info_from_db;
	const struct authn_kerberos_client_policy *client_policy;
	const struct authn_server_policy *server_policy;
	uint32_t supported_enctypes;
	NTSTATUS reject_status;
	bool is_krbtgt : 1;
	bool is_rodc : 1;
	bool is_trust : 1;
	bool claims_from_pac_are_initialized : 1;
	bool claims_from_db_are_initialized : 1;
	bool group_managed_service_account : 1;
	NTTIME current_nttime;
	int64_t enforced_tgt_lifetime_nt_ticks;
};

extern struct hdb_method hdb_samba4_interface;

#define CHANGEPW_LIFETIME (60*2) /* 2 minutes */

#endif /* _SAMBA_KDC_H_ */
