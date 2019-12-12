/* 
   Unix SMB/CIFS implementation.

   interface functions for the sam database

   Copyright (C) Andrew Tridgell 2004
   
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

#ifndef __SAMDB_H__
#define __SAMDB_H__

struct auth_session_info;
struct dsdb_control_current_partition;
struct dsdb_extended_replicated_object;
struct dsdb_extended_replicated_objects;
struct loadparm_context;
struct tevent_context;
struct tsocket_address;
struct dsdb_trust_routing_table;

#include "librpc/gen_ndr/security.h"
#include <ldb.h>
#include "lib/ldb-samba/ldif_handlers.h"
#include "librpc/gen_ndr/samr.h"
#include "librpc/gen_ndr/drsuapi.h"
#include "librpc/gen_ndr/drsblobs.h"
#include "dsdb/schema/schema.h"
#include "dsdb/samdb/samdb_proto.h"
#include "dsdb/common/dsdb_dn.h"
#include "dsdb/common/util_links.h"
#include "dsdb/common/proto.h"
#include "../libds/common/flags.h"

#define DSDB_CONTROL_CURRENT_PARTITION_OID "1.3.6.1.4.1.7165.4.3.2"
struct dsdb_control_current_partition {
	/* 
	 * this is the version of the dsdb_control_current_partition
	 * version 0: initial implementation
	 * version 1: got rid of backend and module fields
	 */
#define DSDB_CONTROL_CURRENT_PARTITION_VERSION 1
	uint32_t version;
	struct ldb_dn *dn;
};


/*
  flags in dsdb_repl_flags to control replication logic
 */
#define DSDB_REPL_FLAG_PRIORITISE_INCOMING 1
#define DSDB_REPL_FLAG_PARTIAL_REPLICA     2
#define DSDB_REPL_FLAG_ADD_NCNAME	   4
#define DSDB_REPL_FLAG_EXPECT_NO_SECRETS   8
#define DSDB_REPL_FLAG_OBJECT_SUBSET       16
#define DSDB_REPL_FLAG_TARGETS_UPTODATE    32

#define DSDB_CONTROL_REPLICATED_UPDATE_OID "1.3.6.1.4.1.7165.4.3.3"

#define DSDB_CONTROL_DN_STORAGE_FORMAT_OID "1.3.6.1.4.1.7165.4.3.4"
/* DSDB_CONTROL_DN_STORAGE_FORMAT_OID has NULL data and behaves very
 * much like LDB_CONTROL_EXTENDED_DN_OID when the DB stores an
 * extended DN, and otherwise returns normal DNs */

#define DSDB_CONTROL_PASSWORD_CHANGE_STATUS_OID "1.3.6.1.4.1.7165.4.3.8"

struct dsdb_user_pwd_settings {
	uint32_t pwdProperties;
	uint32_t pwdHistoryLength;
	int64_t maxPwdAge;
	int64_t minPwdAge;
	uint32_t minPwdLength;
	bool store_cleartext;
	const char *netbios_domain;
	const char *dns_domain;
	const char *realm;
};

struct dsdb_control_password_change_status {
	struct dsdb_user_pwd_settings domain_data;
	enum samPwdChangeReason reject_reason;
};

#define DSDB_CONTROL_PASSWORD_HASH_VALUES_OID "1.3.6.1.4.1.7165.4.3.9"

#define DSDB_CONTROL_PASSWORD_CHANGE_OID "1.3.6.1.4.1.7165.4.3.10"
struct dsdb_control_password_change {
	const struct samr_Password *old_nt_pwd_hash;
	const struct samr_Password *old_lm_pwd_hash;
};

/**
   DSDB_CONTROL_APPLY_LINKS is internal to Samba4 - a token passed between repl_meta_data and linked_attributes modules
*/
#define DSDB_CONTROL_APPLY_LINKS "1.3.6.1.4.1.7165.4.3.11"

/*
 * this should only be used for importing users from Samba3
 */
#define DSDB_CONTROL_BYPASS_PASSWORD_HASH_OID "1.3.6.1.4.1.7165.4.3.12"

/**
  OID used to allow the replacement of replPropertyMetaData.
  It is used when the current replmetadata needs to be edited.
*/
#define DSDB_CONTROL_CHANGEREPLMETADATA_OID "1.3.6.1.4.1.7165.4.3.14"

/* passed when we want to get the behaviour of the non-global catalog port */
#define DSDB_CONTROL_NO_GLOBAL_CATALOG "1.3.6.1.4.1.7165.4.3.17"

/* passed when we want special behaviour for partial replicas */
#define DSDB_CONTROL_PARTIAL_REPLICA "1.3.6.1.4.1.7165.4.3.18"

/* passed when we want special behaviour for dbcheck */
#define DSDB_CONTROL_DBCHECK "1.3.6.1.4.1.7165.4.3.19"

/* passed when dbcheck wants to modify a read only replica (very special case) */
#define DSDB_CONTROL_DBCHECK_MODIFY_RO_REPLICA "1.3.6.1.4.1.7165.4.3.19.1"

/* passed by dbcheck to fix duplicate linked attributes (bug #13095) */
#define DSDB_CONTROL_DBCHECK_FIX_DUPLICATE_LINKS "1.3.6.1.4.1.7165.4.3.19.2"

/* passed by dbcheck to fix the DN string of a one-way-link (bug #13495) */
#define DSDB_CONTROL_DBCHECK_FIX_LINK_DN_NAME "1.3.6.1.4.1.7165.4.3.19.3"

/* passed by dbcheck to fix the DN SID of a one-way-link (bug #13418) */
#define DSDB_CONTROL_DBCHECK_FIX_LINK_DN_SID "1.3.6.1.4.1.7165.4.3.19.4"

/* passed when importing plain text password on upgrades */
#define DSDB_CONTROL_PASSWORD_BYPASS_LAST_SET_OID "1.3.6.1.4.1.7165.4.3.20"

/*
 * passed from the descriptor module in order to
 * store the recalucated nTSecurityDescriptor without
 * modifying the replPropertyMetaData.
 */
#define DSDB_CONTROL_SEC_DESC_PROPAGATION_OID "1.3.6.1.4.1.7165.4.3.21"

/*
 * passed when creating a interdomain trust account through LSA
 * to relax constraints in the samldb ldb module.
 */
#define DSDB_CONTROL_PERMIT_INTERDOMAIN_TRUST_UAC_OID "1.3.6.1.4.1.7165.4.3.23"

/*
 * Internal control to mark requests as being part of Tombstone restoring
 * procedure - it requires slightly special behavior like:
 *  - a bit different security checks
 *  - restoring certain attributes to their default values, etc
 */
#define DSDB_CONTROL_RESTORE_TOMBSTONE_OID "1.3.6.1.4.1.7165.4.3.24"

/**
  OID used to allow the replacement of replPropertyMetaData.
  It is used when the current replmetadata needs only to be re-sorted, but not edited.
*/
#define DSDB_CONTROL_CHANGEREPLMETADATA_RESORT_OID "1.3.6.1.4.1.7165.4.3.25"

/*
 * pass the default state of pwdLastSet between the "samldb" and "password_hash"
 * modules.
 */
#define DSDB_CONTROL_PASSWORD_DEFAULT_LAST_SET_OID "1.3.6.1.4.1.7165.4.3.26"

/*
 * pass the userAccountControl changes between the "samldb" and "password_hash"
 * modules.
 */
#define DSDB_CONTROL_PASSWORD_USER_ACCOUNT_CONTROL_OID "1.3.6.1.4.1.7165.4.3.27"
struct dsdb_control_password_user_account_control {
	uint32_t req_flags; /* the flags given by the client request */
	uint32_t old_flags; /* the old flags stored (0 on add) */
	uint32_t new_flags; /* the new flags stored */
};

/*
 * Ignores strict checking when adding objects to samldb.
 * This is used when provisioning, as checking all objects when added
 * was slow due to an unindexed search.
 */
#define DSDB_CONTROL_SKIP_DUPLICATES_CHECK_OID "1.3.6.1.4.1.7165.4.3.28"

/* passed when we want to thoroughly delete linked attributes */
#define DSDB_CONTROL_REPLMD_VANISH_LINKS "1.3.6.1.4.1.7165.4.3.29"

/*
 * lockoutTime is a replicated attribute, but must be modified before
 * connectivity occurs to allow password lockouts.
 */
#define DSDB_CONTROL_FORCE_RODC_LOCAL_CHANGE "1.3.6.1.4.1.7165.4.3.31"

#define DSDB_CONTROL_INVALID_NOT_IMPLEMENTED "1.3.6.1.4.1.7165.4.3.32"

/*
 * Used to pass "user password change" vs "password reset" from the ACL to the
 * password_hash module, ensuring both modules treat the request identical.
 */
#define DSDB_CONTROL_PASSWORD_ACL_VALIDATION_OID "1.3.6.1.4.1.7165.4.3.33"
struct dsdb_control_password_acl_validation {
	bool pwd_reset;
};

/*
 * Used to pass the current transaction identifier from the audit_log
 * module to group membership auditing module
 */
#define DSDB_CONTROL_TRANSACTION_IDENTIFIER_OID "1.3.6.1.4.1.7165.4.3.34"
struct dsdb_control_transaction_identifier {
	struct GUID transaction_guid;
};

#define DSDB_EXTENDED_REPLICATED_OBJECTS_OID "1.3.6.1.4.1.7165.4.4.1"
struct dsdb_extended_replicated_object {
	struct ldb_message *msg;
	struct GUID object_guid;
	struct GUID *parent_guid;
	const char *when_changed;
	struct replPropertyMetaDataBlob *meta_data;

	/* Only used for internal processing in repl_meta_data */
	struct ldb_dn *last_known_parent;
	struct ldb_dn *local_parent_dn;
};

/*
 * the schema_dn is passed as struct ldb_dn in
 * req->op.extended.data
 */
#define DSDB_EXTENDED_SCHEMA_UPDATE_NOW_OID "1.3.6.1.4.1.7165.4.4.2"

struct dsdb_extended_replicated_objects {
	/* 
	 * this is the version of the dsdb_extended_replicated_objects
	 * version 0: initial implementation
	 */
#define DSDB_EXTENDED_REPLICATED_OBJECTS_VERSION 3
	uint32_t version;

	/* DSDB_REPL_FLAG_* flags */
	uint32_t dsdb_repl_flags;

	struct ldb_dn *partition_dn;

	const struct repsFromTo1 *source_dsa;
	const struct drsuapi_DsReplicaCursor2CtrEx *uptodateness_vector;

	uint32_t num_objects;
	struct dsdb_extended_replicated_object *objects;

	uint32_t linked_attributes_count;
	struct drsuapi_DsReplicaLinkedAttribute *linked_attributes;

	WERROR error;

	bool originating_updates;
};

/* In ldb.h: LDB_EXTENDED_SEQUENCE_NUMBER 1.3.6.1.4.1.7165.4.4.3 */

#define DSDB_EXTENDED_CREATE_PARTITION_OID "1.3.6.1.4.1.7165.4.4.4"
struct dsdb_create_partition_exop {
	struct ldb_dn *new_dn;
};

/* this takes a struct dsdb_fsmo_extended_op */
#define DSDB_EXTENDED_ALLOCATE_RID_POOL "1.3.6.1.4.1.7165.4.4.5"

struct dsdb_fsmo_extended_op {
	uint64_t fsmo_info;
	struct GUID destination_dsa_guid;
};

#define DSDB_EXTENDED_SCHEMA_UPGRADE_IN_PROGRESS_OID "1.3.6.1.4.1.7165.4.4.6"

/*
 * passed from the descriptor module in order to
 * store the recalucated nTSecurityDescriptor without
 * modifying the replPropertyMetaData.
 */
#define DSDB_EXTENDED_SEC_DESC_PROPAGATION_OID "1.3.6.1.4.1.7165.4.4.7"
struct dsdb_extended_sec_desc_propagation_op {
	struct ldb_dn *nc_root;
	struct GUID guid;
	bool include_self;
};

/* this takes no data */
#define DSDB_EXTENDED_CREATE_OWN_RID_SET "1.3.6.1.4.1.7165.4.4.8"

/* this takes a struct dsdb_extended_allocate_rid */
#define DSDB_EXTENDED_ALLOCATE_RID "1.3.6.1.4.1.7165.4.4.9"

struct dsdb_extended_allocate_rid {
	uint32_t rid;
};

#define DSDB_EXTENDED_SCHEMA_LOAD "1.3.6.1.4.1.7165.4.4.10"

#define DSDB_OPENLDAP_DEREFERENCE_CONTROL "1.3.6.1.4.1.4203.666.5.16"

struct dsdb_openldap_dereference {
	const char *source_attribute;
	const char **dereference_attribute;
};

struct dsdb_openldap_dereference_control {
	struct dsdb_openldap_dereference **dereference;
};

struct dsdb_openldap_dereference_result {
	const char *source_attribute;
	const char *dereferenced_dn;
	int num_attributes;
	struct ldb_message_element *attributes;
};

struct dsdb_openldap_dereference_result_control {
	struct dsdb_openldap_dereference_result **attributes;
};

struct samldb_msds_intid_persistant {
	uint32_t msds_intid;
};

#define SAMLDB_MSDS_INTID_OPAQUE "SAMLDB_MSDS_INTID_OPAQUE"

#define DSDB_PARTITION_DN "@PARTITION"
#define DSDB_PARTITION_ATTR "partition"

#define DSDB_EXTENDED_DN_STORE_FORMAT_OPAQUE_NAME "dsdb_extended_dn_store_format"
struct dsdb_extended_dn_store_format {
	bool store_extended_dn_in_ldb;
};

#define DSDB_OPAQUE_PARTITION_MODULE_MSG_OPAQUE_NAME "DSDB_OPAQUE_PARTITION_MODULE_MSG"

#define DSDB_ACL_CHECKS_DIRSYNC_FLAG 0x1
#define DSDB_SAMDB_MINIMUM_ALLOWED_RID   1000

#define DSDB_METADATA_SCHEMA_SEQ_NUM	"SCHEMA_SEQ_NUM"

/*
 * must be in LDB_FLAG_INTERNAL_MASK
 * see also the values in lib/ldb/include/ldb_module.h
 */
#define DSDB_FLAG_INTERNAL_FORCE_META_DATA 0x10000

#define SAMBA_COMPATIBLE_FEATURES_ATTR "compatibleFeatures"
#define SAMBA_REQUIRED_FEATURES_ATTR "requiredFeatures"
#define SAMBA_FEATURES_SUPPORTED_FLAG "@SAMBA_FEATURES_SUPPORTED"

#define SAMBA_SORTED_LINKS_FEATURE "sortedLinks"
#define SAMBA_ENCRYPTED_SECRETS_FEATURE "encryptedSecrets"
/*
 * lmdb level one feature is an experimental release with basic support
 * for lmdb database files, instead of tdb.
 * - Keys are limited to 511 bytes long so GUID indexes are required
 * - Currently only the:
 *     partition data files
 *   are in lmdb format.
 */
#define SAMBA_LMDB_LEVEL_ONE_FEATURE "lmdbLevelOne"

#endif /* __SAMDB_H__ */
