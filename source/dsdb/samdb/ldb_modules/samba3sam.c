/* 
   ldb database library - Samba3 SAM compatibility backend

   Copyright (C) Jelmer Vernooij 2005
*/

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/modules/ldb_map.h"
#include "system/passwd.h"

#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/ndr/libndr.h"
#include "libcli/security/security.h"
#include "libcli/security/proto.h"

/* 
 * sambaSID -> member  (dn!)
 * sambaSIDList -> member (dn!) 
 * sambaDomainName -> name 
 * sambaTrustPassword 
 * sambaUnixIdPool 
 * sambaIdmapEntry 
 * sambaAccountPolicy 
 * sambaSidEntry 
 * sambaAcctFlags -> systemFlags ?
 * sambaPasswordHistory  -> ntPwdHistory*/

/* Not necessary:
 * sambaConfig
 * sambaShare
 * sambaConfigOption 
 * sambaNextGroupRid
 * sambaNextUserRid
 * sambaAlgorithmicRidBase
 */

/* Not in Samba4: 
 * sambaKickoffTime
 * sambaPwdCanChange
 * sambaPwdMustChange
 * sambaHomePath
 * sambaHomeDrive
 * sambaLogonScript
 * sambaProfilePath
 * sambaUserWorkstations
 * sambaMungedDial
 * sambaLogonHours */

/* In Samba4 but not in Samba3:
*/

/* From a sambaPrimaryGroupSID, generate a primaryGroupID (integer) attribute */
static struct ldb_message_element *generate_primaryGroupID(struct ldb_module *module, TALLOC_CTX *ctx, const char *local_attr, const struct ldb_message *remote)
{
	struct ldb_message_element *el;
	const char *sid = ldb_msg_find_attr_as_string(remote, "sambaPrimaryGroupSID", NULL);
	const char *p;
	
	if (!sid)
		return NULL;

	p = strrchr(sid, '-');
	if (!p)
		return NULL;

	el = talloc_zero(ctx, struct ldb_message_element);
	el->name = talloc_strdup(ctx, "primaryGroupID");
	el->num_values = 1;
	el->values = talloc_array(ctx, struct ldb_val, 1);
	el->values[0].data = (uint8_t *)talloc_strdup(el->values, p+1);
	el->values[0].length = strlen((char *)el->values[0].data);

	return el;
}

static void generate_sambaPrimaryGroupSID(struct ldb_module *module, const char *local_attr, const struct ldb_message *local, struct ldb_message *remote_mp, struct ldb_message *remote_fb)
{
	const struct ldb_val *sidval;
	char *sidstring;
	struct dom_sid *sid;
	NTSTATUS status;

	/* We need the domain, so we get it from the objectSid that we hope is here... */
	sidval = ldb_msg_find_ldb_val(local, "objectSid");

	if (!sidval) 
		return; /* Sorry, no SID today.. */

	sid = talloc(remote_mp, struct dom_sid);
	if (sid == NULL) {
		return;
	}
	status = ndr_pull_struct_blob(sidval, sid, sid, (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(sid);
		return;
	}

	if (!ldb_msg_find_ldb_val(local, "primaryGroupID"))
		return; /* Sorry, no SID today.. */

	sid->num_auths--;

	sidstring = dom_sid_string(remote_mp, sid);
	talloc_free(sid);
	ldb_msg_add_fmt(remote_mp, "sambaPrimaryGroupSID", "%s-%d", sidstring, ldb_msg_find_attr_as_uint(local, "primaryGroupID", 0));
	talloc_free(sidstring);
}

static struct ldb_val convert_uid_samaccount(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	return ldb_val_dup(ctx, val);
}

static struct ldb_val lookup_homedir(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct passwd *pwd; 
	struct ldb_val retval;
	
	pwd = getpwnam((char *)val->data);

	if (!pwd) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "Unable to lookup '%s' in passwd", (char *)val->data);
		return *talloc_zero(ctx, struct ldb_val);
	}

	retval.data = (uint8_t *)talloc_strdup(ctx, pwd->pw_dir);
	retval.length = strlen((char *)retval.data);

	return retval;
}

static struct ldb_val lookup_gid(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct passwd *pwd; 
	struct ldb_val retval;
	
	pwd = getpwnam((char *)val->data);

	if (!pwd) {
		return *talloc_zero(ctx, struct ldb_val);
	}

	retval.data = (uint8_t *)talloc_asprintf(ctx, "%ld", (unsigned long)pwd->pw_gid);
	retval.length = strlen((char *)retval.data);

	return retval;
}

static struct ldb_val lookup_uid(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct passwd *pwd; 
	struct ldb_val retval;
	
	pwd = getpwnam((char *)val->data);

	if (!pwd) {
		return *talloc_zero(ctx, struct ldb_val);
	}

	retval.data = (uint8_t *)talloc_asprintf(ctx, "%ld", (unsigned long)pwd->pw_uid);
	retval.length = strlen((char *)retval.data);

	return retval;
}

static struct ldb_val encode_sid(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct dom_sid *sid = dom_sid_parse_talloc(ctx, (char *)val->data);
	struct ldb_val *out = talloc_zero(ctx, struct ldb_val);
	NTSTATUS status;

	if (sid == NULL) {
		return *out;
	}
	status = ndr_push_struct_blob(out, ctx, sid, 
				      (ndr_push_flags_fn_t)ndr_push_dom_sid);
	talloc_free(sid);
	if (!NT_STATUS_IS_OK(status)) {
		return *out;
	}

	return *out;
}

static struct ldb_val decode_sid(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct dom_sid *sid;
	NTSTATUS status;
	struct ldb_val *out = talloc_zero(ctx, struct ldb_val);
	
	sid = talloc(ctx, struct dom_sid);
	if (sid == NULL) {
		return *out;
	}
	status = ndr_pull_struct_blob(val, sid, sid, 
				      (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(sid);
		return *out;
	}
	out->data = (uint8_t *)dom_sid_string(ctx, sid);
	talloc_free(sid);
	if (out->data == NULL) {
		return *out;
	}
	out->length = strlen((const char *)out->data);

	return *out;
}

const struct ldb_map_objectclass samba3_objectclasses[] = {
	{
		.local_name = "user",
		.remote_name = "posixAccount",
		.base_classes = { "top", NULL },
		.musts = { "cn", "uid", "uidNumber", "gidNumber", "homeDirectory", NULL },
		.mays = { "userPassword", "loginShell", "gecos", "description", NULL },
	},
	{
		.local_name = "group",
		.remote_name = "posixGroup",
		.base_classes = { "top", NULL },
		.musts = { "cn", "gidNumber", NULL },
		.mays = { "userPassword", "memberUid", "description", NULL },
	},
	{ 
		.local_name = "group", 
		.remote_name = "sambaGroupMapping",
		.base_classes = { "top", "posixGroup", NULL },
		.musts = { "gidNumber", "sambaSID", "sambaGroupType", NULL },
		.mays = { "displayName", "description", "sambaSIDList", NULL },
	},
	{ 
		.local_name = "user", 
		.remote_name = "sambaSAMAccount",
		.base_classes = { "top", "posixAccount", NULL },
		.musts = { "uid", "sambaSID", NULL },
		.mays = { "cn", "sambaLMPassword", "sambaNTPassword",
			"sambaPwdLastSet", "sambaLogonTime", "sambaLogoffTime",
			"sambaKickoffTime", "sambaPwdCanChange", "sambaPwdMustChange",
			"sambaAcctFlags", "displayName", "sambaHomePath", "sambaHomeDrive",
			"sambaLogonScript", "sambaProfilePath", "description", "sambaUserWorkstations",
			"sambaPrimaryGroupSID", "sambaDomainName", "sambaMungedDial",
			"sambaBadPasswordCount", "sambaBadPasswordTime",
	        "sambaPasswordHistory", "sambaLogonHours", NULL }
	
	},
	{ 
		.local_name = "domain", 
		.remote_name = "sambaDomain",
		.base_classes = { "top", NULL },
		.musts = { "sambaDomainName", "sambaSID", NULL },
		.mays = { "sambaNextRid", "sambaNextGroupRid", "sambaNextUserRid", "sambaAlgorithmicRidBase", NULL },
	},
		{ NULL, NULL }
};

const struct ldb_map_attribute samba3_attributes[] = 
{
	/* sambaNextRid -> nextRid */
	{
		.local_name = "nextRid",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				.remote_name = "sambaNextRid",
			},
		},
	},

	/* sambaBadPasswordTime -> badPasswordtime*/
	{
		.local_name = "badPasswordTime",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				.remote_name = "sambaBadPasswordTime",
			},
		},
	},

	/* sambaLMPassword -> lmPwdHash*/
	{
		.local_name = "lmPwdHash",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				.remote_name = "sambaLMPassword",
			},
		},
	},

	/* sambaGroupType -> groupType */
	{
		.local_name = "groupType",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				.remote_name = "sambaGroupType",
			},
		},
	},

	/* sambaNTPassword -> ntPwdHash*/
	{
		.local_name = "ntPwdHash",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				.remote_name = "sambaNTPassword",
			},
		},
	},

	/* sambaPrimaryGroupSID -> primaryGroupID */
	{
		.local_name = "primaryGroupID",
		.type = MAP_GENERATE,
		.u = {
			.generate = {
				.remote_names = { "sambaPrimaryGroupSID", NULL },
				.generate_local = generate_primaryGroupID,
				.generate_remote = generate_sambaPrimaryGroupSID, 
			},
		},
	},

	/* sambaBadPasswordCount -> badPwdCount */
	{
		.local_name = "badPwdCount",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				.remote_name = "sambaBadPasswordCount",
			},
		},
	},

	/* sambaLogonTime -> lastLogon*/
	{
		.local_name = "lastLogon",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				.remote_name = "sambaLogonTime",
			},
		},
	},

	/* sambaLogoffTime -> lastLogoff*/
	{
		.local_name = "lastLogoff",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				.remote_name = "sambaLogoffTime",
			},
		},
	},

	/* uid -> unixName */
	{
		.local_name = "unixName",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				.remote_name = "uid",
			},
		},
	},

	/* displayName -> name */
	{
		.local_name = "name",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				.remote_name = "displayName",
			},
		},
	},

	/* cn */
	{
		.local_name = "cn",
		.type = MAP_KEEP,
	},

	/* sAMAccountName -> cn */
	{
		.local_name = "sAMAccountName",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "uid",
				.convert_remote = convert_uid_samaccount,
			},
		},
	},

	/* objectCategory */
	{
		.local_name = "objectCategory",
		.type = MAP_IGNORE,
	},

	/* objectGUID */
	{
		.local_name = "objectGUID",
		.type = MAP_IGNORE,
	},

	/* objectVersion */
	{
		.local_name = "objectVersion",
		.type = MAP_IGNORE,
	},

	/* codePage */
	{ 
		.local_name = "codePage",
		.type = MAP_IGNORE,
	},

	/* dNSHostName */
	{
		.local_name = "dNSHostName",
		.type = MAP_IGNORE,
	},


	/* dnsDomain */
	{
		.local_name = "dnsDomain",
		.type = MAP_IGNORE,
	},

	/* dnsRoot */
	{
		.local_name = "dnsRoot",
		.type = MAP_IGNORE,
	},

	/* countryCode */
	{
		.local_name = "countryCode",
		.type = MAP_IGNORE,
	},

	/* nTMixedDomain */
	{ 
		.local_name = "nTMixedDomain",
		.type = MAP_IGNORE,
	},

	/* operatingSystem */
	{ 
		.local_name = "operatingSystem",
		.type = MAP_IGNORE,
	},

	/* operatingSystemVersion */
	{
		.local_name = "operatingSystemVersion",
		.type = MAP_IGNORE,
	},


	/* servicePrincipalName */
	{
		.local_name = "servicePrincipalName",
		.type = MAP_IGNORE,
	},

	/* msDS-Behavior-Version */
	{
		.local_name = "msDS-Behavior-Version",
		.type = MAP_IGNORE,
	},

	/* msDS-KeyVersionNumber */
	{
		.local_name = "msDS-KeyVersionNumber",
		.type = MAP_IGNORE,
	},

	/* msDs-masteredBy */
	{
		.local_name = "msDs-masteredBy",
		.type = MAP_IGNORE,
	},

	/* ou */
	{
		.local_name = "ou",
		.type = MAP_KEEP,
	},

	/* dc */
	{
		.local_name = "dc",
		.type = MAP_KEEP,
	},

	/* description */
	{
		.local_name = "description",
		.type = MAP_KEEP,
	},

	/* sambaSID -> objectSid*/
	{
		.local_name = "objectSid",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "sambaSID", 
				.convert_local = decode_sid,
				.convert_remote = encode_sid,
			},
		},
	},

	/* sambaPwdLastSet -> pwdLastSet */
	{
		.local_name = "pwdLastSet",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				.remote_name = "sambaPwdLastSet",
			},
		},
	},	

	/* accountExpires */
	{
		.local_name = "accountExpires", 
		.type = MAP_IGNORE,
	},

	/* adminCount */
	{
		.local_name = "adminCount",
		.type = MAP_IGNORE,
	},

	/* canonicalName */
	{
		.local_name = "canonicalName",
		.type = MAP_IGNORE,
	},

	/* createTimestamp */
	{
		.local_name = "createTimestamp",
		.type = MAP_IGNORE,
	},
	
	/* creationTime */
	{
		.local_name = "creationTime",
		.type = MAP_IGNORE,
	},
	
	/* dMDLocation */
	{
		.local_name = "dMDLocation",
		.type = MAP_IGNORE,
	},
	
	/* fSMORoleOwner */
	{
		.local_name = "fSMORoleOwner",
		.type = MAP_IGNORE,
	},
	
	/* forceLogoff */
	{
		.local_name = "forceLogoff",
		.type = MAP_IGNORE,
	},
	
	/* instanceType */
	{
		.local_name = "instanceType",
		.type = MAP_IGNORE,
	},
	
	/* invocationId */
	{
		.local_name = "invocationId",
		.type = MAP_IGNORE,
	},
	
	/* isCriticalSystemObject */
	{
		.local_name = "isCriticalSystemObject",
		.type = MAP_IGNORE,
	},
	
	/* localPolicyFlags */
	{
		.local_name = "localPolicyFlags",
		.type = MAP_IGNORE,
	},
	
	/* lockOutObservationWindow */
	{
		.local_name = "lockOutObservationWindow",
		.type = MAP_IGNORE,
	},

	/* lockoutDuration */
	{
		.local_name = "lockoutDuration",
		.type = MAP_IGNORE,
	},

	/* lockoutThreshold */
	{
		.local_name = "lockoutThreshold",
		.type = MAP_IGNORE,
	},

	/* logonCount */
	{
		.local_name = "logonCount",
		.type = MAP_IGNORE,
	},

	/* masteredBy */
	{
		.local_name = "masteredBy",
		.type = MAP_IGNORE,
	},

	/* maxPwdAge */
	{
		.local_name = "maxPwdAge",
		.type = MAP_IGNORE,
	},

	/* member */
	{
		.local_name = "member",
		.type = MAP_IGNORE,
	},

	/* memberOf */
	{
		.local_name = "memberOf",
		.type = MAP_IGNORE,
	},

	/* minPwdAge */
	{
		.local_name = "minPwdAge",
		.type = MAP_IGNORE,
	},

	/* minPwdLength */
	{
		.local_name = "minPwdLength",
		.type = MAP_IGNORE,
	},

	/* modifiedCount */
	{
		.local_name = "modifiedCount",
		.type = MAP_IGNORE,
	},

	/* modifiedCountAtLastProm */
	{
		.local_name = "modifiedCountAtLastProm",
		.type = MAP_IGNORE,
	},

	/* modifyTimestamp */
	{
		.local_name = "modifyTimestamp",
		.type = MAP_IGNORE,
	},

	/* nCName */
	{
		.local_name = "nCName",
		.type = MAP_IGNORE,
	},

	/* nETBIOSName */
	{
		.local_name = "nETBIOSName",
		.type = MAP_IGNORE,
	},

	/* oEMInformation */
	{
		.local_name = "oEMInformation",
		.type = MAP_IGNORE,
	},

	/* privilege */
	{
		.local_name = "privilege",
		.type = MAP_IGNORE,
	},

	/* pwdHistoryLength */
	{
		.local_name = "pwdHistoryLength",
		.type = MAP_IGNORE,
	},

	/* pwdProperties */
	{
		.local_name = "pwdProperties",
		.type = MAP_IGNORE,
	},

	/* rIDAvailablePool */
	{
		.local_name = "rIDAvailablePool",
		.type = MAP_IGNORE,
	},

	/* revision */
	{
		.local_name = "revision",
		.type = MAP_IGNORE,
	},

	/* ridManagerReference */
	{
		.local_name = "ridManagerReference",
		.type = MAP_IGNORE,
	},

	/* sAMAccountType */
	{
		.local_name = "sAMAccountType",
		.type = MAP_IGNORE,
	},

	/* sPNMappings */
	{
		.local_name = "sPNMappings",
		.type = MAP_IGNORE,
	},

	/* serverReference */
	{
		.local_name = "serverReference",
		.type = MAP_IGNORE,
	},

	/* serverState */
	{
		.local_name = "serverState",
		.type = MAP_IGNORE,
	},

	/* showInAdvancedViewOnly */
	{
		.local_name = "showInAdvancedViewOnly",
		.type = MAP_IGNORE,
	},

	/* subRefs */
	{
		.local_name = "subRefs",
		.type = MAP_IGNORE,
	},

	/* systemFlags */
	{
		.local_name = "systemFlags",
		.type = MAP_IGNORE,
	},

	/* uASCompat */
	{
		.local_name = "uASCompat",
		.type = MAP_IGNORE,
	},

	/* uSNChanged */
	{
		.local_name = "uSNChanged",
		.type = MAP_IGNORE,
	},

	/* uSNCreated */
	{
		.local_name = "uSNCreated",
		.type = MAP_IGNORE,
	},

	/* sambaPassword */
	{
		.local_name = "sambaPassword",
		.type = MAP_IGNORE,
	},

	/* userAccountControl */
	{
		.local_name = "userAccountControl",
		.type = MAP_IGNORE,
	},

	/* whenChanged */
	{
		.local_name = "whenChanged",
		.type = MAP_IGNORE,
	},

	/* whenCreated */
	{
		.local_name = "whenCreated",
		.type = MAP_IGNORE,
	},

	/* uidNumber */
	{
		.local_name = "unixName",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "uidNumber",
				.convert_local = lookup_uid,
			},
		},
	},

	/* gidNumber. Perhaps make into generate so we can distinguish between 
	 * groups and accounts? */
	{
		.local_name = "unixName",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "gidNumber",
				.convert_local = lookup_gid,
			},
		},
	},

	/* homeDirectory */
	{
		.local_name = "unixName",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "homeDirectory",
				.convert_local = lookup_homedir,
			},
		},
	},
	{
		.local_name = NULL,
	}
};

/* the context init function */
static int samba3sam_init(struct ldb_module *module)
{
        int ret;

	ret = ldb_map_init(module, samba3_attributes, samba3_objectclasses, NULL, "samba3sam");
        if (ret != LDB_SUCCESS)
                return ret;

        return ldb_next_init(module);
}

static struct ldb_module_ops samba3sam_ops = {
	.name		   = "samba3sam",
	.init_context	   = samba3sam_init,
};

/* the init function */
int ldb_samba3sam_module_init(void)
{
	struct ldb_module_ops ops = ldb_map_get_ops();
	samba3sam_ops.add	= ops.add;
	samba3sam_ops.modify	= ops.modify;
	samba3sam_ops.del	= ops.del;
	samba3sam_ops.rename	= ops.rename;
	samba3sam_ops.search	= ops.search;
	samba3sam_ops.wait	= ops.wait;

	return ldb_register_module(&samba3sam_ops);
}
