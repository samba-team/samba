/* 
   ldb database library - Samba3 SAM compatibility backend

   Copyright (C) Jelmer Vernooij 2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "ldb/ldb_map/ldb_map.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"

/* FIXME: 
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

static struct ldb_val convert_sid_rid(struct ldb_map_context *map, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	printf("Converting SID TO RID *\n");

	return ldb_val_dup(ctx, val);
}

static struct ldb_val convert_rid_sid(struct ldb_map_context *map, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	printf("Converting RID TO SID *\n");

	return ldb_val_dup(ctx, val);
}

static struct ldb_val convert_unix_id2name(struct ldb_map_context *map, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	printf("Converting UNIX ID to name\n");

	return ldb_val_dup(ctx, val);
}

static struct ldb_val convert_unix_name2id(struct ldb_map_context *map, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	printf("Converting UNIX name to ID\n");

	return ldb_val_dup(ctx, val);
}

const struct ldb_map_objectclass samba3_objectclasses[] = {
	{ "group", "sambaGroupMapping" },
	{ "user", "sambaSAMAccount" },
	{ "domain", "sambaDomain" },
	{ NULL, NULL }
};

const struct ldb_map_attribute samba3_attributes[] = 
{
	/* sambaNextRid -> nextRid */
	{
		.local_name = "nextRid",
		.type = MAP_RENAME,
		.u.rename.remote_name = "sambaNextRid",
	},

	/* sambaBadPasswordTime -> badPasswordtime*/
	{
		.local_name = "badPasswordTime",
		.type = MAP_RENAME,
		.u.rename.remote_name = "sambaBadPasswordTime",
	},

	/* sambaLMPassword -> lmPwdHash*/
	{
		.local_name = "lmPwdHash",
		.type = MAP_RENAME,
		.u.rename.remote_name = "sambaLMPassword",
	},

	/* sambaGroupType -> groupType */
	{
		.local_name = "groupType",
		.type = MAP_RENAME,
		.u.rename.remote_name = "sambaGroupType",
	},

	/* sambaNTPassword -> ntPwdHash*/
	{
		.local_name = "badPwdCount",
		.type = MAP_RENAME,
		.u.rename.remote_name = "sambaNTPassword",
	},

	/* sambaPrimaryGroupSID -> primaryGroupID */
	{
		.local_name = "primaryGroupID",
		.type = MAP_CONVERT,
		.u.convert.remote_name = "sambaPrimaryGroupSID",
		.u.convert.convert_local = convert_rid_sid,
		.u.convert.convert_remote = convert_sid_rid, 
	},

	/* sambaBadPasswordCount -> badPwdCount */
	{
		.local_name = "badPwdCount",
		.type = MAP_RENAME,
		.u.rename.remote_name = "sambaBadPasswordCount",
	},

	/* sambaLogonTime -> lastLogon*/
	{
		.local_name = "lastLogon",
		.type = MAP_RENAME,
		.u.rename.remote_name = "sambaLogonTime",
	},

	/* sambaLogoffTime -> lastLogoff*/
	{
		.local_name = "lastLogoff",
		.type = MAP_RENAME,
		.u.rename.remote_name = "sambaLogoffTime",
	},

	/* gidNumber -> unixName */
	{
		.local_name = "unixName",
		.type = MAP_CONVERT,
		.u.convert.remote_name = "gidNumber",
		.u.convert.convert_local = convert_unix_name2id,
		.u.convert.convert_remote = convert_unix_id2name, 
	},

	/* uid -> unixName */
	{
		.local_name = "unixName",
		.type = MAP_CONVERT,
		.u.convert.remote_name = "uid",
		.u.convert.convert_local = convert_unix_name2id,
		.u.convert.convert_remote = convert_unix_id2name,
	},

	/* displayName -> name */
	{
		.local_name = "name",
		.type = MAP_RENAME,
		.u.rename.remote_name = "displayName",
	},

	/* cn */
	{
		.local_name = "cn",
		.type = MAP_KEEP,
	},

	/* sAMAccountName -> cn */
	{
		.local_name = "sAMAccountName",
		.type = MAP_RENAME,
		.u.rename.remote_name = "uid",
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
		.type = MAP_RENAME,
		.u.rename.remote_name = "sambaSID", 
	},

	/* sambaPwdLastSet -> pwdLastSet */
	{
		.local_name = "pwdLastSet",
		.type = MAP_RENAME,
		.u.rename.remote_name = "sambaPwdLastSet",
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

	/* unicodePwd */
	{
		.local_name = "unicodePwd",
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

	{
		.local_name = NULL,
	}
};

	/* the init function */
#ifdef HAVE_DLOPEN_DISABLED
struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *ldb_samba3sam_module_init(struct ldb_context *ldb, const char *options[])
#endif
{
	return ldb_map_init(ldb, samba3_attributes, samba3_objectclasses, "samba3sam");
}
