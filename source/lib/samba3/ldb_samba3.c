/* 
   ldb database library - Samba3 compatibility backend

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
 * sambaSID -> member 
 * sambaSIDList -> member (special!) 
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

/* sambaNextRid -> nextRid */
const struct ldb_map_attribute attr_nextRid = {
	.local_name = "nextRid",
	.type = MAP_RENAME,
	.u.rename.remote_name = "sambaNextRid",
};

/* sambaBadPasswordTime -> badPasswordtime*/
const struct ldb_map_attribute attr_badPasswordTime = {
	.local_name = "badPasswordTime",
	.type = MAP_RENAME,
	.u.rename.remote_name = "sambaBadPasswordTime",
};

/* sambaLMPassword -> lmPwdHash*/
const struct ldb_map_attribute attr_lmPwdHash = {
	.local_name = "lmPwdHash",
	.type = MAP_RENAME,
	.u.rename.remote_name = "sambaLMPassword",
};

/* sambaGroupType -> groupType */
const struct ldb_map_attribute attr_groupType = {
	.local_name = "groupType",
	.type = MAP_RENAME,
	.u.rename.remote_name = "sambaGroupType",
};

/* sambaNTPassword -> ntPwdHash*/
const struct ldb_map_attribute attr_ntPwdHash = {
	.local_name = "badPwdCount",
	.type = MAP_RENAME,
	.u.rename.remote_name = "sambaNTPassword",
};

/* sambaPrimaryGroupSID -> primaryGroupID */
const struct ldb_map_attribute attr_primaryGroupID = {
	.local_name = "primaryGroupID",
	.type = MAP_CONVERT,
	.u.convert.remote_name = "sambaPrimaryGroupSID",
	.u.convert.convert_local = NULL, /* FIXME: Add domain SID */
	.u.convert.convert_remote = NULL, /* FIXME: Extract RID */
};

/* sambaBadPasswordCount -> badPwdCount */
const struct ldb_map_attribute attr_badPwdCount = {
	.local_name = "badPwdCount",
	.type = MAP_RENAME,
	.u.rename.remote_name = "sambaBadPasswordCount",
};

/* sambaLogonTime -> lastLogon*/
const struct ldb_map_attribute attr_lastLogon = {
	.local_name = "lastLogon",
	.type = MAP_RENAME,
	.u.rename.remote_name = "sambaLogonTime",
};

/* sambaLogoffTime -> lastLogoff*/
const struct ldb_map_attribute attr_lastLogoff = {
	.local_name = "lastLogoff",
	.type = MAP_RENAME,
	.u.rename.remote_name = "sambaLogoffTime",
};

/* gidNumber -> unixName */
const struct ldb_map_attribute attr_unixName_gid = {
	.local_name = "unixName",
	.type = MAP_CONVERT,
	.u.convert.remote_name = "gidNumber",
	.u.convert.convert_local = NULL, /* FIXME: Lookup gid */
	.u.convert.convert_remote = NULL, /* FIXME: Lookup groupname */
};

/* uid -> unixName */
const struct ldb_map_attribute attr_unixName_uid = {
	.local_name = "unixName",
	.type = MAP_CONVERT,
	.u.convert.remote_name = "uid",
	.u.convert.convert_local = NULL, /* FIXME: Lookup uid */
	.u.convert.convert_remote = NULL, /* FIXME: Lookup username */
};

/* displayName -> name */
const struct ldb_map_attribute attr_name = {
	.local_name = "name",
	.type = MAP_RENAME,
	.u.rename.remote_name = "displayName",
};

/* cn */
const struct ldb_map_attribute attr_cn = {
	.local_name = "cn",
	.type = MAP_KEEP,
};

/* description */
const struct ldb_map_attribute attr_description = {
	.local_name = "description",
	.type = MAP_KEEP,
};

/* sambaSID -> objectSid*/
const struct ldb_map_attribute attr_objectSid = {
	.local_name = "objectSid",
	.type = MAP_RENAME,
	.u.rename.remote_name = "sambaSID", 
};

/* sambaPwdLastSet -> pwdLastSet*/
const struct ldb_map_attribute attr_pwdLastSet = {
	.local_name = "pwdLastSet",
	.type = MAP_RENAME,
	.u.rename.remote_name = "sambaPwdLastSet",
};

const struct ldb_map_objectclass samba3_objectclasses[] = {
	{ "group", "sambaGroupMapping" },
	{ "user", "sambaSAMAccount" },
	{ "domain", "sambaDomain" },
};

const struct ldb_map_mappings samba3_mappings = 
{
	.name = "samba3",
	{
		&attr_objectSid,
		&attr_pwdLastSet,
		&attr_description,
		&attr_cn,
		&attr_unixName_uid,
		&attr_unixName_gid,
		&attr_name,
		&attr_lastLogoff,
		&attr_lastLogon,
		&attr_primaryGroupID,
		&attr_badPwdCount,
		&attr_ntPwdHash,
		&attr_lmPwdHash,
		&attr_groupType,
		&attr_badPasswordTime,
		&attr_nextRid,
	}
};	

/* the init function */
#ifdef HAVE_DLOPEN_DISABLED
 struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *ldb_samba3_module_init(struct ldb_context *ldb, const char *options[])
#endif
{
	return ldb_map_init(ldb, &samba3_mappings, options);
}
